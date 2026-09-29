package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

// sim runs many simulated enforcement points in one process. Each has its own
// TLS connection, as separate processes would.
type sim struct {
	jitter bool
	policy string // "classic" or "lease", see run
	base   time.Duration
	cap    time.Duration
	eps    []*ep

	dialMu sync.Mutex
	dials  []time.Time

	receiptMu sync.Mutex
	receipts  map[string][]time.Duration // halt ID → time from issue to receipt
	errors    map[string]int             // why sessions ended, by message

	leaseExpiries atomic.Int64
}

// ep is one simulated enforcement point, embedded in one agent.
type ep struct {
	s          *sim
	instanceID string
	agentID    string
	client     modulev1alpha1connect.GovernanceServiceClient

	partitioned atomic.Bool
	debug       bool // log every session end

	mu            sync.Mutex
	cancel        context.CancelFunc
	connected     bool
	stateReceived bool
	version       uint64
	agent         *pb.AgentState
	fleet         *pb.FleetState
	seen          map[string]bool
	leaseDeadline time.Time
	lastRenewal   time.Time
	leaseExpired  bool
	sessions      int
	renewed       bool // the current session received a lease renewal

	partition partitionRecord
}

// partitionRecord is what happened to one enforcement point during a
// simulated partition.
type partitionRecord struct {
	Start          time.Time `json:"start"`
	LastRenewal    time.Time `json:"last_renewal"`
	FailedClosedAt time.Time `json:"failed_closed_at"`
	HealedAt       time.Time `json:"healed_at"`
	RecoveredAt    time.Time `json:"recovered_at"`
}

var errPartitioned = errors.New("simulated partition: the core is unreachable")

func runEPs(args []string) error {
	fs := flag.NewFlagSet("eps", flag.ExitOnError)
	instancesFile := fs.String("instances", "instances.json", "instances to simulate")
	target := fs.String("target", "127.0.0.1:9700", "load balancer address")
	caFile := fs.String("ca", "ca.pem", "CA certificate")
	admin := fs.String("admin", "127.0.0.1:9720", "spike admin address (HTTP)")
	jitter := fs.Bool("jitter", true, "randomize reconnection backoff (full jitter)")
	base := fs.Duration("backoff-base", 500*time.Millisecond, "first reconnection backoff")
	backoffCap := fs.Duration("backoff-cap", 30*time.Second, "largest reconnection backoff")
	policy := fs.String("policy", "lease", "backoff policy: classic or lease")
	_ = fs.Parse(args)

	data, err := os.ReadFile(*instancesFile)
	if err != nil {
		return err
	}
	var instances []instance
	if err := json.Unmarshal(data, &instances); err != nil {
		return err
	}
	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	s := &sim{jitter: *jitter, policy: *policy, base: *base, cap: *backoffCap, receipts: map[string][]time.Duration{}, errors: map[string]int{}}
	ctx := context.Background()
	for _, in := range instances {
		e := &ep{s: s, instanceID: in.InstanceID, agentID: in.AgentID, seen: map[string]bool{}, debug: len(s.eps) < 3}
		transport := &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			DialContext:         e.dial,
			TLSHandshakeTimeout: 5 * time.Second,
			// Detect a dead connection: a PING after 5 s without frames, closed
			// after 3 s without an answer.
			HTTP2: &http.HTTP2Config{SendPingTimeout: 5 * time.Second, PingTimeout: 3 * time.Second},
		}
		e.client = modulev1alpha1connect.NewGovernanceServiceClient(&http.Client{Transport: transport}, "https://"+*target)
		s.eps = append(s.eps, e)
	}
	for _, e := range s.eps {
		go func() {
			// Enforcement points do not all start in the same millisecond.
			_ = sleepCtx(ctx, time.Duration(rand.Int64N(int64(2*time.Second)))) //nolint:gosec // G404: a start delay needs no cryptographic randomness
			e.run(ctx)
		}()
	}
	go s.checkLeases(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /spike/stats", s.handleStats)
	mux.HandleFunc("POST /spike/partition", s.handlePartition)
	mux.HandleFunc("POST /spike/heal", s.handleHeal)
	mux.HandleFunc("GET /spike/partition-report", s.handlePartitionReport)
	mux.HandleFunc("GET /spike/dials", s.handleDials)
	mux.HandleFunc("POST /spike/reset", s.handleReset)
	log.Printf("eps: %d enforcement points -> %s (jitter %v)", len(s.eps), *target, *jitter)
	srv := &http.Server{Addr: *admin, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

func (e *ep) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	e.s.dialMu.Lock()
	e.s.dials = append(e.s.dials, time.Now())
	e.s.dialMu.Unlock()
	if e.partitioned.Load() {
		// Like an unanswered connection attempt.
		_ = sleepCtx(ctx, time.Second)
		return nil, errPartitioned
	}
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &partitionConn{Conn: c, ep: e}, nil
}

// partitionConn simulates a network partition on one connection: while it
// lasts, what arrives is lost and what is sent never leaves.
type partitionConn struct {
	net.Conn
	ep *ep
}

func (c *partitionConn) Read(b []byte) (int, error) {
	for {
		n, err := c.Conn.Read(b)
		if err != nil || !c.ep.partitioned.Load() {
			return n, err
		}
	}
}

func (c *partitionConn) Write(b []byte) (int, error) {
	if c.ep.partitioned.Load() {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

// run watches until ctx ends, reconnecting with exponential backoff, with or
// without jitter (obligation I-4).
func (e *ep) run(ctx context.Context) {
	backoff := e.s.base
	for ctx.Err() == nil {
		started := time.Now()
		err := e.watch(ctx)
		if err != nil {
			e.s.countError(err)
		}
		e.mu.Lock()
		e.connected = false
		e.sessions++
		renewed := e.renewed
		e.renewed = false
		ttl := e.agent.GetLeaseTtl().AsDuration()
		e.mu.Unlock()
		// classic: back to the first backoff after 30 s of healthy session;
		// the cap is the configured one.
		// lease: back to the first backoff once a session received a renewal,
		// and never wait more than a third of the lease TTL, so everyone is
		// back within one renewal interval after the core returns.
		limit := e.s.cap
		switch {
		case e.s.policy == "lease":
			if renewed {
				backoff = e.s.base
			}
			if ttl > 0 {
				limit = min(limit, ttl/3)
			}
		case time.Since(started) > 30*time.Second:
			backoff = e.s.base
		}
		backoff = min(backoff, limit)
		wait := backoff
		if e.s.jitter {
			wait = time.Duration(rand.Int64N(int64(backoff))) + time.Millisecond //nolint:gosec // G404: jitter needs no cryptographic randomness
		}
		if e.debug {
			log.Printf("ep %s: session of %v ended: %v; next attempt in %v", e.instanceID[:8], time.Since(started).Round(time.Millisecond), err, wait.Round(time.Millisecond))
		}
		_ = sleepCtx(ctx, wait)
		backoff = min(backoff*2, limit)
	}
}

func (e *ep) watch(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.mu.Lock()
	e.cancel = cancel
	since := e.version
	e.mu.Unlock()
	stream, err := e.client.Watch(sctx, connect.NewRequest(&pb.WatchRequest{InstanceId: e.instanceID, SinceVersion: since}))
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	for stream.Receive() {
		e.apply(ctx, stream.Msg())
	}
	return stream.Err()
}

func (e *ep) apply(ctx context.Context, msg *pb.WatchResponse) {
	now := time.Now()
	e.mu.Lock()
	switch m := msg.GetMessage().(type) {
	case *pb.WatchResponse_SnapshotPart:
		part := m.SnapshotPart
		if part.GetFirst() {
			e.fleet = part.GetFleet()
		}
		for _, a := range part.GetAgents() {
			if a.GetAgentId() == e.agentID {
				e.agent = a
			}
		}
		if part.GetLast() {
			e.stateReceived, e.connected, e.version = true, true, msg.GetVersion()
		}
	case *pb.WatchResponse_Change:
		if msg.GetVersion() > e.version {
			if f := m.Change.GetFleet(); f != nil {
				e.fleet = f
			}
			for _, a := range m.Change.GetAgents() {
				if a.GetAgentId() == e.agentID {
					e.agent = a
				}
			}
			e.version = msg.GetVersion()
		}
	case *pb.WatchResponse_LeaseRenewal:
		if e.stateReceived && e.agent != nil {
			e.leaseDeadline = now.Add(e.agent.GetLeaseTtl().AsDuration())
			e.lastRenewal = now
			e.renewed = true
			if e.leaseExpired {
				e.leaseExpired = false
				if !e.partition.HealedAt.IsZero() && e.partition.RecoveredAt.IsZero() {
					e.partition.RecoveredAt = now
				}
			}
		}
	}
	var fresh []*pb.Halt
	for _, h := range slices.Concat(e.agent.GetHalts(), e.fleet.GetHalts()) {
		if !e.seen[h.GetHaltId()] {
			e.seen[h.GetHaltId()] = true
			fresh = append(fresh, h)
		}
	}
	e.mu.Unlock()
	for _, h := range fresh {
		e.s.receiptMu.Lock()
		e.s.receipts[h.GetHaltId()] = append(e.s.receipts[h.GetHaltId()], now.Sub(h.GetIssuedAt().AsTime()))
		e.s.receiptMu.Unlock()
		go e.ack(ctx, h.GetHaltId(), now)
	}
}

// ack acknowledges the gate layer: closed at once (obligation EP-4).
func (e *ep) ack(ctx context.Context, haltID string, at time.Time) {
	req := &pb.AcknowledgeRequest{InstanceId: e.instanceID, Acknowledgements: []*pb.Acknowledgement{{
		AcknowledgementId: newUUID(),
		AgentId:           e.agentID,
		Kind: &pb.Acknowledgement_Halt{Halt: &pb.HaltAcknowledgement{HaltId: haltID, Layers: []*pb.HaltLayerReport{{
			Layer: pb.HaltLayer_HALT_LAYER_GATE_CLOSED, Outcome: pb.LayerOutcome_LAYER_OUTCOME_DONE,
			AfterReceipt: durationpb.New(time.Since(at)), ObservedAt: timestamppb.New(at),
		}}}},
	}}}
	for attempt := range 10 {
		actx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := e.client.Acknowledge(actx, connect.NewRequest(req))
		cancel()
		if err == nil {
			return
		}
		_ = sleepCtx(ctx, time.Duration(attempt+1)*200*time.Millisecond)
	}
}

// countError records why a session ended, without the parts that vary.
func (s *sim) countError(err error) {
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120]
	}
	s.receiptMu.Lock()
	s.errors[msg]++
	s.receiptMu.Unlock()
}

// checkLeases fails an enforcement point closed when its lease expires, and
// makes it reconnect (obligation EP-3).
func (s *sim) checkLeases(ctx context.Context) {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, e := range s.eps {
				e.mu.Lock()
				if e.stateReceived && !e.leaseExpired && !e.leaseDeadline.IsZero() && now.After(e.leaseDeadline) {
					e.leaseExpired = true
					s.leaseExpiries.Add(1)
					if !e.partition.Start.IsZero() && e.partition.FailedClosedAt.IsZero() {
						e.partition.FailedClosedAt = now
					}
					if e.cancel != nil {
						e.cancel()
					}
				}
				e.mu.Unlock()
			}
		}
	}
}

// simStats is the simulator's view of its enforcement points.
type simStats struct {
	EPs           int                `json:"eps"`
	Connected     int                `json:"connected"`
	StateReceived int                `json:"state_received"`
	Halted        int                `json:"halted"`
	LeaseExpired  int                `json:"lease_expired_now"`
	LeaseExpiries int64              `json:"lease_expiries"`
	Errors        map[string]int     `json:"errors"`
	Sessions      int                `json:"sessions_ended"`
	Receipts      map[string]summary `json:"receipts"`
	Proc          procStats          `json:"proc"`
}

func (s *sim) handleStats(w http.ResponseWriter, _ *http.Request) {
	st := simStats{EPs: len(s.eps), Receipts: map[string]summary{}, Errors: map[string]int{}, LeaseExpiries: s.leaseExpiries.Load(), Proc: readProcStats()}
	for _, e := range s.eps {
		e.mu.Lock()
		if e.connected {
			st.Connected++
		}
		if e.stateReceived {
			st.StateReceived++
		}
		if len(e.agent.GetHalts()) > 0 || len(e.fleet.GetHalts()) > 0 {
			st.Halted++
		}
		if e.leaseExpired {
			st.LeaseExpired++
		}
		st.Sessions += e.sessions
		e.mu.Unlock()
	}
	s.receiptMu.Lock()
	for id, ds := range s.receipts {
		st.Receipts[id] = summarize(ds)
	}
	for msg, n := range s.errors {
		st.Errors[msg] = n
	}
	s.receiptMu.Unlock()
	writeJSON(w, st)
}

func (s *sim) handlePartition(w http.ResponseWriter, r *http.Request) {
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count <= 0 || count > len(s.eps) {
		http.Error(w, "bad count", http.StatusBadRequest)
		return
	}
	now := time.Now()
	step := len(s.eps) / count
	for i := range count {
		e := s.eps[i*step]
		e.mu.Lock()
		e.partition = partitionRecord{Start: now, LastRenewal: e.lastRenewal}
		e.mu.Unlock()
		e.partitioned.Store(true)
	}
	writeJSON(w, map[string]int{"partitioned": count})
}

func (s *sim) handleHeal(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	healed := 0
	for _, e := range s.eps {
		if e.partitioned.Swap(false) {
			e.mu.Lock()
			e.partition.HealedAt = now
			e.mu.Unlock()
			healed++
		}
	}
	writeJSON(w, map[string]int{"healed": healed})
}

func (s *sim) handlePartitionReport(w http.ResponseWriter, _ *http.Request) {
	var out []partitionRecord
	for _, e := range s.eps {
		e.mu.Lock()
		if !e.partition.Start.IsZero() {
			out = append(out, e.partition)
		}
		e.mu.Unlock()
	}
	writeJSON(w, out)
}

// handleDials reports connection attempts since a time, and the busiest
// 100-millisecond window.
func (s *sim) handleDials(w http.ResponseWriter, r *http.Request) {
	ms, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	since := time.UnixMilli(ms)
	s.dialMu.Lock()
	buckets := map[int64]int{}
	total := 0
	for _, t := range s.dials {
		if t.After(since) {
			total++
			buckets[t.UnixMilli()/100]++
		}
	}
	s.dialMu.Unlock()
	peak := 0
	for _, n := range buckets {
		peak = max(peak, n)
	}
	writeJSON(w, map[string]int{"total": total, "peak_per_100ms": peak})
}

func (s *sim) handleReset(w http.ResponseWriter, _ *http.Request) {
	s.receiptMu.Lock()
	s.receipts = map[string][]time.Duration{}
	s.errors = map[string]int{}
	s.receiptMu.Unlock()
	s.leaseExpiries.Store(0)
	for _, e := range s.eps {
		e.mu.Lock()
		e.partition = partitionRecord{}
		e.sessions = 0
		e.mu.Unlock()
	}
	writeJSON(w, map[string]bool{"reset": true})
}
