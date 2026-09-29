package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

// replica is one core replica: it serves Watch and Acknowledge, and follows
// governance changes through LISTEN/NOTIFY. Every replica is identical and
// keeps no state of its own beyond the streams it serves.
type replica struct {
	name string
	pool *pgxpool.Pool

	catchUpMu sync.Mutex // one catch-up at a time

	mu       sync.Mutex
	version  uint64
	fleet    *pb.FleetState
	watchers map[string]map[*watcher]struct{} // by agent ID

	streams   atomic.Int64
	instances sync.Map // instance ID → agent ID
}

// watcher is one open Watch stream.
type watcher struct {
	ch chan *pb.WatchResponse
}

var errTooSlow = errors.New("the client did not keep up with the stream")

func runCore(args []string) error {
	fs := flag.NewFlagSet("core", flag.ExitOnError)
	name := fs.String("name", "replica", "replica name")
	addr := fs.String("addr", "127.0.0.1:9701", "module API address (TLS)")
	admin := fs.String("admin", "127.0.0.1:9711", "spike admin address (HTTP)")
	db := fs.String("db", "", "database URL of the runtime role")
	cert := fs.String("cert", "", "TLS certificate file")
	key := fs.String("key", "", "TLS key file")
	_ = fs.Parse(args)

	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(*db)
	if err != nil {
		return err
	}
	cfg.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	r := &replica{name: *name, pool: pool, watchers: map[string]map[*watcher]struct{}{}}
	version, halts, err := loadFleet(ctx, pool)
	if err != nil {
		return err
	}
	r.fleet = fleetState(version, halts)
	if err := pool.QueryRow(ctx, `SELECT greatest(max(state_version), $1) FROM whitetower.governance_state`, version).Scan(&r.version); err != nil {
		return err
	}
	go r.listen(ctx, *db)

	mux := http.NewServeMux()
	mux.Handle(modulev1alpha1connect.NewGovernanceServiceHandler(r))
	api := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { log.Fatal(api.ListenAndServeTLS(*cert, *key)) }()

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("POST /spike/halt", r.handleHalt)
	adminMux.HandleFunc("POST /spike/release", r.handleRelease)
	adminMux.HandleFunc("GET /spike/stats", func(w http.ResponseWriter, _ *http.Request) {
		s := readProcStats()
		s.Streams = r.streams.Load()
		writeJSON(w, s)
	})
	adminSrv := &http.Server{Addr: *admin, Handler: adminMux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("%s: module API on %s, admin on %s", r.name, *addr, *admin)
	return adminSrv.ListenAndServe()
}

// listen follows the governance channel with a dedicated connection. It also
// catches up every five seconds, so a lost notification delays a change but
// never loses it.
func (r *replica) listen(ctx context.Context, db string) {
	for {
		conn, err := pgx.Connect(ctx, db)
		if err == nil {
			_, err = conn.Exec(ctx, "LISTEN "+notifyChannel)
		}
		if err != nil {
			log.Printf("%s: listen: %v", r.name, err)
			_ = sleepCtx(ctx, time.Second)
			continue
		}
		r.catchUp(ctx)
		for {
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := conn.WaitForNotification(wctx)
			cancel()
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				log.Printf("%s: notification: %v", r.name, err)
				break
			}
			r.catchUp(ctx)
		}
		_ = conn.Close(ctx)
	}
}

// catchUp reads every change after the replica's version and sends it, in
// version order, to the streams it concerns.
func (r *replica) catchUp(ctx context.Context) {
	r.catchUpMu.Lock()
	defer r.catchUpMu.Unlock()
	r.mu.Lock()
	since, fleetVersion := r.version, r.fleet.GetVersion()
	r.mu.Unlock()

	agents, err := changedAgents(ctx, r.pool, since)
	if err != nil {
		log.Printf("%s: changes: %v", r.name, err)
		return
	}
	version, halts, err := loadFleet(ctx, r.pool)
	if err != nil {
		log.Printf("%s: fleet: %v", r.name, err)
		return
	}
	type change struct {
		version uint64
		msg     *pb.WatchResponse
		agentID string // empty for the fleet
		fleet   *pb.FleetState
	}
	var changes []change
	for _, a := range agents {
		state := agentState(a)
		changes = append(changes, change{version: a.Version, agentID: a.AgentID, msg: &pb.WatchResponse{
			Version: a.Version,
			Message: &pb.WatchResponse_Change{Change: &pb.StateChange{Agents: []*pb.AgentState{state}}},
		}})
	}
	if version > fleetVersion {
		fleet := fleetState(version, halts)
		changes = append(changes, change{version: version, fleet: fleet, msg: &pb.WatchResponse{
			Version: version,
			Message: &pb.WatchResponse_Change{Change: &pb.StateChange{Fleet: fleet}},
		}})
	}
	slices.SortFunc(changes, func(a, b change) int { return cmp.Compare(a.version, b.version) })

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range changes {
		if c.fleet != nil {
			r.fleet = c.fleet
			for _, ws := range r.watchers {
				for w := range ws {
					r.sendLocked(w, ws, c.msg)
				}
			}
		} else if ws, ok := r.watchers[c.agentID]; ok {
			for w := range ws {
				r.sendLocked(w, ws, c.msg)
			}
		}
		r.version = max(r.version, c.version)
	}
}

// sendLocked queues a message without blocking; a watcher that cannot keep up
// is dropped (CORE-7). Callers hold r.mu.
func (r *replica) sendLocked(w *watcher, set map[*watcher]struct{}, msg *pb.WatchResponse) {
	select {
	case w.ch <- msg:
	default:
		delete(set, w)
		close(w.ch)
	}
}

func agentState(a agentRow) *pb.AgentState {
	state := &pb.AgentState{
		AgentId:        a.AgentID,
		Version:        a.Version,
		LifecycleState: lifecycle(a.LifecycleState),
		LeaseTtl:       durationpb.New(time.Duration(a.LeaseTTL) * time.Second),
		HaltMode:       pb.HaltMode_HALT_MODE_INTERRUPT,
	}
	for _, h := range a.Halts {
		state.Halts = append(state.Halts, halt(h))
	}
	return state
}

func fleetState(version uint64, halts []haltRow) *pb.FleetState {
	f := &pb.FleetState{Version: version}
	for _, h := range halts {
		f.Halts = append(f.Halts, halt(h))
	}
	return f
}

func halt(h haltRow) *pb.Halt {
	scope := map[string]pb.HaltScope{"agent": pb.HaltScope_HALT_SCOPE_AGENT, "selector": pb.HaltScope_HALT_SCOPE_SELECTOR, "fleet": pb.HaltScope_HALT_SCOPE_FLEET}[h.Scope]
	return &pb.Halt{HaltId: h.ID, Scope: scope, IssuedAt: timestamppb.New(h.IssuedAt), Drill: h.Drill}
}

func lifecycle(s string) pb.LifecycleState {
	if v, ok := pb.LifecycleState_value["LIFECYCLE_STATE_"+strings.ToUpper(s)]; ok {
		return pb.LifecycleState(v)
	}
	return pb.LifecycleState_LIFECYCLE_STATE_UNSPECIFIED
}

func (r *replica) agentOf(ctx context.Context, instanceID string) (string, error) {
	if v, ok := r.instances.Load(instanceID); ok {
		return v.(string), nil
	}
	var agentID string
	err := r.pool.QueryRow(ctx, `SELECT identity_agent_id::text FROM whitetower.module_instances WHERE id = $1`, instanceID).Scan(&agentID)
	if err != nil {
		return "", err
	}
	r.instances.Store(instanceID, agentID)
	return agentID, nil
}

// Watch sends a snapshot of the instance's agent and the fleet, a renewal,
// then changes and renewals (contract, section 5.2). The spike skips
// authentication: the instance ID alone gives the scope.
func (r *replica) Watch(ctx context.Context, req *connect.Request[pb.WatchRequest], stream *connect.ServerStream[pb.WatchResponse]) error {
	agentID, err := r.agentOf(ctx, req.Msg.GetInstanceId())
	if err != nil {
		return connect.NewError(connect.CodeNotFound, err)
	}
	w := &watcher{ch: make(chan *pb.WatchResponse, 64)}
	r.mu.Lock()
	if r.watchers[agentID] == nil {
		r.watchers[agentID] = map[*watcher]struct{}{}
	}
	r.watchers[agentID][w] = struct{}{}
	r.mu.Unlock()
	r.streams.Add(1)
	defer func() {
		r.streams.Add(-1)
		r.mu.Lock()
		delete(r.watchers[agentID], w)
		r.mu.Unlock()
	}()

	// Registered before reading the snapshot, so no change can fall between
	// the two; a change the snapshot already holds is skipped below.
	a, err := loadAgent(ctx, r.pool, agentID)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	r.mu.Lock()
	fleet := r.fleet
	sent := max(r.version, a.Version, fleet.GetVersion())
	r.mu.Unlock()
	if err := stream.Send(&pb.WatchResponse{Version: sent, Message: &pb.WatchResponse_SnapshotPart{
		SnapshotPart: &pb.SnapshotPart{First: true, Last: true, Fleet: fleet, Agents: []*pb.AgentState{agentState(a)}},
	}}); err != nil {
		return err
	}
	renewal := func() *pb.WatchResponse {
		return &pb.WatchResponse{Version: sent, Message: &pb.WatchResponse_LeaseRenewal{
			LeaseRenewal: &pb.LeaseRenewal{ServerTime: timestamppb.Now()},
		}}
	}
	if err := stream.Send(renewal()); err != nil {
		return err
	}

	interval := min(time.Duration(a.LeaseTTL)*time.Second/3, 30*time.Second)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-w.ch:
			if !ok {
				return connect.NewError(connect.CodeResourceExhausted, errTooSlow)
			}
			if msg.GetVersion() <= sent {
				continue
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
			sent = msg.GetVersion()
		case <-ticker.C:
			if len(w.ch) > 0 {
				continue // renew only once caught up (CORE-6)
			}
			if err := stream.Send(renewal()); err != nil {
				return err
			}
		}
	}
}

// Acknowledge records the gate layer of halt acknowledgements.
func (r *replica) Acknowledge(ctx context.Context, req *connect.Request[pb.AcknowledgeRequest]) (*connect.Response[pb.AcknowledgeResponse], error) {
	batch := &pgx.Batch{}
	for _, a := range req.Msg.GetAcknowledgements() {
		h := a.GetHalt()
		if h == nil {
			continue
		}
		for _, l := range h.GetLayers() {
			if l.GetLayer() == pb.HaltLayer_HALT_LAYER_GATE_CLOSED {
				batch.Queue(`INSERT INTO whitetower.halt_acks (halt_id, instance_id, agent_id, expected, gate_closed_at, acknowledged_at)
				             VALUES ($1, $2, $3, true, $4, clock_timestamp())
				             ON CONFLICT (halt_id, instance_id, agent_id) DO NOTHING`,
					h.GetHaltId(), req.Msg.GetInstanceId(), a.GetAgentId(), l.GetObservedAt().AsTime())
			}
		}
	}
	if batch.Len() > 0 {
		if err := r.pool.SendBatch(ctx, batch).Close(); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
	}
	return connect.NewResponse(&pb.AcknowledgeResponse{}), nil
}

func (r *replica) handleHalt(w http.ResponseWriter, req *http.Request) {
	scope, agentID := req.URL.Query().Get("scope"), req.URL.Query().Get("agent")
	haltID, issuedAt, err := issueHalt(req.Context(), r.pool, scope, agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"halt_id": haltID, "issued_at": issuedAt, "replica": r.name})
}

func (r *replica) handleRelease(w http.ResponseWriter, req *http.Request) {
	if err := releaseHalt(req.Context(), r.pool, req.URL.Query().Get("halt")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"released": req.URL.Query().Get("halt"), "replica": r.name})
}
