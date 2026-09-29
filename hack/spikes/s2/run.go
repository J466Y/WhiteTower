package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// proc is a child process of the coordinator.
type proc struct {
	name string
	args []string
	dir  string
	cmd  *exec.Cmd
}

func startProc(dir, name string, args ...string) (*proc, error) {
	p := &proc{name: name, args: args, dir: dir}
	return p, p.start()
}

func (p *proc) start() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(p.dir, p.name+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	p.cmd = exec.CommandContext(context.Background(), exe, p.args...) //nolint:gosec // G204: the spike starts itself
	p.cmd.Stdout, p.cmd.Stderr = logFile, logFile
	return p.cmd.Start()
}

// kill ends the process abruptly, like a crash.
func (p *proc) kill() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
}

const (
	replicaA = "http://127.0.0.1:9711"
	replicaB = "http://127.0.0.1:9712"
	lbAdmin  = "http://127.0.0.1:9710"
	epsAdmin = "http://127.0.0.1:9720"
)

// report is everything the run measured.
type report struct {
	EPs             int                  `json:"eps"`
	LeaseTTLSeconds int                  `json:"lease_ttl_seconds"`
	ColdStart       time.Duration        `json:"cold_start_ns"`
	Idle            map[string]procStats `json:"replicas_before_streams"`
	Streams         map[string]procStats `json:"replicas_with_streams"`
	IdleCPUPercent  map[string]float64   `json:"replicas_idle_cpu_percent"`
	AgentHalts      summary              `json:"agent_halts_issue_to_ack"`
	AgentHaltsByA   summary              `json:"agent_halts_issued_on_a"`
	AgentHaltsByB   summary              `json:"agent_halts_issued_on_b"`
	FleetHalts      []summary            `json:"fleet_halts_issue_to_ack"`
	FleetReceipts   []summary            `json:"fleet_halts_issue_to_receipt"`
	FleetAll        summary              `json:"fleet_halts_all_acks"`
	FleetMissing    []int                `json:"fleet_halts_missing_acks"`
	Partitions      []partitionSummary   `json:"partitions"`
	Storms          []stormResult        `json:"storms"`
	Simulator       procStats            `json:"simulator"`
}

type partitionSummary struct {
	Policy           string  `json:"policy"`
	EPs              int     `json:"eps"`
	FailedClosed     int     `json:"failed_closed"`
	FailClosedAfter  summary `json:"partition_to_fail_closed"`
	AfterLastRenewal summary `json:"last_renewal_to_fail_closed"`
	Recovered        int     `json:"recovered"`
	RecoveryAfter    summary `json:"heal_to_recovered"`
}

type stormResult struct {
	Name          string         `json:"name"`
	Policy        string         `json:"policy"`
	Jitter        bool           `json:"jitter"`
	Reconnecting  int            `json:"reconnecting"`
	Recovery      time.Duration  `json:"recovery_ns"`
	Dials         int            `json:"dials"`
	PeakDials     int            `json:"peak_dials_per_100ms"`
	LeaseExpiries int64          `json:"lease_expiries"`
	CPUPercent    float64        `json:"cpu_percent"`
	Errors        map[string]int `json:"errors"`
}

// cluster is the running system under test.
type cluster struct {
	dir, instancesFile, caFile string
	n                          int
	a, b                       *proc
	eps                        *proc
}

func (c *cluster) epsArgs(policy string, jitter bool) []string {
	return []string{"eps", "-instances", c.instancesFile, "-ca", c.caFile, "-policy", policy, "-jitter", strconv.FormatBool(jitter)}
}

// restartEPs restarts the simulator, so every enforcement point starts from
// the first backoff and the streams spread over both replicas again.
func (c *cluster) restartEPs(ctx context.Context, policy string, jitter bool) error {
	if c.eps != nil {
		c.eps.kill()
	}
	var err error
	if c.eps, err = startProc(c.dir, fmt.Sprintf("eps-%s-jitter-%v", policy, jitter), c.epsArgs(policy, jitter)...); err != nil {
		return err
	}
	if err := waitConnected(ctx, c.n, 90*time.Second); err != nil {
		return fmt.Errorf("simulator (%s, jitter %v): %w", policy, jitter, err)
	}
	return sleepCtx(ctx, 5*time.Second)
}

func runCoordinator(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	adminDB := fs.String("db", "", "database URL of a superuser (the schema is recreated)")
	n := fs.Int("n", 1000, "enforcement points")
	ttl := fs.Int("ttl", 15, "lease TTL in seconds (critical risk tier)")
	migration := fs.String("migration", "../../../internal/platform/db/migrations/00001_init.sql", "the core's migration")
	agentHalts := fs.Int("agent-halts", 20, "agent halts to measure")
	fleetHalts := fs.Int("fleet-halts", 5, "fleet halts to measure")
	partition := fs.Int("partition", 50, "enforcement points to partition (0 to skip)")
	policies := fs.String("policies", "lease,classic", "backoff policies to compare")
	storms := fs.Bool("storms", true, "run the reconnection storms")
	outFile := fs.String("out", "results.json", "where to write the raw results")
	_ = fs.Parse(args)
	if *adminDB == "" {
		return errors.New("-db is required")
	}
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "wt-s2-")
	if err != nil {
		return err
	}
	log.Printf("logs in %s", dir)

	instances, runtimeURL, err := setupDB(ctx, *adminDB, *migration, *n, *ttl)
	if err != nil {
		return err
	}
	c := &cluster{dir: dir, n: *n, instancesFile: filepath.Join(dir, "instances.json")}
	data, err := json.Marshal(instances)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.instancesFile, data, 0o600); err != nil {
		return err
	}
	var certFile, keyFile string
	if c.caFile, certFile, keyFile, err = writeCerts(dir); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, *adminDB)
	if err != nil {
		return err
	}
	defer pool.Close()

	coreArgs := func(name, addr, admin string) []string {
		return []string{"core", "-name", name, "-addr", addr, "-admin", admin, "-db", runtimeURL, "-cert", certFile, "-key", keyFile}
	}
	if c.a, err = startProc(dir, "core-a", coreArgs("a", "127.0.0.1:9701", "127.0.0.1:9711")...); err != nil {
		return err
	}
	defer func() { c.a.kill() }()
	if c.b, err = startProc(dir, "core-b", coreArgs("b", "127.0.0.1:9702", "127.0.0.1:9712")...); err != nil {
		return err
	}
	defer func() { c.b.kill() }()
	lb, err := startProc(dir, "lb", "lb")
	if err != nil {
		return err
	}
	defer lb.kill()
	if err := waitReady(ctx, replicaA, replicaB, lbAdmin); err != nil {
		return err
	}
	defer func() {
		if c.eps != nil {
			c.eps.kill()
		}
	}()

	rep := report{EPs: *n, LeaseTTLSeconds: *ttl, Idle: replicaStats(ctx), IdleCPUPercent: map[string]float64{}}
	policyList := strings.Split(*policies, ",")

	// Cold start: every enforcement point starts within two seconds.
	start := time.Now()
	if c.eps, err = startProc(dir, "eps", c.epsArgs(policyList[0], true)...); err != nil {
		return err
	}
	if err := waitConnected(ctx, *n, 90*time.Second); err != nil {
		return fmt.Errorf("cold start: %w", err)
	}
	rep.ColdStart = time.Since(start)
	log.Printf("cold start: %d enforcement points connected in %v", *n, rep.ColdStart.Round(time.Millisecond))

	// Resources with every stream open, and CPU while only renewals flow.
	_ = sleepCtx(ctx, 5*time.Second)
	rep.Streams = replicaStats(ctx)
	before := replicaStats(ctx)
	const idleWindow = 20 * time.Second
	_ = sleepCtx(ctx, idleWindow)
	after := replicaStats(ctx)
	for name := range after {
		rep.IdleCPUPercent[name] = 100 * (after[name].CPUSeconds - before[name].CPUSeconds) / idleWindow.Seconds()
	}

	if err := measureHalts(ctx, pool, instances, *agentHalts, *fleetHalts, &rep); err != nil {
		return err
	}

	for _, policy := range policyList {
		if *partition > 0 {
			if err := c.restartEPs(ctx, policy, true); err != nil {
				return err
			}
			p, err := partitionScenario(ctx, *partition, *n, *ttl)
			if err != nil {
				return err
			}
			p.Policy = policy
			rep.Partitions = append(rep.Partitions, p)
			log.Printf("partition (%s): %+v", policy, p)
		}
		if !*storms {
			continue
		}
		for _, jitter := range []bool{true, false} {
			if err := c.restartEPs(ctx, policy, jitter); err != nil {
				return err
			}
			crash, err := storm(ctx, "replica A crashes", policy, jitter, *n, []*proc{c.a}, 0, replicaB)
			if err != nil {
				return err
			}
			rep.Storms = append(rep.Storms, crash)
			if err := c.a.start(); err != nil {
				return err
			}
			if err := waitReady(ctx, replicaA); err != nil {
				return err
			}
			if err := c.restartEPs(ctx, policy, jitter); err != nil {
				return err
			}
			outage, err := storm(ctx, "whole core down for 5 s", policy, jitter, *n, []*proc{c.a, c.b}, 5*time.Second, "")
			if err != nil {
				return err
			}
			rep.Storms = append(rep.Storms, outage)
		}
	}
	var st simStats
	if err := call(ctx, http.MethodGet, epsAdmin+"/spike/stats", &st); err == nil {
		rep.Simulator = st.Proc
	}

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outFile, out, 0o600); err != nil {
		return err
	}
	printReport(rep)
	return nil
}

func waitReady(ctx context.Context, urls ...string) error {
	for _, url := range urls {
		if err := waitUntil(ctx, 20*time.Second, func() bool { return call(ctx, http.MethodGet, url+"/spike/stats", nil) == nil }); err != nil {
			return fmt.Errorf("%s not ready: %w", url, err)
		}
	}
	return nil
}

// measureHalts issues agent halts and fleet halts alternately on each replica
// and records the time from issue to each acknowledgement.
func measureHalts(ctx context.Context, pool *pgxpool.Pool, instances []instance, agentHalts, fleetHalts int, rep *report) error {
	var all, onA, onB []time.Duration
	for i := range agentHalts {
		in := instances[rand.IntN(len(instances))] //nolint:gosec // G404: choosing an agent needs no cryptographic randomness
		issuer, releaser := replicaA, replicaB
		if i%2 == 1 {
			issuer, releaser = replicaB, replicaA
		}
		_, lat, err := haltAndWait(ctx, pool, issuer, releaser, "agent", in.AgentID, 1)
		if err != nil {
			return fmt.Errorf("agent halt %d: %w", i, err)
		}
		all = append(all, lat...)
		if i%2 == 0 {
			onA = append(onA, lat...)
		} else {
			onB = append(onB, lat...)
		}
	}
	rep.AgentHalts, rep.AgentHaltsByA, rep.AgentHaltsByB = summarize(all), summarize(onA), summarize(onB)
	log.Printf("agent halts: %s", rep.AgentHalts)

	var fleetAll []time.Duration
	for i := range fleetHalts {
		issuer, releaser := replicaA, replicaB
		if i%2 == 1 {
			issuer, releaser = replicaB, replicaA
		}
		haltID, lat, err := haltAndWait(ctx, pool, issuer, releaser, "fleet", "", rep.EPs)
		if err != nil {
			return fmt.Errorf("fleet halt %d: %w", i, err)
		}
		rep.FleetHalts = append(rep.FleetHalts, summarize(lat))
		rep.FleetMissing = append(rep.FleetMissing, rep.EPs-len(lat))
		fleetAll = append(fleetAll, lat...)
		var st simStats
		if err := call(ctx, http.MethodGet, epsAdmin+"/spike/stats", &st); err == nil {
			rep.FleetReceipts = append(rep.FleetReceipts, st.Receipts[haltID])
		}
		log.Printf("fleet halt %d: %s", i, summarize(lat))
	}
	rep.FleetAll = summarize(fleetAll)
	return nil
}

func waitUntil(ctx context.Context, timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		if err := sleepCtx(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

func waitConnected(ctx context.Context, n int, timeout time.Duration) error {
	var st simStats
	err := waitUntil(ctx, timeout, func() bool {
		return call(ctx, http.MethodGet, epsAdmin+"/spike/stats", &st) == nil && st.Connected == n && st.StateReceived == n
	})
	if err != nil {
		return fmt.Errorf("%d of %d connected: %w", st.Connected, n, err)
	}
	return nil
}

func replicaStats(ctx context.Context) map[string]procStats {
	out := map[string]procStats{}
	for name, url := range map[string]string{"a": replicaA, "b": replicaB} {
		var s procStats
		if err := call(ctx, http.MethodGet, url+"/spike/stats", &s); err == nil {
			out[name] = s
		}
	}
	return out
}

// haltAndWait issues a halt on one replica, waits for the acknowledgements
// (up to 30 s), releases it through the other replica, and waits until no
// enforcement point is halted.
func haltAndWait(ctx context.Context, pool *pgxpool.Pool, issuer, releaser, scope, agentID string, want int) (string, []time.Duration, error) {
	var h struct {
		HaltID string `json:"halt_id"`
	}
	if err := call(ctx, http.MethodPost, issuer+"/spike/halt?scope="+scope+"&agent="+agentID, &h); err != nil {
		return "", nil, err
	}
	var lat []time.Duration
	_ = waitUntil(ctx, 30*time.Second, func() bool {
		var err error
		lat, err = ackLatencies(ctx, pool, h.HaltID)
		return err == nil && len(lat) >= want
	})
	if err := call(ctx, http.MethodPost, releaser+"/spike/release?halt="+h.HaltID, nil); err != nil {
		return h.HaltID, lat, err
	}
	var st simStats
	err := waitUntil(ctx, 30*time.Second, func() bool {
		return call(ctx, http.MethodGet, epsAdmin+"/spike/stats", &st) == nil && st.Halted == 0
	})
	return h.HaltID, lat, err
}

// partitionScenario cuts some enforcement points off the core for longer
// than their lease, heals the partition, and reports when they failed closed
// and when they recovered.
func partitionScenario(ctx context.Context, count, n, ttl int) (partitionSummary, error) {
	if err := call(ctx, http.MethodPost, epsAdmin+"/spike/reset", nil); err != nil {
		return partitionSummary{}, err
	}
	if err := call(ctx, http.MethodPost, epsAdmin+"/spike/partition?count="+strconv.Itoa(count), nil); err != nil {
		return partitionSummary{}, err
	}
	_ = sleepCtx(ctx, time.Duration(ttl+5)*time.Second)
	if err := call(ctx, http.MethodPost, epsAdmin+"/spike/heal", nil); err != nil {
		return partitionSummary{}, err
	}
	if err := waitConnected(ctx, n, 60*time.Second); err != nil {
		log.Printf("after the partition: %v", err)
	}
	_ = sleepCtx(ctx, time.Duration(ttl/3+1)*time.Second) // one renewal for everyone
	var recs []partitionRecord
	if err := call(ctx, http.MethodGet, epsAdmin+"/spike/partition-report", &recs); err != nil {
		return partitionSummary{}, err
	}
	var failClosed, afterRenewal, recovery []time.Duration
	for _, r := range recs {
		if !r.FailedClosedAt.IsZero() {
			failClosed = append(failClosed, r.FailedClosedAt.Sub(r.Start))
			afterRenewal = append(afterRenewal, r.FailedClosedAt.Sub(r.LastRenewal))
		}
		if !r.RecoveredAt.IsZero() {
			recovery = append(recovery, r.RecoveredAt.Sub(r.HealedAt))
		}
	}
	return partitionSummary{
		EPs: len(recs), FailedClosed: len(failClosed), FailClosedAfter: summarize(failClosed),
		AfterLastRenewal: summarize(afterRenewal), Recovered: len(recovery), RecoveryAfter: summarize(recovery),
	}, nil
}

// storm kills processes, restarts them after a pause (or leaves them down
// when pause is 0), and measures how the enforcement points reconnect.
func storm(ctx context.Context, name, policy string, jitter bool, n int, victims []*proc, pause time.Duration, survivor string) (stormResult, error) {
	res := stormResult{Name: name, Policy: policy, Jitter: jitter}
	if err := call(ctx, http.MethodPost, epsAdmin+"/spike/reset", nil); err != nil {
		return res, err
	}
	var survivorBefore procStats
	if survivor != "" {
		_ = call(ctx, http.MethodGet, survivor+"/spike/stats", &survivorBefore)
		var s procStats
		_ = call(ctx, http.MethodGet, replicaA+"/spike/stats", &s)
		res.Reconnecting = int(s.Streams)
	} else {
		res.Reconnecting = n
	}
	t0 := time.Now()
	for _, v := range victims {
		v.kill()
	}
	restarted := t0
	if pause > 0 {
		_ = sleepCtx(ctx, pause)
		for _, v := range victims {
			if err := v.start(); err != nil {
				return res, err
			}
		}
		restarted = time.Now()
	}
	var st simStats
	// Wait for the disconnections to show, then for everyone to be back.
	_ = waitUntil(ctx, 10*time.Second, func() bool {
		return call(ctx, http.MethodGet, epsAdmin+"/spike/stats", &st) == nil && st.Connected < n
	})
	err := waitUntil(ctx, 120*time.Second, func() bool {
		return call(ctx, http.MethodGet, epsAdmin+"/spike/stats", &st) == nil && st.Connected == n
	})
	res.Recovery = time.Since(restarted)
	if err != nil {
		log.Printf("%s: %d of %d reconnected", name, st.Connected, n)
	}
	res.LeaseExpiries, res.Errors = st.LeaseExpiries, st.Errors
	var dials struct {
		Total int `json:"total"`
		Peak  int `json:"peak_per_100ms"`
	}
	if err := call(ctx, http.MethodGet, epsAdmin+"/spike/dials?since="+strconv.FormatInt(t0.UnixMilli(), 10), &dials); err == nil {
		res.Dials, res.PeakDials = dials.Total, dials.Peak
	}
	if survivor != "" {
		var after procStats
		if err := call(ctx, http.MethodGet, survivor+"/spike/stats", &after); err == nil {
			res.CPUPercent = 100 * (after.CPUSeconds - survivorBefore.CPUSeconds) / time.Since(t0).Seconds()
		}
	} else {
		// Restarted replicas: their CPU time since the restart, averaged.
		stats := replicaStats(ctx)
		total := 0.0
		for _, s := range stats {
			total += s.CPUSeconds
		}
		if len(stats) > 0 {
			res.CPUPercent = 100 * total / float64(len(stats)) / time.Since(restarted).Seconds()
		}
	}
	log.Printf("%s (%s, jitter %v): recovery %v, %d attempts, peak %d per 100 ms, %d lease expiries",
		name, policy, jitter, res.Recovery.Round(time.Millisecond), res.Dials, res.PeakDials, res.LeaseExpiries)
	return res, nil
}

func printReport(r report) {
	mb := func(b uint64) float64 { return float64(b) / (1 << 20) }
	fmt.Printf("\n## S2 results: %d enforcement points, lease TTL %d s\n\n", r.EPs, r.LeaseTTLSeconds)
	fmt.Printf("Cold start: every enforcement point connected in %.1f s\n\n", r.ColdStart.Seconds())
	fmt.Println("| Replica | Streams | Heap live before, MiB | Heap live with streams, MiB | Per stream, KiB | Goroutines | CPU while idle |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- |")
	for _, name := range []string{"a", "b"} {
		before, with := r.Idle[name], r.Streams[name]
		per := 0.0
		if with.Streams > 0 {
			per = (float64(with.HeapLive) - float64(before.HeapLive)) / float64(with.Streams) / 1024
		}
		fmt.Printf("| %s | %d | %.1f | %.1f | %.1f | %d | %.1f%% |\n", name, with.Streams, mb(before.HeapLive), mb(with.HeapLive), per, with.Goroutines, r.IdleCPUPercent[name])
	}
	fmt.Println("\nHalt propagation, from issue to acknowledgement recorded, in ms:")
	fmt.Println()
	fmt.Println("| Halt | n | p50 | p95 | p99 | max |")
	fmt.Println("| --- | --- | --- | --- | --- | --- |")
	fmt.Printf("| Agent halts, all | %s |\n", r.AgentHalts)
	fmt.Printf("| Agent halts issued on replica A | %s |\n", r.AgentHaltsByA)
	fmt.Printf("| Agent halts issued on replica B | %s |\n", r.AgentHaltsByB)
	for i, s := range r.FleetHalts {
		fmt.Printf("| Fleet halt %d | %s |\n", i+1, s)
	}
	fmt.Printf("| Fleet halts, all acknowledgements | %s |\n", r.FleetAll)
	fmt.Println("\nFleet halts, from issue to receipt by the enforcement point, in ms:")
	fmt.Println()
	for i, s := range r.FleetReceipts {
		fmt.Printf("- fleet halt %d: %s (missing acknowledgements: %d)\n", i+1, s, r.FleetMissing[i])
	}
	for _, p := range r.Partitions {
		fmt.Printf("\nPartition of %d enforcement points, %s backoff: %d failed closed, %d recovered after the heal\n\n", p.EPs, p.Policy, p.FailedClosed, p.Recovered)
		fmt.Println("| Measure | n | p50 | p95 | p99 | max |")
		fmt.Println("| --- | --- | --- | --- | --- | --- |")
		fmt.Printf("| Partition start to fail-closed | %s |\n", p.FailClosedAfter)
		fmt.Printf("| Last renewal to fail-closed | %s |\n", p.AfterLastRenewal)
		fmt.Printf("| Heal to recovered | %s |\n", p.RecoveryAfter)
	}
	fmt.Println("\n| Storm | Backoff | Jitter | Reconnecting | Recovery, s | Connection attempts | Peak per 100 ms | Lease expiries | CPU |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, s := range r.Storms {
		fmt.Printf("| %s | %s | %v | %d | %.2f | %d | %d | %d | %.0f%% |\n", s.Name, s.Policy, s.Jitter, s.Reconnecting, s.Recovery.Seconds(), s.Dials, s.PeakDials, s.LeaseExpiries, s.CPUPercent)
	}
	fmt.Printf("\nSimulator process: %.0f MiB, %d goroutines\n", mb(r.Simulator.MemTotal), r.Simulator.Goroutines)
}
