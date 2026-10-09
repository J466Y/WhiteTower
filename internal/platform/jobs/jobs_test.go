package jobs

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

var epoch = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// memoryLocks are advisory locks within the process, which the runners of a
// test share as replicas share the database.
type memoryLocks struct {
	mu      sync.Mutex
	holders map[int32]*memorySession
}

var errEnded = errors.New("the session has ended")

func (l *memoryLocks) open(context.Context) (session, error) {
	return &memorySession{locks: l}, nil
}

// holder returns the session that holds a job's lock, if any.
func (l *memoryLocks) holder(name string) *memorySession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.holders[lockKey(name)]
}

type memorySession struct {
	locks *memoryLocks
	ended atomic.Bool
}

func (s *memorySession) tryLock(_ context.Context, key int32) (bool, error) {
	if s.ended.Load() {
		return false, errEnded
	}
	s.locks.mu.Lock()
	defer s.locks.mu.Unlock()
	if s.locks.holders == nil {
		s.locks.holders = map[int32]*memorySession{}
	}
	if h := s.locks.holders[key]; h != nil && h != s {
		return false, nil
	}
	s.locks.holders[key] = s
	return true, nil
}

func (s *memorySession) check(context.Context) error {
	if s.ended.Load() {
		return errEnded
	}
	return nil
}

func (s *memorySession) close() { s.end() }

// end ends the session as a failure would: its locks are free at once.
func (s *memorySession) end() {
	s.ended.Store(true)
	s.locks.mu.Lock()
	defer s.locks.mu.Unlock()
	for key, h := range s.locks.holders {
		if h == s {
			delete(s.locks.holders, key)
		}
	}
}

// memoryHistory is a job_state within the process.
type memoryHistory struct {
	mu    sync.Mutex
	last  map[string]time.Time
	runs  []string // "job replica start", in order
	ended map[string]string
}

func newMemoryHistory() *memoryHistory {
	return &memoryHistory{last: map[string]time.Time{}, ended: map[string]string{}}
}

func (h *memoryHistory) lastStarted(_ context.Context, job string) (time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last[job], nil
}

func (h *memoryHistory) started(_ context.Context, job, replica string, at time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last[job] = at
	h.runs = append(h.runs, job+" "+replica+" "+at.Format(time.TimeOnly))
	return nil
}

func (h *memoryHistory) finished(_ context.Context, job string, _ time.Time, err error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ended[job] = "success"
	if err != nil {
		h.ended[job] = "failure: " + err.Error()
	}
	return nil
}

func (h *memoryHistory) outcome(job string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ended[job]
}

// replica is a runner of a test, with what the test reads from it.
type replica struct {
	*Runner
	registry *prometheus.Registry
	logs     *lockedWriter
	stop     func()
}

func newReplica(t *testing.T, name string, clk *clocktest.Fake, l locks, h history, jobs ...Job) *replica {
	t.Helper()
	reg := prometheus.NewRegistry()
	logs := &lockedWriter{}
	r := newRunner(Options{
		Replica: name, Clock: clk, Logger: logging.New(logs, "info"), Metrics: metrics.NewJobs(reg),
	}, l, h)
	for _, j := range jobs {
		if err := r.Add(j); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		<-done
	})
	t.Cleanup(stop)
	return &replica{Runner: r, registry: reg, logs: logs, stop: stop}
}

// lockedWriter collects the logs that the runner writes while the test
// reads them.
type lockedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *lockedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// leads reports whether the replica reports that it leads the job.
func (r *replica) leads(t *testing.T, job string) bool {
	t.Helper()
	return value(t, r.registry, "whitetower_job_leader", job) == 1
}

// value returns the value of a gauge's or a counter's series for a job, or
// 0 when it has none.
func value(t *testing.T, reg *prometheus.Registry, name, job string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "job" && l.GetValue() == job {
					return m.GetGauge().GetValue() + m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// receive waits for a value from c.
func receive[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
		var zero T
		return zero
	}
}

func quiet[T any](t *testing.T, c <-chan T) {
	t.Helper()
	select {
	case v := <-c:
		t.Fatalf("unexpected %v", v)
	default:
	}
}

// ticker is a job, "tick", that runs every minute and reports the time of
// each run.
func ticker(clk *clocktest.Fake) (Job, <-chan time.Time) {
	ran := make(chan time.Time, 16)
	return Job{Name: "tick", Schedule: Every(time.Minute), Run: func(context.Context) error {
		ran <- clk.Now()
		return nil
	}}, ran
}

func TestAJobRunsOnItsSchedule(t *testing.T) {
	clk := clocktest.New(epoch)
	job, ran := ticker(clk)
	r := newReplica(t, "a", clk, &memoryLocks{}, newMemoryHistory(), job)

	// It never ran: it runs at once.
	if at := receive(t, ran); !at.Equal(epoch) {
		t.Fatalf("first run at %v", at)
	}
	for i := 1; i <= 3; i++ {
		clk.WaitTimers(t, 2) // the next check-in and the next run
		clk.Advance(time.Minute)
		if at := receive(t, ran); !at.Equal(epoch.Add(time.Duration(i) * time.Minute)) {
			t.Fatalf("run %d at %v", i, at)
		}
	}
	if !r.leads(t, "tick") {
		t.Error("the replica does not report that it leads the job")
	}
	clk.WaitTimers(t, 2)
	if got := value(t, r.registry, "whitetower_job_failures_total", "tick"); got != 0 {
		t.Errorf("%v failures", got)
	}
	if n := testutil.CollectAndCount(r.registry, "whitetower_job_duration_seconds"); n != 1 {
		t.Errorf("%d duration series", n)
	}
}

// A new leader keeps the pace of the runs before it.
func TestANewLeaderKeepsThePace(t *testing.T) {
	clk := clocktest.New(epoch)
	h := newMemoryHistory()
	h.last["tick"] = epoch.Add(-40 * time.Second)
	job, ran := ticker(clk)
	newReplica(t, "a", clk, &memoryLocks{}, h, job)

	clk.WaitTimers(t, 2)
	clk.Advance(19 * time.Second)
	clk.WaitTimers(t, 2)
	quiet(t, ran)
	clk.Advance(time.Second)
	if at := receive(t, ran); !at.Equal(epoch.Add(20 * time.Second)) {
		t.Fatalf("ran at %v, want a minute after the last start", at)
	}
}

// A run missed while no replica led the job happens once, at once.
func TestAMissedRunHappensOnce(t *testing.T) {
	clk := clocktest.New(epoch)
	h := newMemoryHistory()
	h.last["tick"] = epoch.Add(-time.Hour)
	job, ran := ticker(clk)
	newReplica(t, "a", clk, &memoryLocks{}, h, job)

	if at := receive(t, ran); !at.Equal(epoch) {
		t.Fatalf("ran at %v", at)
	}
	clk.WaitTimers(t, 2)
	quiet(t, ran)
	clk.Advance(time.Minute)
	if at := receive(t, ran); !at.Equal(epoch.Add(time.Minute)) {
		t.Fatalf("ran at %v", at)
	}
}

func TestEachJobRunsOnOneReplica(t *testing.T) {
	clk := clocktest.New(epoch)
	locks, h := &memoryLocks{}, newMemoryHistory()
	job, ran := ticker(clk)
	a := newReplica(t, "a", clk, locks, h, job)
	receive(t, ran)
	clk.WaitTimers(t, 2)
	b := newReplica(t, "b", clk, locks, h, job)
	clk.WaitTimers(t, 3) // b checks in again later
	if !a.leads(t, "tick") || b.leads(t, "tick") {
		t.Fatal("a should lead the job, and b wait")
	}

	// a stops: its session ends, and b takes over at its next check-in,
	// keeping the pace of a's runs.
	a.stop()
	clk.Advance(DefaultCheckInterval)
	clk.WaitTimers(t, 2)
	if !b.leads(t, "tick") {
		t.Fatal("b did not take over")
	}
	quiet(t, ran)
	clk.Advance(time.Minute - DefaultCheckInterval)
	if at := receive(t, ran); !at.Equal(epoch.Add(time.Minute)) {
		t.Fatalf("ran at %v", at)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if want := []string{"tick a 12:00:00", "tick b 12:01:00"}; strings.Join(h.runs, ", ") != strings.Join(want, ", ") {
		t.Fatalf("runs %v, want %v", h.runs, want)
	}
}

// When its session fails, a replica stops the jobs it leads at once: another
// replica may take them over.
func TestALostSessionStopsItsJobs(t *testing.T) {
	clk := clocktest.New(epoch)
	locks := &memoryLocks{}
	started, stopped := make(chan struct{}, 4), make(chan error, 4)
	job := Job{Name: "long", Schedule: Every(time.Hour), Run: func(ctx context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		stopped <- ctx.Err()
		return ctx.Err()
	}}
	h := newMemoryHistory()
	r := newReplica(t, "a", clk, locks, h, job)
	receive(t, started)
	clk.WaitTimers(t, 1)

	locks.holder("long").end()
	clk.Advance(DefaultCheckInterval)
	if err := receive(t, stopped); !errors.Is(err, context.Canceled) {
		t.Fatalf("the job ended with %v", err)
	}
	clk.WaitTimers(t, 1) // the wait before reconnecting
	if r.leads(t, "long") {
		t.Fatal("the replica still reports that it leads the job")
	}
	if got := h.outcome("long"); got != "" {
		t.Errorf("an interrupted run was recorded as %q", got)
	}
	if got := value(t, r.registry, "whitetower_job_failures_total", "long"); got != 0 {
		t.Errorf("an interrupted run counted as a failure")
	}

	// It reconnects, leads the job again, and keeps its pace.
	clk.Advance(DefaultCheckInterval)
	clk.WaitTimers(t, 2)
	if !r.leads(t, "long") {
		t.Fatal("the replica did not lead the job again")
	}
	quiet(t, started)
	if logs := r.logs.String(); !strings.Contains(logs, "the lock session failed") ||
		!strings.Contains(logs, "the lock session holds again") {
		t.Errorf("logs:\n%s", logs)
	}
}

func TestFailuresAndPanicsAreRecorded(t *testing.T) {
	clk := clocktest.New(epoch)
	h := newMemoryHistory()
	calls := make(chan struct{}, 8)
	var n atomic.Int32
	job := Job{Name: "flaky", Schedule: Every(time.Minute), Run: func(context.Context) error {
		defer func() { calls <- struct{}{} }()
		switch n.Add(1) {
		case 1:
			return errors.New("the export target refused the batch")
		case 2:
			panic("index out of range")
		}
		return nil
	}}
	r := newReplica(t, "a", clk, &memoryLocks{}, h, job)

	receive(t, calls)
	clk.WaitTimers(t, 2)
	if got := h.outcome("flaky"); got != "failure: the export target refused the batch" {
		t.Errorf("recorded %q", got)
	}
	clk.Advance(time.Minute)
	receive(t, calls)
	clk.WaitTimers(t, 2)
	if got := h.outcome("flaky"); got != "failure: panic: index out of range" {
		t.Errorf("recorded %q", got)
	}
	if got := value(t, r.registry, "whitetower_job_failures_total", "flaky"); got != 2 {
		t.Errorf("%v failures, want 2", got)
	}
	if testutil.CollectAndCount(r.registry, "whitetower_job_last_success_timestamp_seconds") != 0 {
		t.Error("a success was recorded")
	}
	clk.Advance(time.Minute)
	receive(t, calls)
	clk.WaitTimers(t, 2)
	if got := h.outcome("flaky"); got != "success" {
		t.Errorf("recorded %q", got)
	}
	want := float64(epoch.Add(2*time.Minute).UnixMilli()) / 1000
	if got := value(t, r.registry, "whitetower_job_last_success_timestamp_seconds", "flaky"); got != want {
		t.Errorf("last success %v, want %v", got, want)
	}
	if logs := r.logs.String(); !strings.Contains(logs, `"msg":"panic in a background job"`) ||
		!strings.Contains(logs, `"stack":`) {
		t.Errorf("the panic is not logged with its stack:\n%s", logs)
	}
}

func TestAdd(t *testing.T) {
	r := newRunner(Options{Clock: clocktest.New(epoch)}, &memoryLocks{}, newMemoryHistory())
	run := func(context.Context) error { return nil }
	if err := r.Add(Job{Name: "audit-sealer", Schedule: Every(200 * time.Millisecond), Run: run}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		job  Job
		want string
	}{
		{Job{Name: "audit-sealer", Schedule: Every(time.Second), Run: run}, "is taken by audit-sealer"},
		{Job{Name: "Audit", Schedule: Every(time.Second), Run: run}, "invalid name"},
		{Job{Name: "audit_sealer", Schedule: Every(time.Second), Run: run}, "invalid name"},
		{Job{Name: "", Schedule: Every(time.Second), Run: run}, "invalid name"},
		{Job{Name: "no-schedule", Run: run}, "needs a schedule and a function"},
		{Job{Name: "no-function", Schedule: Every(time.Second)}, "needs a schedule and a function"},
		{Job{Name: "stuck", Schedule: Every(0), Run: run}, "never moves forward"},
	} {
		if err := r.Add(tt.job); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: got %v, want an error with %q", tt.job.Name, err, tt.want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Run(ctx)
	if err := r.Add(Job{Name: "late", Schedule: Every(time.Second), Run: run}); err == nil {
		t.Error("Add after Run succeeded")
	}
}
