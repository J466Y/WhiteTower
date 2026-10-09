package jobs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// server is a replica of the server running jobs on the test's database.
type server struct {
	name     string
	registry *prometheus.Registry
	stop     func()
}

func startServer(t *testing.T, d *dbtest.Database, name string, jobs ...Job) *server {
	t.Helper()
	reg := prometheus.NewRegistry()
	r := New(Options{
		DB: d.OpenReplica(t, name), Replica: name, Logger: slog.New(slog.DiscardHandler),
		Metrics: metrics.NewJobs(reg), CheckInterval: 50 * time.Millisecond,
	})
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
	return &server{name: name, registry: reg, stop: stop}
}

func (s *server) leads(t *testing.T, job string) bool {
	t.Helper()
	return value(t, s.registry, "whitetower_job_leader", job) == 1
}

// tracker records the runs of a job on every replica, and fails the test if
// two overlap, unless overlaps are expected.
type tracker struct {
	t        *testing.T
	overlaps bool
	running  atomic.Int32
	runs     chan string // the replica of each run
}

func newTracker(t *testing.T) *tracker { return &tracker{t: t, runs: make(chan string, 10000)} }

func (k *tracker) job(name, replica string) Job {
	return Job{Name: name, Schedule: Every(20 * time.Millisecond), Run: func(ctx context.Context) error {
		if k.running.Add(1) > 1 && !k.overlaps {
			k.t.Errorf("%s runs on two replicas at once", name)
		}
		defer k.running.Add(-1)
		k.runs <- replica
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Millisecond):
		}
		return nil
	}}
}

// next returns the replica of the next run.
func (k *tracker) next() string {
	k.t.Helper()
	select {
	case r := <-k.runs:
		return r
	case <-time.After(10 * time.Second):
		k.t.Fatal("no run for ten seconds")
		return ""
	}
}

// drain discards the runs recorded so far.
func (k *tracker) drain() {
	for {
		select {
		case <-k.runs:
		default:
			return
		}
	}
}

// The criterion of plan P1-01, step 7: with two replicas, each job runs on
// exactly one of them, and on the other once the first stops.
func TestEachJobRunsOnExactlyOneReplica(t *testing.T) {
	d := dbtest.New(t)
	alpha, beta := newTracker(t), newTracker(t)
	servers := map[string]*server{}
	for _, name := range []string{"replica-a", "replica-b"} {
		servers[name] = startServer(t, d, name, alpha.job("alpha", name), beta.job("beta", name))
	}

	for _, k := range []*tracker{alpha, beta} {
		leader := k.next()
		for range 10 {
			if r := k.next(); r != leader {
				t.Fatalf("a job ran on %s and %s", leader, r)
			}
		}
	}
	for _, job := range []string{"alpha", "beta"} {
		leaders := 0
		for _, s := range servers {
			if s.leads(t, job) {
				leaders++
			}
		}
		if leaders != 1 {
			t.Fatalf("%d replicas report that they lead %s", leaders, job)
		}
	}
	leader := alpha.next()
	other := map[string]string{"replica-a": "replica-b", "replica-b": "replica-a"}[leader]
	if !servers[leader].leads(t, "alpha") {
		t.Fatalf("%s runs alpha but does not report that it leads it", leader)
	}

	// The leader stops its jobs before it ends its session, so the other
	// replica takes over without overlap.
	servers[leader].stop()
	alpha.drain()
	for range 10 {
		if r := alpha.next(); r != other {
			t.Fatalf("alpha ran on %s after it stopped", r)
		}
	}
	var runner, status string
	if err := d.Superuser(t).QueryRow(context.Background(),
		"SELECT runner, last_status FROM whitetower.job_state WHERE name = 'alpha'").Scan(&runner, &status); err != nil {
		t.Fatal(err)
	}
	if runner != other || status != "success" {
		t.Fatalf("job_state: runner %q, status %q", runner, status)
	}
}

// When the database ends the leader's session, the leader stops its jobs at
// its next check-in, and the other replica takes them over.
func TestALostLockSessionHandsTheJobsOver(t *testing.T) {
	d := dbtest.New(t)
	k := newTracker(t)
	// Until its next check-in, the old leader does not know that it lost
	// the lock, which the database released at once: the runs may overlap.
	k.overlaps = true
	a := startServer(t, d, "replica-a", k.job("alpha", "replica-a"))
	if r := k.next(); r != "replica-a" {
		t.Fatalf("ran on %s", r)
	}
	b := startServer(t, d, "replica-b", k.job("alpha", "replica-b"))

	if n := d.Terminate(t, "replica-a jobs"); n != 1 {
		t.Fatalf("ended %d sessions, want 1", n)
	}
	deadline := time.Now().Add(10 * time.Second)
	for k.next() != "replica-b" {
		if time.Now().After(deadline) {
			t.Fatal("replica-b did not take over")
		}
	}
	time.Sleep(200 * time.Millisecond) // a few check intervals: replica-a is back, without the lock
	k.drain()
	for range 10 {
		if r := k.next(); r != "replica-b" {
			t.Fatalf("alpha ran on %s", r)
		}
	}
	if a.leads(t, "alpha") || !b.leads(t, "alpha") {
		t.Fatal("the metrics do not name the leader")
	}
}

func TestJobStateRecordsFailures(t *testing.T) {
	d := dbtest.New(t)
	ran := make(chan struct{}, 100)
	startServer(t, d, "replica-a", Job{Name: "broken", Schedule: Every(time.Hour), Run: func(context.Context) error {
		ran <- struct{}{}
		return errors.New("the syslog receiver refused the connection\r\nforged: line")
	}})
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("the job did not run")
	}
	superuser := d.Superuser(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var status, message *string
		var started, finished *time.Time
		if err := superuser.QueryRow(context.Background(),
			"SELECT last_status, last_error, last_started_at, last_finished_at FROM whitetower.job_state WHERE name = 'broken'",
		).Scan(&status, &message, &started, &finished); err != nil {
			t.Fatal(err)
		}
		if status != nil {
			if *status != "failure" || *message != `the syslog receiver refused the connection\r\nforged: line` ||
				started == nil || finished == nil || finished.Before(*started) {
				t.Fatalf("job_state: %v %q %v %v", *status, *message, started, finished)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the end of the run was not recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
