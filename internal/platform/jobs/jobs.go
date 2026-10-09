// Package jobs runs the core's background jobs (plan P1-01, step 7;
// architecture, section 3.1). Every replica registers the same jobs, and
// each job runs on one replica at a time, its leader: the replica that holds
// the job's PostgreSQL advisory lock (ADR-0003).
//
// A replica takes its locks on a connection of its own, and checks in on it
// at every CheckInterval. When the connection fails, the replica stops the
// jobs it leads at once. The database releases the locks when the replica
// stops or its connection closes, and when a replica cut off from it has not
// checked in for IdleTimeout. Another replica takes over at its next check.
// A run that loses its leader ends with its context, so jobs must be
// idempotent, and safe to run again after a run that stopped halfway.
//
// A new leader keeps the job's pace: it schedules the next run from the start
// of the last one on any replica, which job_state records with its outcome.
// A run missed while no replica led the job happens once, at once.
package jobs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// Job is a background job.
type Job struct {
	// Name identifies the job: lowercase letters, digits and hyphens. It
	// names the job's lock, its row in job_state and its metrics.
	Name string
	// Schedule says when the job runs.
	Schedule Schedule
	// Run does the job's work. Its context ends when the replica stops
	// leading the job, or stops: Run must then return promptly.
	Run func(ctx context.Context) error
}

// Defaults of the options.
const (
	DefaultCheckInterval = 5 * time.Second
	DefaultIdleTimeout   = 30 * time.Second
)

// Options are what the runner needs from the rest of the server.
type Options struct {
	// DB takes the locks, on a connection of its own, and records the runs
	// in job_state.
	DB *db.DB
	// Replica names this replica in job_state.
	Replica string
	Logger  *slog.Logger
	Metrics *metrics.Jobs
	// Clock is the system clock unless a test sets another.
	Clock clock.Clock
	// CheckInterval is how often the replica checks in on its lock
	// connection, and tries to take the jobs that no replica leads.
	CheckInterval time.Duration
	// IdleTimeout is how long the database keeps the locks of a replica that
	// stopped checking in; at least three check intervals.
	IdleTimeout time.Duration
}

// Runner runs the jobs that this replica leads.
type Runner struct {
	opts    Options
	locks   locks
	history history
	jobs    []*job
	running atomic.Bool
	// failing is Run's: whether the last lock session failed.
	failing bool
}

type job struct {
	Job
	key int32
}

// New returns a runner that takes its locks and records its runs in the
// database.
func New(opts Options) *Runner {
	opts.CheckInterval = cmp.Or(opts.CheckInterval, DefaultCheckInterval)
	opts.IdleTimeout = max(cmp.Or(opts.IdleTimeout, DefaultIdleTimeout), 3*opts.CheckInterval)
	return newRunner(opts, postgresLocks{opts.DB, opts.IdleTimeout}, newPostgresHistory(opts.DB))
}

func newRunner(opts Options, l locks, h history) *Runner {
	opts.Clock = cmp.Or(opts.Clock, clock.System)
	opts.CheckInterval = cmp.Or(opts.CheckInterval, DefaultCheckInterval)
	return &Runner{opts: opts, locks: l, history: h}
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// Add registers a job; every replica registers the same ones. It fails on an
// invalid job, on a name already registered, and once Run has started.
func (r *Runner) Add(j Job) error {
	switch {
	case r.running.Load():
		return errors.New("jobs: Add after Run")
	case !namePattern.MatchString(j.Name):
		return fmt.Errorf("jobs: invalid name %q: lowercase letters, digits and hyphens, starting with a letter", j.Name)
	case j.Schedule == nil || j.Run == nil:
		return fmt.Errorf("jobs: %s needs a schedule and a function", j.Name)
	}
	now := r.opts.Clock.Now()
	if !j.Schedule.Next(now).After(now) {
		return fmt.Errorf("jobs: %s: the schedule never moves forward", j.Name)
	}
	key := lockKey(j.Name)
	for _, other := range r.jobs {
		if other.Name == j.Name || other.key == key {
			return fmt.Errorf("jobs: %s: the name, or its lock, is taken by %s", j.Name, other.Name)
		}
	}
	r.jobs = append(r.jobs, &job{Job: j, key: key})
	return nil
}

// lockClass marks the advisory locks of background jobs: "WTjb" in ASCII.
// They take the two-key form, which does not overlap with the one-key form of
// the migrations' lock.
const lockClass int32 = 0x57546a62

// lockKey is the second key of a job's lock.
func lockKey(name string) int32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return int32(h.Sum32()) //nolint:gosec // G115: a hash, wrapped on purpose
}

// Run runs the jobs that this replica leads until ctx ends, then stops them
// and returns once they have returned. Without jobs, it opens no connection.
// It logs a warning when the lock session starts failing and a message when
// one holds again; the attempts between them are logged at the debug level.
func (r *Runner) Run(ctx context.Context) {
	r.running.Store(true)
	if len(r.jobs) == 0 {
		<-ctx.Done()
		return
	}
	for ctx.Err() == nil {
		err := r.session(ctx)
		if ctx.Err() != nil {
			return
		}
		level := slog.LevelDebug
		if !r.failing {
			r.failing, level = true, slog.LevelWarn
		}
		r.opts.Logger.Log(ctx, level, "background jobs: the lock session failed; reconnecting",
			"error", err.Error(), "retry_in", r.opts.CheckInterval.String())
		if !r.sleep(ctx, r.opts.CheckInterval) {
			return
		}
	}
}

// leadership is a job that this replica leads.
type leadership struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// session takes and holds locks on one connection, and leads the jobs it
// locks, until the connection fails or ctx ends. The jobs then stop before it
// returns, so that a job never runs twice on one replica.
func (r *Runner) session(ctx context.Context) error {
	s, err := r.locks.open(ctx)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer s.close()
	if r.failing {
		r.failing = false
		r.opts.Logger.InfoContext(ctx, "background jobs: the lock session holds again")
	}
	leading := map[*job]leadership{}
	defer func() {
		for _, l := range leading {
			l.cancel()
		}
		for j, l := range leading {
			<-l.done
			r.opts.Metrics.Leading(j.Name, false)
			r.opts.Logger.InfoContext(ctx, "stopped leading a background job", "job", j.Name)
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.check(ctx); err != nil {
			return fmt.Errorf("checking in: %w", err)
		}
		for _, j := range r.jobs {
			if _, ok := leading[j]; ok {
				continue
			}
			locked, err := s.tryLock(ctx, j.key)
			if err != nil {
				return fmt.Errorf("locking %s: %w", j.Name, err)
			}
			if locked {
				leading[j] = r.lead(ctx, j)
			}
		}
		if !r.sleep(ctx, r.opts.CheckInterval) {
			return ctx.Err()
		}
	}
}

// lead starts leading a job.
func (r *Runner) lead(ctx context.Context, j *job) leadership {
	ctx, cancel := context.WithCancel(ctx)
	l := leadership{cancel: cancel, done: make(chan struct{})}
	r.opts.Metrics.Leading(j.Name, true)
	r.opts.Logger.InfoContext(ctx, "leading a background job", "job", j.Name)
	go func() {
		defer close(l.done)
		r.schedule(ctx, j)
	}()
	return l
}

// schedule runs a job at the times of its schedule, until ctx ends.
func (r *Runner) schedule(ctx context.Context, j *job) {
	next := r.opts.Clock.Now()
	switch last, err := r.history.lastStarted(ctx, j.Name); {
	case err != nil:
		// Without the pace of the last run, wait a whole period rather than
		// risk running early.
		r.opts.Logger.WarnContext(ctx, "background jobs: reading the last run", "job", j.Name, "error", err.Error())
		next = j.Schedule.Next(next)
	case !last.IsZero():
		next = j.Schedule.Next(last)
	}
	for {
		if !r.sleep(ctx, next.Sub(r.opts.Clock.Now())) {
			return
		}
		started := r.opts.Clock.Now()
		r.run(ctx, j, started)
		if ctx.Err() != nil {
			return
		}
		// A run that overran the next start is followed by another at once;
		// the starts it overran are skipped.
		next = j.Schedule.Next(started)
	}
}

// run runs a job once, and records the run.
func (r *Runner) run(ctx context.Context, j *job, started time.Time) {
	if err := r.history.started(ctx, j.Name, r.opts.Replica, started); err != nil {
		r.opts.Logger.WarnContext(ctx, "background jobs: recording a start", "job", j.Name, "error", err.Error())
	}
	err := r.call(ctx, j)
	ended := r.opts.Clock.Now()
	if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
		// The replica stopped leading the job; nothing failed.
		r.opts.Logger.InfoContext(ctx, "background job interrupted", "job", j.Name)
		return
	}
	r.opts.Metrics.Ran(j.Name, ended.Sub(started), ended, err == nil)
	if err != nil {
		r.opts.Logger.ErrorContext(ctx, "background job failed", "job", j.Name, "error", logging.Sanitize(err.Error()))
	}
	// Recorded even when ctx has just ended: the run did end so.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if herr := r.history.finished(rctx, j.Name, ended, err); herr != nil {
		r.opts.Logger.WarnContext(ctx, "background jobs: recording an end", "job", j.Name, "error", herr.Error())
	}
}

// call runs the job's function, and turns a panic into an error, with the
// stack in the log.
func (r *Runner) call(ctx context.Context, j *job) (err error) {
	defer func() {
		if p := recover(); p != nil {
			r.opts.Logger.ErrorContext(ctx, "panic in a background job", "job", j.Name,
				"panic", logging.Sanitize(fmt.Sprint(p)), "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return j.Run(ctx)
}

// sleep waits for d, and reports false when ctx ends first.
func (r *Runner) sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	if d <= 0 {
		return true
	}
	t := r.opts.Clock.NewTimer(d)
	select {
	case <-ctx.Done():
		t.Stop()
		return false
	case <-t.C():
		return true
	}
}

// locks opens sessions that hold advisory locks.
type locks interface {
	open(ctx context.Context) (session, error)
}

// session holds advisory locks until it ends.
type session interface {
	// tryLock takes the lock of a job, unless another session holds it.
	tryLock(ctx context.Context, key int32) (bool, error)
	// check checks in, and fails when the session has ended.
	check(ctx context.Context) error
	// close ends the session, which releases its locks.
	close()
}

// history records the runs of jobs.
type history interface {
	// lastStarted returns when the job last started, on any replica, or the
	// zero time when it never did.
	lastStarted(ctx context.Context, job string) (time.Time, error)
	started(ctx context.Context, job, replica string, at time.Time) error
	finished(ctx context.Context, job string, at time.Time, err error) error
}
