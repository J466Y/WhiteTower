package inventory_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/jobs"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

const day = 24 * time.Hour

// runGuard runs the lifecycle guard once, as its job does.
func (f *fixture) runGuard(t *testing.T) error {
	t.Helper()
	return f.inv.GuardJob(slog.New(slog.DiscardHandler)).Run(context.Background())
}

// startGuard runs the lifecycle guard as the server does, under a runner of
// background jobs that leads it through the database, on the fixture's
// clock, until the test ends. It returns once the first run, which starts at
// once, is over.
func (f *fixture) startGuard(t *testing.T) {
	t.Helper()
	discard := slog.New(slog.DiscardHandler)
	runner := jobs.New(jobs.Options{
		DB: f.pool, Replica: "replica-a", Logger: discard, Metrics: metrics.NewJobs(prometheus.NewRegistry()), Clock: f.clk,
	})
	if err := runner.Add(f.inv.GuardJob(discard)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	f.clk.WaitTimers(t, 2) // the next check-in and the next run
}

// giveTo makes p the agent's primary owner, as an operator reassigns it.
func (f *fixture) giveTo(t *testing.T, agent uuid.UUID, p auth.Principal) {
	t.Helper()
	if _, err := f.inv.Reassign(context.Background(), f.omar, agent, f.get(t, agent).Version, uuid.MustParse(p.ID), "Reorganization."); err != nil {
		t.Fatal(err)
	}
}

// suspension returns the agent's lifecycle state, followed by the reason of
// its suspension.
func (f *fixture) suspension(t *testing.T, agent uuid.UUID) string {
	t.Helper()
	a := f.get(t, agent)
	if a.Suspension == nil {
		return a.LifecycleState
	}
	return a.LifecycleState + " " + a.Suspension.Reason
}

// reminders returns the recipients of the review's open reminders, oldest
// first: a principal's ID, or a role.
func (f *fixture) reminders(t *testing.T, review uuid.UUID) []string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT coalesce(principal_id::text, role) FROM whitetower.inbox_items
		WHERE kind = 'review_due' AND subject_type = 'review' AND subject_id = $1 AND resolved_at IS NULL ORDER BY created_at, id`, review)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := []string{}
	for rows.Next() {
		var to string
		if err := rows.Scan(&to); err != nil {
			t.Fatal(err)
		}
		found = append(found, to)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return found
}

// remindedEvents returns the review events of the reminders, oldest first.
func (f *fixture) remindedEvents(t *testing.T) []event {
	t.Helper()
	var reminded []event
	for _, e := range f.events(t, "whitetower.review.changed.v1") {
		if e.data["change"] == "reminded" {
			reminded = append(reminded, e)
		}
	}
	return reminded
}

// Deactivating an agent's owner, as SCIM does, suspends the agent within one
// interval of the lifecycle guard, which a runner of background jobs leads
// through the database; so does letting its review lapse past its grace
// period. Until the next run, the agent stays as it is (INV-05; plan P1-04,
// step 7).
func TestTheGuardSuspendsAnAgentWithinOneInterval(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	left := f.inState(t, "owner-left", "active")
	lapsed := f.inState(t, "review-lapsed", "active")
	f.giveTo(t, lapsed.ID, f.otto)
	r := f.openReview(t, lapsed.ID)
	f.startGuard(t)

	people := authn.NewPrincipalStore(f.pool, f.clk, f.opts.Writer,
		authn.NewSessionStore(f.pool, f.clk, f.opts.Writer, authn.SessionOptions{}), nil)
	if err := people.Deactivate(ctx, uuid.MustParse(f.olivia.ID), authn.SCIMPrincipal, "SCIM deprovisioning (patch active=false)"); err != nil {
		t.Fatal(err)
	}
	if got := f.suspension(t, left.ID); got != "active" {
		t.Fatalf("before the next run, the agent is %s", got)
	}
	f.clk.Advance(time.Minute)
	f.clk.WaitTimers(t, 2)
	if got := f.suspension(t, left.ID); got != "suspended owner_inactive" {
		t.Fatalf("a minute after its owner left, the agent is %s", got)
	}
	if got := f.suspension(t, lapsed.ID); got != "active" {
		t.Fatalf("the agent of an active owner is %s", got)
	}

	// The run before the end of the grace period leaves the agent in service,
	// and the next one suspends it.
	f.clk.Advance(r.GraceEndsAt.Sub(f.clk.Now()) - 30*time.Second)
	f.clk.WaitTimers(t, 2)
	if got := f.suspension(t, lapsed.ID); got != "active" {
		t.Fatalf("within its grace period, the agent is %s", got)
	}
	f.clk.Advance(time.Minute)
	f.clk.WaitTimers(t, 2)
	if got := f.suspension(t, lapsed.ID); got != "suspended review_overdue" {
		t.Fatalf("a minute after its review lapsed, the agent is %s", got)
	}
	last, changed := f.lastTransition(t, lapsed.ID)
	if last.Transition != "T11" || last.Reason != "review_overdue" || last.Actor.Type != "system" || last.Actor.ID != nil ||
		changed.actorType != "system" || changed.data["suspension_reason"] != "review_overdue" {
		t.Errorf("history %+v, event %+v", last, changed)
	}
	if status := scalar[string](t, f, `SELECT last_status FROM whitetower.job_state WHERE name = 'lifecycle-guard'`); status != "success" {
		t.Errorf("the job's last run: %s", status)
	}
}

// The lifecycle guard suspends, as White Tower, each validated, ready or
// active agent whose primary owner is no longer active, and each whose open
// review is past its grace period, for the reason that holds, the owner's
// first. It leaves every other agent as it is, and never moves an agent out
// of a suspension. A second run changes nothing.
func TestTheGuardSuspendsOnlyTheAgentsWhoseReasonHolds(t *testing.T) {
	f := setup(t)
	leo := f.member(t, "Leo Leaver", "owner")
	past, future := f.clk.Now().Add(-time.Second), f.clk.Now().Add(time.Hour)
	in := func(state string) func(*testing.T, string) *inventory.Agent {
		return func(t *testing.T, slug string) *inventory.Agent { return f.inState(t, slug, state) }
	}
	lapse := func(t *testing.T, a *inventory.Agent) { f.review(t, a.ID, &past) }
	cases := []struct {
		name   string
		agent  func(*testing.T, string) *inventory.Agent
		leaves bool // its primary owner, Leo, leaves
		spoil  func(*testing.T, *inventory.Agent)
		want   string
	}{
		{"a validated agent whose owner left", in("validated"), true, nil, "suspended owner_inactive"},
		{"a ready agent whose owner left", in("ready"), true, nil, "suspended owner_inactive"},
		{"an active agent whose owner left", in("active"), true, nil, "suspended owner_inactive"},
		{"an active agent whose review lapsed", in("active"), false, lapse, "suspended review_overdue"},
		{"a ready agent whose review lapsed", in("ready"), false, lapse, "suspended review_overdue"},
		{"an active agent whose owner left and whose review lapsed", in("active"), true, lapse, "suspended owner_inactive"},
		{"an active agent whose review is past due, within its grace period", in("active"), false, func(t *testing.T, a *inventory.Agent) {
			f.set(t, `UPDATE whitetower.reviews SET due_at = $2, grace_ends_at = $3 WHERE agent_id = $1`, a.ID, past, future)
		}, "active"},
		{"an active agent of an active owner", in("active"), false, nil, "active"},
		{"a suspended agent whose owner left", in("suspended from active"), true, lapse, "suspended manual"},
		{"a draft whose owner left", f.propose, true, nil, "draft"},
		{"a proposal whose owner left", f.submitted, true, nil, "proposed"},
		{"a retired agent whose owner left", f.propose, true, func(t *testing.T, a *inventory.Agent) {
			if _, err := f.act(f.omar, f.get(t, a.ID), "retire", "No longer needed."); err != nil {
				t.Fatal(err)
			}
		}, "retired"},
	}
	agents := make([]*inventory.Agent, len(cases))
	for i, c := range cases {
		agents[i] = c.agent(t, fmt.Sprintf("agent-%d", i))
		if c.leaves {
			f.giveTo(t, agents[i].ID, leo)
		}
		if c.spoil != nil {
			c.spoil(t, agents[i])
		}
	}
	f.setStatus(t, leo, "inactive")
	if err := f.runGuard(t); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		a := agents[i]
		if got := f.suspension(t, a.ID); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
			continue
		}
		reason, suspended := strings.CutPrefix(c.want, "suspended ")
		if !suspended || reason == "manual" {
			continue
		}
		last, _ := f.lastTransition(t, a.ID)
		if last.Transition != "T11" || last.Reason != reason || last.Actor.Type != "system" || last.StateVersion != f.stateVersion(t, a.ID) ||
			f.lifecycleState(t, a.ID) != "suspended" {
			t.Errorf("%s: history %+v, governance state %s", c.name, last, f.lifecycleState(t, a.ID))
		}
		var changed event
		for _, e := range f.events(t, "whitetower.agent.lifecycle_changed.v1") {
			if *e.subject == a.ID {
				changed = e
			}
		}
		if changed.actorType != "system" || changed.data["suspension_reason"] != reason || changed.data["state_version"] != float64(last.StateVersion) {
			t.Errorf("%s: event %+v", c.name, changed)
		}
	}

	transitions := scalar[int](t, f, `SELECT count(*) FROM whitetower.lifecycle_transitions`)
	events := len(f.events(t, "whitetower.agent.lifecycle_changed.v1"))
	if err := f.runGuard(t); err != nil {
		t.Fatal(err)
	}
	if again := scalar[int](t, f, `SELECT count(*) FROM whitetower.lifecycle_transitions`); again != transitions ||
		len(f.events(t, "whitetower.agent.lifecycle_changed.v1")) != events {
		t.Errorf("the second run took %d transitions", again-transitions)
	}
}

// One agent that the lifecycle guard fails to suspend stops none of the
// others: the guard logs it and goes on, and the run fails, so that its
// record says so.
func TestAnAgentThatTheGuardFailsToSuspendStopsNoOther(t *testing.T) {
	f := setup(t)
	before := f.inState(t, "agent-before", "active")
	// An agent without its governance state, which every change refuses.
	broken, olivia := uuid.Must(uuid.NewV7()), uuid.MustParse(f.olivia.ID)
	f.set(t, `INSERT INTO whitetower.agents (id, slug, name, description, kind, framework, deployment_location,
		environments, risk_tier, data_categories, use_case_id, lifecycle_state, created_by)
		VALUES ($1, 'agent-broken', 'Broken', 'Has no governance state.', 'in_house', 'langgraph', 'eu-west-1',
		'{production}', 'high', '{financial_data}', $2, 'validated', $3)`, broken, f.useCase(t, f.olivia).ID, olivia)
	f.set(t, `INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by)
		VALUES ($1, $2, $3, 'primary', $3)`, uuid.Must(uuid.NewV7()), broken, olivia)
	after := f.inState(t, "agent-after", "active")
	f.setStatus(t, f.olivia, "inactive")

	var logs bytes.Buffer
	err := f.inv.GuardJob(slog.New(slog.NewJSONHandler(&logs, nil))).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "suspensions 1, reminders 0") {
		t.Fatalf("got %v, want the run to fail", err)
	}
	for _, a := range []*inventory.Agent{before, after} {
		if got := f.suspension(t, a.ID); got != "suspended owner_inactive" {
			t.Errorf("%s is %s", a.Slug, got)
		}
	}
	if !strings.Contains(logs.String(), `"msg":"lifecycle guard: suspending an agent failed","agent_id":"`+broken.String()) {
		t.Errorf("the log does not name the agent:\n%s", logs.String())
	}
}

// blockedVersions holds back the transaction that asks for the nth version
// until the test lets it go: the transaction then holds the rows that it
// locked, but not the version counter.
type blockedVersions struct {
	inventory.StateVersions
	mu                sync.Mutex
	calls, at         int
	reached, released chan struct{}
}

func (v *blockedVersions) Next(ctx context.Context, tx *db.Tx) (int64, error) {
	v.mu.Lock()
	v.calls++
	n := v.calls
	v.mu.Unlock()
	if n == v.at {
		close(v.reached)
		<-v.released
	}
	return v.StateVersions.Next(ctx, tx)
}

// While the lifecycle guard suspends many agents, an agent halt waits for it
// at most for one short transaction of one agent: the guard holds the locks
// of one agent at a time, those of the agents it suspended are free, and
// those of the agents it has not reached yet are not taken. Each suspension
// checks its reasons again under its lock: an agent that a halt suspended
// first stays as it is, and one whose owner came back is suspended only if
// its review lapsed. On connections that wait at most 200 ms for a lock, only
// the halt of the agent that the guard holds times out (the design of the
// halt path, section 2; NFR-03).
func TestAHaltWaitsForTheGuardAtMostForOneAgent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	agents := make([]*inventory.Agent, 7)
	for i := range agents {
		agents[i] = f.inState(t, fmt.Sprintf("agent-%d", i), "active")
	}
	for _, a := range agents[4:] {
		f.giveTo(t, a.ID, f.otto)
	}
	past := f.clk.Now().Add(-time.Second)
	f.review(t, agents[5].ID, &past)
	f.setStatus(t, f.olivia, "inactive")
	f.setStatus(t, f.otto, "inactive")

	versions := &blockedVersions{StateVersions: f.opts.Versions, at: 2, reached: make(chan struct{}), released: make(chan struct{})}
	opts := f.opts
	opts.Versions = versions
	run := make(chan error, 1)
	go func() { run <- inventory.New(opts).GuardJob(slog.New(slog.DiscardHandler)).Run(ctx) }()
	defer func() {
		select {
		case <-versions.released:
		default:
			close(versions.released)
		}
	}()
	select {
	case <-versions.reached: // the guard suspended agents[0], and holds agents[1]
	case err := <-run:
		t.Fatalf("the guard ended before it held its second agent: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the guard never held its second agent")
	}

	f.setStatus(t, f.otto, "active")
	pool := f.impatientPool(t)
	halt := func(agent uuid.UUID) error {
		return pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			id, err := issueHalt(ctx, tx, agent, false)
			if err != nil {
				return err
			}
			_, err = f.inv.SystemTransition(ctx, tx, agent, inventory.Cause{Action: "halt_suspend", Halt: id})
			return err
		})
	}
	for _, i := range []int{0, 2, 4} {
		if err := halt(agents[i].ID); err != nil {
			t.Errorf("the halt of agents[%d] waited for the guard: %v", i, err)
		}
	}
	var pgErr *pgconn.PgError
	if err := halt(agents[1].ID); !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("the halt of the agent that the guard holds: got %v, want a lock timeout", err)
	}
	close(versions.released)
	if err := <-run; err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{
		"suspended owner_inactive", // suspended before its halt, which does not move it
		"suspended owner_inactive", // its halt timed out
		"suspended halt",
		"suspended owner_inactive",
		"suspended halt",
		"suspended review_overdue", // its owner came back, but its review lapsed
		"active",                   // its owner came back
	} {
		if got := f.suspension(t, agents[i].ID); got != want {
			t.Errorf("agents[%d] is %s, want %s", i, got, want)
		}
	}
}

// The lifecycle guard reminds whoever is the agent's primary owner at each
// number of days before the review's due date that the setting gives, and
// each reminder takes the one before it out of the inbox. Past the due date,
// it reminds the advisory committee, once, and the owner's last reminder
// stays. A reminder changes nothing that the review shows, so a completion
// read before it applies, and takes every reminder out of the inbox. A review
// that waits for its sign-off is not reminded.
func TestTheGuardRemindsWhoeverOwnsTheAgentUntilTheReviewIsDone(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.inState(t, "invoice-triage", "active")
	r := f.openReview(t, a.ID)
	_, waiting := f.completed(t, "awaiting-signoff")
	run := func(want ...string) {
		t.Helper()
		if err := f.runGuard(t); err != nil {
			t.Fatal(err)
		}
		if got := f.reminders(t, r.ID); !slices.Equal(got, want) {
			t.Fatalf("on %s, the open reminders go to %v, want %v", f.clk.Now().Format(time.DateTime), got, want)
		}
	}
	at := func(before time.Duration) { f.clk.Advance(r.DueAt.Add(-before).Sub(f.clk.Now())) }

	run()
	at(30*day + time.Minute)
	run()
	at(30 * day)
	run(f.olivia.ID)
	run(f.olivia.ID)
	reminded := f.remindedEvents(t)
	if len(reminded) != 1 || *reminded[0].subject != a.ID || reminded[0].actorType != "system" || reminded[0].actorID != "" ||
		reminded[0].data["review_id"] != r.ID.String() ||
		fmt.Sprint(reminded[0].data["reminder"]) != fmt.Sprintf("map[days_before_due:30 principal_id:%s]", f.olivia.ID) {
		t.Fatalf("reminder events %+v", reminded)
	}
	first := scalar[uuid.UUID](t, f, `SELECT id FROM whitetower.inbox_items WHERE subject_id = $1 AND resolved_at IS NULL`, r.ID)

	at(7 * day)
	run(f.olivia.ID)
	if scalar[bool](t, f, `SELECT resolved_at IS NULL FROM whitetower.inbox_items WHERE id = $1`, first) {
		t.Error("the first reminder stayed in the inbox")
	}
	f.giveTo(t, a.ID, f.otto)
	at(day)
	run(f.otto.ID)
	at(-time.Minute)
	run(f.otto.ID, "advisory")
	run(f.otto.ID, "advisory")
	reminded = f.remindedEvents(t)
	if len(reminded) != 4 || fmt.Sprint(reminded[2].data["reminder"]) != fmt.Sprintf("map[days_before_due:1 principal_id:%s]", f.otto.ID) ||
		fmt.Sprint(reminded[3].data["reminder"]) != "map[role:advisory]" {
		t.Fatalf("reminder events %+v", reminded)
	}
	if got := f.reminders(t, waiting.ID); len(got) != 0 {
		t.Errorf("a review that waits for its sign-off was reminded: %v", got)
	}

	if _, err := f.inv.CompleteReview(ctx, f.otto, r.ID, r.Version, attested()); err != nil {
		t.Fatal(err)
	}
	run()
}

// When several reminders fell due since the guard last ran, only the latest
// goes out; and past the due date, the advisory committee is reminded even if
// the owner never was.
func TestTheGuardSendsOnlyTheLatestReminderThatFellDue(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "active")
	b := f.inState(t, "never-reminded", "active")
	r, s := f.openReview(t, a.ID), f.openReview(t, b.ID)
	f.set(t, `UPDATE whitetower.reviews SET due_at = $2::timestamptz, grace_ends_at = $2::timestamptz + interval '14 days' WHERE id = $1`, s.ID, r.DueAt.Add(-day))
	f.clk.Advance(r.DueAt.Sub(f.clk.Now()) - 12*time.Hour)
	if err := f.runGuard(t); err != nil {
		t.Fatal(err)
	}
	if got := f.reminders(t, r.ID); !slices.Equal(got, []string{f.olivia.ID}) {
		t.Errorf("the reminders of the review due in 12 hours: %v", got)
	}
	if got := f.reminders(t, s.ID); !slices.Equal(got, []string{"advisory"}) {
		t.Errorf("the reminders of the review past its due date: %v", got)
	}
	got := map[any]string{}
	for _, e := range f.remindedEvents(t) {
		got[e.data["review_id"]] = fmt.Sprint(e.data["reminder"])
	}
	if want := map[any]string{
		r.ID.String(): fmt.Sprintf("map[days_before_due:1 principal_id:%s]", f.olivia.ID),
		s.ID.String(): "map[role:advisory]",
	}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("reminder events %v, want %v", got, want)
	}
}

// A reminder setting outside its rules fails the run, which names it and
// sends no reminder: no default stands in for it. The suspensions, which read
// no setting, still happen.
func TestAMalformedReminderSettingFailsTheRunButNoSuspension(t *testing.T) {
	f := setup(t)
	const key = "lifecycle.review_reminder_days"
	for i, value := range []string{
		`[]`, `null`, `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]`, `[0]`, `[366]`, `[-1]`, `[7, 7]`, `[7.5]`, `["7"]`, `7`, `{"days": 7}`,
	} {
		t.Run(value, func(t *testing.T) {
			leaver := f.member(t, fmt.Sprintf("Leaver %d", i), "owner")
			a := f.inState(t, fmt.Sprintf("agent-%d", i), "active")
			f.giveTo(t, a.ID, leaver)
			f.setStatus(t, leaver, "inactive")
			due := f.clk.Now().Add(time.Hour)
			f.set(t, `UPDATE whitetower.reviews SET due_at = $2::timestamptz, grace_ends_at = $2::timestamptz + interval '14 days' WHERE agent_id = $1`, a.ID, due)
			f.set(t, `UPDATE whitetower.settings SET value = $2::jsonb WHERE key = $1`, key, value)
			defer f.set(t, `UPDATE whitetower.settings SET value = '[30, 7, 1]' WHERE key = $1`, key)
			err := f.runGuard(t)
			var r *inventory.Refusal
			if err == nil || errors.As(err, &r) || !strings.Contains(err.Error(), key) {
				t.Fatalf("got %v, want an internal error that names the setting", err)
			}
			if got := f.suspension(t, a.ID); got != "suspended owner_inactive" {
				t.Errorf("the agent of an owner who left is %s", got)
			}
		})
	}
	if n := scalar[int](t, f, `SELECT count(*) FROM whitetower.inbox_items WHERE kind = 'review_due'`); n != 0 {
		t.Fatalf("%d reminders went out", n)
	}
	if err := f.runGuard(t); err != nil {
		t.Fatal(err)
	}
	if n := scalar[int](t, f, `SELECT count(*) FROM whitetower.inbox_items WHERE kind = 'review_due' AND resolved_at IS NULL`); n == 0 {
		t.Fatal("with the setting as it was, no reminder went out")
	}
}

// The reminders take no lock that an agent halt takes: while a session holds
// the agents' rows, their governance state and the version counter, as a
// halt does, every reminder goes out on connections that wait at most 200 ms
// for a lock. A halt therefore never waits for a reminder (the design of the
// halt path, section 2).
func TestTheRemindersTakeNoLockThatAHaltHolds(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "active")
	b := f.inState(t, "expense-triage", "active")
	ids := []uuid.UUID{a.ID, b.ID}
	r := f.openReview(t, a.ID)
	f.clk.Advance(r.DueAt.Sub(f.clk.Now()) - 30*day)
	f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			for _, sql := range []string{
				`SELECT 1 FROM whitetower.agents WHERE id = ANY($1) ORDER BY id FOR NO KEY UPDATE`,
				`SELECT 1 FROM whitetower.governance_state WHERE agent_id = ANY($1) ORDER BY agent_id FOR NO KEY UPDATE`,
			} {
				if _, err := tx.Exec(ctx, sql, ids); err != nil {
					return err
				}
			}
			_, err := tx.Exec(ctx, `SELECT whitetower.next_governance_version()`)
			return err
		},
		func(context.Context, *db.Tx) error { return nil })
	if err := f.impatient(t).GuardJob(slog.New(slog.DiscardHandler)).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if got := f.reminders(t, f.openReview(t, id).ID); !slices.Equal(got, []string{f.olivia.ID}) {
			t.Errorf("the reminders of %s: %v", id, got)
		}
	}
}
