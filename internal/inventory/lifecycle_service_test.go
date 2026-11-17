package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// refusedBy fails the test unless err is a conflict that names the guard.
func refusedBy(t *testing.T, err error, guard string) {
	t.Helper()
	var r *inventory.Refusal
	if !errors.As(err, &r) || r.Kind != inventory.Conflict || !strings.Contains(r.Detail, guard) {
		t.Fatalf("got %v, want a conflict that names the guard %s", err, guard)
	}
}

// get reads the agent again, as an operator.
func (f *fixture) get(t *testing.T, id uuid.UUID) *inventory.Agent {
	t.Helper()
	a, err := f.inv.Get(context.Background(), f.omar, id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// serviceAccount stores a service account that Omar is responsible for, and
// returns it as an API caller with the role given.
func (f *fixture) serviceAccount(t *testing.T, role string) auth.Principal {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	f.set(t, `INSERT INTO whitetower.principals (id, kind, display_name, responsible_principal_id)
		VALUES ($1, 'service_account', 'Deploy bot', $2)`, id, uuid.MustParse(f.omar.ID))
	return auth.Principal{ID: id.String(), Kind: auth.ServiceAccount, Name: "Deploy bot", Roles: []string{role}}
}

// system takes a transition as White Tower, in a transaction of its own, and
// reports whether the agent moved.
func (f *fixture) system(t *testing.T, id uuid.UUID, c inventory.Cause) bool {
	t.Helper()
	var moved bool
	if err := f.pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		var err error
		moved, err = f.inv.SystemTransition(ctx, tx, id, c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return moved
}

// halt halts the agent, or releases it, as an agent halt of plan P1-08 does
// to its governance state.
func (f *fixture) halt(t *testing.T, id uuid.UUID, halted bool) {
	t.Helper()
	ids := []uuid.UUID{}
	if halted {
		ids = append(ids, uuid.Must(uuid.NewV7()))
	}
	f.set(t, `UPDATE whitetower.governance_state SET run_state = CASE WHEN cardinality($2::uuid[]) > 0 THEN 'halted' ELSE 'running' END,
		agent_halt_ids = $2, state_version = whitetower.next_governance_version() WHERE agent_id = $1`, id, ids)
}

// review gives the agent an open review whose grace period ends at the time
// given, or, without a time, cancels its open review.
func (f *fixture) review(t *testing.T, id uuid.UUID, graceEnds *time.Time) {
	t.Helper()
	if graceEnds == nil {
		f.set(t, `UPDATE whitetower.reviews SET status = 'cancelled' WHERE agent_id = $1 AND status = 'scheduled'`, id)
		return
	}
	f.set(t, `INSERT INTO whitetower.reviews (id, agent_id, due_at, grace_ends_at, signoff_required) VALUES ($1, $2, $3, $3, false)`,
		uuid.Must(uuid.NewV7()), id, *graceEnds)
}

// setStatus makes the principal active or inactive.
func (f *fixture) setStatus(t *testing.T, p auth.Principal, status string) {
	t.Helper()
	f.set(t, `UPDATE whitetower.principals SET status = $2 WHERE id = $1`, uuid.MustParse(p.ID), status)
}

// inState brings an agent of Olivia's, with a harness and an active agent
// policy, to the state given: validated, ready, active, or suspended from one
// of those. White Tower moves it to ready (T7).
func (f *fixture) inState(t *testing.T, slug, state string) *inventory.Agent {
	t.Helper()
	ctx := context.Background()
	a, err := f.act(f.alex, f.submitted(t, slug), "validate", "Fine.")
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, `UPDATE whitetower.agents SET harness = '{"description": "A container."}' WHERE id = $1`, a.ID)
	f.policies.set(a.ID, true)
	from, suspended := strings.CutPrefix(state, "suspended from ")
	if from != "validated" && !f.system(t, a.ID, inventory.Cause{Action: "mark_ready"}) {
		t.Fatal("White Tower did not make the agent ready")
	}
	if from == "active" {
		if _, err := f.inv.Transition(ctx, f.olivia, a.ID, f.get(t, a.ID).Version, "activate", ""); err != nil {
			t.Fatal(err)
		}
	}
	if suspended {
		if _, err := f.inv.Transition(ctx, f.omar, a.ID, f.get(t, a.ID).Version, "suspend", "Suspected misuse."); err != nil {
			t.Fatal(err)
		}
	}
	return f.get(t, a.ID)
}

// lifecycleState returns the lifecycle state that the agent's governance
// state tells enforcement points.
func (f *fixture) lifecycleState(t *testing.T, id uuid.UUID) string {
	t.Helper()
	return scalar[string](t, f, `SELECT lifecycle_state FROM whitetower.governance_state WHERE agent_id = $1`, id)
}

func TestActivationPutsAReadyAgentIntoService(t *testing.T) {
	f := setup(t)
	for i, by := range []auth.Principal{f.olivia, f.omar} {
		f.clk.Advance(time.Hour)
		ready := f.inState(t, fmt.Sprintf("agent-%d", i), "ready")
		a, err := f.act(by, ready, "activate", "")
		if err != nil {
			t.Fatal(err)
		}
		if a.LifecycleState != "active" || a.ActivatedAt == nil || !a.ActivatedAt.Equal(f.clk.Now()) || a.Version != ready.Version+1 {
			t.Errorf("state %s, activated at %v, version %d", a.LifecycleState, a.ActivatedAt, a.Version)
		}
		version := f.stateVersion(t, a.ID)
		if state := f.lifecycleState(t, a.ID); state != "active" {
			t.Errorf("governance state %s", state)
		}
		history, _, err := f.inv.Transitions(context.Background(), f.alex, a.ID, nil, 1)
		if err != nil || history[0].Transition != "T9" || history[0].From != "ready" || history[0].Actor.ID.String() != by.ID ||
			history[0].StateVersion != version || history[0].Reason != "" {
			t.Errorf("history %+v, %v", history, err)
		}
		changed := f.events(t, "whitetower.agent.lifecycle_changed.v1")
		if last := changed[len(changed)-1]; last.data["transition"] != "T9" || last.data["to"] != "active" ||
			last.data["state_version"] != float64(version) || last.data["suspension_reason"] != nil {
			t.Errorf("event %+v", last)
		}
	}
}

// An agent goes into service only with an active owner, a validated use
// case, an active agent-specific policy, a declared harness and no halt (the
// invariant of active). A ready agent always has its harness: the database
// refuses one without it (agents_ready_needs_harness).
func TestActivationNeedsTheInvariantOfActive(t *testing.T) {
	f := setup(t)
	for guard, spoil := range map[string]func(a *inventory.Agent){
		"owner_active": func(*inventory.Agent) { f.setStatus(t, f.olivia, "inactive") },
		"use_case_validated": func(a *inventory.Agent) {
			f.set(t, `UPDATE whitetower.use_cases SET status = 'submitted' WHERE id = $1`, a.UseCaseID)
		},
		"agent_policy_active": func(a *inventory.Agent) { f.policies.set(a.ID, false) },
		"not_halted":          func(a *inventory.Agent) { f.halt(t, a.ID, true) },
	} {
		t.Run(guard, func(t *testing.T) {
			a := f.inState(t, "agent-"+uuid.NewString()[:8], "ready")
			spoil(a)
			_, err := f.act(f.olivia, a, "activate", "")
			f.setStatus(t, f.olivia, "active")
			refusedBy(t, err, guard)
		})
	}
	t.Run("a halted fleet", func(t *testing.T) {
		a := f.inState(t, "agent-fleet", "ready")
		f.set(t, `UPDATE whitetower.fleet_state SET run_state = 'halted', halt_ids = ARRAY[$1::uuid],
			state_version = whitetower.next_governance_version()`, uuid.Must(uuid.NewV7()))
		_, err := f.act(f.omar, a, "activate", "")
		refusedBy(t, err, "not_halted")
	})
}

// A suspension remembers the state that the agent was in, and a
// reinstatement takes it back there. A service account may suspend.
func TestASuspensionRemembersWhereTheAgentWas(t *testing.T) {
	f := setup(t)
	bot := f.serviceAccount(t, "operator")
	for i, from := range []string{"validated", "ready", "active"} {
		a := f.inState(t, fmt.Sprintf("agent-%d", i), from)
		_, err := f.act(f.olivia, a, "suspend", " ")
		refused(t, err, inventory.Invalid)
		f.clk.Advance(time.Hour)
		suspended, err := f.act(bot, a, "suspend", "Unusual traffic.")
		if err != nil {
			t.Fatal(err)
		}
		if s := suspended.Suspension; suspended.LifecycleState != "suspended" || s == nil || s.From != from || s.Reason != "manual" || !s.At.Equal(f.clk.Now()) {
			t.Errorf("%s: state %s, suspension %+v", from, suspended.LifecycleState, s)
		}
		history, _, err := f.inv.Transitions(context.Background(), f.alex, a.ID, nil, 1)
		if err != nil || history[0].Transition != "T10" || history[0].Reason != "manual" || history[0].Actor.Type != "service_account" {
			t.Errorf("history %+v, %v", history, err)
		}
		changed := f.events(t, "whitetower.agent.lifecycle_changed.v1")
		if last := changed[len(changed)-1]; last.data["suspension_reason"] != "manual" || last.data["to"] != "suspended" {
			t.Errorf("event %+v", last)
		}

		back, err := f.act(f.alex, suspended, "reinstate", "Traffic explained.")
		if err != nil {
			t.Fatal(err)
		}
		if back.LifecycleState != from || back.Suspension != nil || (from == "active") != (back.ActivatedAt != nil) {
			t.Errorf("reinstated to %s, suspension %+v, activated at %v", back.LifecycleState, back.Suspension, back.ActivatedAt)
		}
		if state := f.lifecycleState(t, a.ID); state != from {
			t.Errorf("governance state %s, want %s", state, from)
		}
	}
}

// Reinstatement checks the conditions that hold now, not the reason of the
// suspension: an active owner, no overdue review, no halt, and the invariant
// of the state that the agent returns to (the lifecycle, section 6).
func TestReinstatementChecksTheConditionsOfThePreviousState(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "suspended from active")
	past, future := f.clk.Now().Add(-time.Second), f.clk.Now().Add(time.Hour)
	for _, c := range []struct {
		guard          string
		spoil, restore func()
	}{
		{"owner_active", func() { f.setStatus(t, f.olivia, "inactive") }, func() { f.setStatus(t, f.olivia, "active") }},
		{"review_not_overdue", func() { f.review(t, a.ID, &past) }, func() { f.review(t, a.ID, nil) }},
		{"not_halted", func() { f.halt(t, a.ID, true) }, func() { f.halt(t, a.ID, false) }},
		{"previous_state_invariants_hold", func() { f.policies.set(a.ID, false) }, func() { f.policies.set(a.ID, true) }},
	} {
		c.spoil()
		_, err := f.act(f.alex, a, "reinstate", "Back to work.")
		refusedBy(t, err, c.guard)
		c.restore()
	}
	_, err := f.act(f.olivia, a, "reinstate", "My own agent.")
	refused(t, err, inventory.Forbidden)
	_, err = f.act(f.alex, a, "reinstate", "")
	refused(t, err, inventory.Invalid)

	// A review whose grace period has not ended yet holds nothing back.
	f.review(t, a.ID, &future)
	if a, err = f.act(f.omar, a, "reinstate", "Back to work."); err != nil || a.LifecycleState != "active" {
		t.Fatalf("got %+v, %v", a, err)
	}
}

// Security test ST-18: Nobody reinstates an agent that they own, delegate for, ever did, or created, nor one whose use case they created
func TestNobodyReinstatesAnAgentTheyOwnOwnedOrCreated(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.inState(t, "invoice-triage", "suspended from validated")
	assign := func(p auth.Principal, role, ended string) {
		f.set(t, `INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by, ended_at, ended_by, end_reason)
			VALUES ($1, $2, $3, $4, $3, `+ended+`)`, uuid.Must(uuid.NewV7()), a.ID, uuid.MustParse(p.ID), role)
	}
	delegate := f.person(t, "Dora Operator", "operator")
	delegate.Roles = []string{"operator", "owner"}
	assign(delegate, "delegate", "NULL, NULL, NULL")
	formerOwner := f.person(t, "Fiona Advisory", "advisory")
	assign(formerOwner, "primary", "now(), $3, 'moved on'")
	creator := f.person(t, "Carl Advisory", "advisory")
	f.set(t, `UPDATE whitetower.use_cases SET created_by = $2 WHERE id = $1`, a.UseCaseID, uuid.MustParse(creator.ID))
	for _, p := range []auth.Principal{delegate, formerOwner, creator} {
		_, err := f.act(p, a, "reinstate", "Back to work.")
		refused(t, err, inventory.Forbidden)
		if _, actions, err := f.inv.Actions(ctx, p, a.ID); err != nil || fmt.Sprint(actions[0]) != "{reinstate T13 true [not_owner_or_creator]}" {
			t.Errorf("%s: actions %+v, %v", p.Name, actions, err)
		}
	}
	if a, err := f.act(f.omar, a, "reinstate", "Back to work."); err != nil || a.LifecycleState != "validated" {
		t.Fatalf("another operator: %+v, %v", a, err)
	}
}

// Retiring a proposal takes it out of the advisory committee's inbox,
// withdraws its use case as T3 does, and cancels its pending ownership
// transfer. A retired agent never changes again.
func TestRetiringAProposalWithdrawsIt(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.submitted(t, "invoice-triage")
	transfer, err := f.inv.RequestTransfer(ctx, f.olivia, a.ID, uuid.MustParse(f.otto.ID))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.act(f.olivia, f.get(t, a.ID), "retire", "")
	refused(t, err, inventory.Invalid)
	retired, err := f.act(f.olivia, f.get(t, a.ID), "retire", "No longer needed.")
	if err != nil {
		t.Fatal(err)
	}
	if retired.LifecycleState != "retired" || retired.RetiredAt == nil || !retired.RetiredAt.Equal(f.clk.Now()) || retired.PendingTransfer != nil {
		t.Errorf("state %s, retired at %v, transfer %+v", retired.LifecycleState, retired.RetiredAt, retired.PendingTransfer)
	}
	if f.awaitingCommittee(t, a) != 0 || f.useCaseStatus(t, a) != "draft" || f.openInboxItems(t, transfer.ID) != 0 || f.lifecycleState(t, a.ID) != "retired" {
		t.Errorf("%d inbox items, use case %s, %d transfer items, governance state %s",
			f.awaitingCommittee(t, a), f.useCaseStatus(t, a), f.openInboxItems(t, transfer.ID), f.lifecycleState(t, a.ID))
	}
	for _, action := range []string{"retire", "submit"} {
		_, err := f.act(f.olivia, retired, action, "Again.")
		refused(t, err, inventory.Conflict)
	}
	if state, actions, err := f.inv.Actions(ctx, f.omar, a.ID); err != nil || state != "retired" || len(actions) != 0 {
		t.Errorf("actions of a retired agent: %s %+v, %v", state, actions, err)
	}

	// A suspended agent that retires keeps no suspension.
	suspended := f.inState(t, "invoice-sorter", "suspended from ready")
	if retired, err = f.act(f.alex, suspended, "retire", "Replaced."); err != nil || retired.Suspension != nil {
		t.Fatalf("got %+v, %v", retired, err)
	}
}

// Only people put an agent into service or retire it: a service account
// takes only suspend, whoever is responsible for it (the maintainer's
// decision of 2026-11-12). Each action needs its own permission within its
// scope, and an API token needs it among its scopes (ST-19).
func TestOnlyPeoplePutAnAgentIntoServiceOrRetireIt(t *testing.T) {
	f := setup(t)
	ready := f.inState(t, "invoice-triage", "ready")
	suspended := f.inState(t, "invoice-sorter", "suspended from validated")
	operatorBot, advisoryBot := f.serviceAccount(t, "operator"), f.serviceAccount(t, "advisory")
	breakglass := auth.Principal{ID: f.omar.ID, Kind: auth.Human, Roles: []string{"operator", "advisory"}, IsBreakglass: true}
	viewer := f.omar
	viewer.Scopes = []string{"inventory.view", "agent.suspend"}
	for _, c := range []struct {
		name   string
		caller auth.Principal
		agent  *inventory.Agent
		action string
		kind   inventory.RefusalKind
	}{
		{"a service account activates", operatorBot, ready, "activate", inventory.Forbidden},
		{"a service account retires", operatorBot, ready, "retire", inventory.Forbidden},
		{"a service account reinstates", advisoryBot, suspended, "reinstate", inventory.Forbidden},
		{"another owner activates", f.otto, ready, "activate", inventory.Forbidden},
		{"another owner suspends", f.otto, ready, "suspend", inventory.Forbidden},
		{"another owner retires", f.otto, ready, "retire", inventory.Forbidden},
		{"the advisory committee activates", f.alex, ready, "activate", inventory.Forbidden},
		{"the owner reinstates", f.olivia, suspended, "reinstate", inventory.Forbidden},
		{"a break-glass session suspends", breakglass, ready, "suspend", inventory.Forbidden},
		{"a token without the scope activates", viewer, ready, "activate", inventory.Forbidden},
		{"a user, who sees only active agents, suspends", f.uma, ready, "suspend", inventory.NotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.act(c.caller, c.agent, c.action, "A comment.")
			refused(t, err, c.kind)
		})
	}
	if a, err := f.act(viewer, ready, "suspend", "A token with the scope."); err != nil || a.LifecycleState != "suspended" {
		t.Fatalf("got %+v, %v", a, err)
	}
	if a, err := f.act(advisoryBot, f.inState(t, "invoice-reader", "validated"), "suspend", "Automated check."); err != nil || a.LifecycleState != "suspended" {
		t.Fatalf("a service account suspends: %+v, %v", a, err)
	}
}

// The actions of an agent say what refuses each one to the caller: the
// permission, separation of duties or the guards that do not hold, but never
// the comment, which only the request brings.
func TestTheActionsSayWhatRefusesThem(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	proposed := f.submitted(t, "invoice-triage")
	suspended := f.inState(t, "invoice-sorter", "suspended from ready")
	f.policies.set(suspended.ID, false)
	bot := f.serviceAccount(t, "operator")
	for _, c := range []struct {
		caller auth.Principal
		agent  *inventory.Agent
		want   string
	}{
		{f.olivia, proposed, "proposed [{withdraw T3 false []} {request_changes T4 true [permission not_owner_or_creator]} " +
			"{reject T5 true [permission not_owner_or_creator]} {validate T6 true [permission not_owner_or_creator]} {retire T14 true []}]"},
		{f.alex, proposed, "proposed [{withdraw T3 false [permission]} {request_changes T4 true []} " +
			"{reject T5 true []} {validate T6 true []} {retire T14 true []}]"},
		{f.alex, suspended, "suspended [{reinstate T13 true [previous_state_invariants_hold]} {retire T14 true []}]"},
		{bot, suspended, "suspended [{reinstate T13 true [permission previous_state_invariants_hold]} {retire T14 true [permission]}]"},
	} {
		state, actions, err := f.inv.Actions(ctx, c.caller, c.agent.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(state, " ", actions); got != c.want {
			t.Errorf("%s: got %s, want %s", c.caller.Name, got, c.want)
		}
	}
	_, _, err := f.inv.Actions(ctx, f.uma, proposed.ID)
	refused(t, err, inventory.NotFound)
}

// A transition locks its agent's governance state before it reads the run
// state: a halt under way either commits first and refuses the activation,
// or waits for it, so that an activation never puts into service an agent
// whose halt it did not see (the design of the halt path, section 2).
func TestAnActivationSeesAHaltThatCommitsWhileItWaits(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "ready")
	proceed, halt := f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE whitetower.governance_state SET run_state = 'halted', agent_halt_ids = ARRAY[gen_random_uuid()],
				state_version = whitetower.next_governance_version() WHERE agent_id = $1`, a.ID)
			return err
		},
		func(context.Context, *db.Tx) error { return nil })
	activated := make(chan error, 1)
	go func() {
		_, err := f.act(f.olivia, a, "activate", "")
		activated <- err
	}()
	f.awaitLockWaits(t, 1) // the activation waits for the agent's state
	proceed()
	if err := <-halt; err != nil {
		t.Fatal(err)
	}
	refusedBy(t, <-activated, "not_halted")
}
