package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/govstate"
	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// issueHalt does in tx what an agent halt of plan P1-08 does before it
// applies T12: it locks the agent's row and its governance state, takes the
// version, inserts the halt and adds it to the agent's state.
func issueHalt(ctx context.Context, tx *db.Tx, agentID uuid.UUID, drill bool) (uuid.UUID, error) {
	id := uuid.Must(uuid.NewV7())
	for _, sql := range []string{
		`SELECT 1 FROM whitetower.agents WHERE id = $1 FOR NO KEY UPDATE`,
		`SELECT 1 FROM whitetower.governance_state WHERE agent_id = $1 FOR NO KEY UPDATE`,
	} {
		if _, err := tx.Exec(ctx, sql, agentID); err != nil {
			return id, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO whitetower.halts (id, scope, agent_id, reason, drill, issued_by_type, state_version)
		VALUES ($1, 'agent', $2, 'suspected exfiltration', $3, 'system', whitetower.next_governance_version())`, id, agentID, drill); err != nil {
		return id, err
	}
	_, err := tx.Exec(ctx, `UPDATE whitetower.governance_state SET run_state = 'halted', agent_halt_ids = agent_halt_ids || $2::uuid,
		state_version = whitetower.next_governance_version() WHERE agent_id = $1`, agentID, id)
	return id, err
}

// halted issues an agent halt in a transaction of its own, applies T12 with
// it, and reports whether the agent moved.
func (f *fixture) halted(t *testing.T, id uuid.UUID, drill bool) bool {
	t.Helper()
	var moved bool
	if err := f.pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		halt, err := issueHalt(ctx, tx, id, drill)
		if err != nil {
			return err
		}
		moved, err = f.inv.SystemTransition(ctx, tx, id, inventory.Cause{Action: "halt_suspend", Halt: halt})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return moved
}

// lastTransition returns the newest transition of the agent's history, and
// the newest lifecycle event.
func (f *fixture) lastTransition(t *testing.T, id uuid.UUID) (inventory.TransitionRecord, event) {
	t.Helper()
	history, _, err := f.inv.Transitions(context.Background(), f.alex, id, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	changed := f.events(t, "whitetower.agent.lifecycle_changed.v1")
	return history[0], changed[len(changed)-1]
}

// An edit that declares a harness on a validated agent makes it ready, as
// White Tower, once it has an active agent-specific policy (T7). Under the
// stub of P1-06, no agent has one, and the agent stays validated.
func TestAnEditThatDeclaresAHarnessMakesAValidatedAgentReady(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a, err := f.act(f.alex, f.submitted(t, "invoice-triage"), "validate", "Fine.")
	if err != nil {
		t.Fatal(err)
	}
	harness := inventory.Harness{Description: "A container."}
	edited, err := f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{Harness: &harness})
	if err != nil || edited.LifecycleState != "validated" || edited.Version != a.Version+1 {
		t.Fatalf("without a policy: %+v, %v", edited, err)
	}

	f.policies.set(a.ID, true)
	harness.Description = "A container without network access."
	ready, err := f.inv.Edit(ctx, f.olivia, a.ID, edited.Version, inventory.AgentChanges{Harness: &harness})
	if err != nil {
		t.Fatal(err)
	}
	version := f.stateVersion(t, a.ID)
	if ready.LifecycleState != "ready" || ready.Version != edited.Version+2 || f.lifecycleState(t, a.ID) != "ready" {
		t.Errorf("state %s at version %d, governance state %s", ready.LifecycleState, ready.Version, f.lifecycleState(t, a.ID))
	}
	last, changed := f.lastTransition(t, a.ID)
	if last.Transition != "T7" || last.From != "validated" || last.Actor.Type != "system" || last.Actor.ID != nil || last.StateVersion != version {
		t.Errorf("history %+v", last)
	}
	if changed.data["transition"] != "T7" || changed.actorType != "system" || changed.actorID != "" || changed.data["state_version"] != float64(version) {
		t.Errorf("event %+v", changed)
	}
	// Enforcement points do not see the harness: T7's event carries the
	// version, the edit's does not.
	updated := f.events(t, "whitetower.agent.updated.v1")
	if data := updated[len(updated)-1].data; data["state_version"] != nil {
		t.Errorf("the edit's event %v", data)
	}
}

// White Tower takes a transition only from a state that it starts from, and
// only while its guards hold. Otherwise the agent stays as it is, and its
// caller's transaction goes on: nothing fails.
func TestWhiteTowerTakesATransitionOnlyWhileItsGuardsHold(t *testing.T) {
	f := setup(t)
	past := f.clk.Now().Add(-time.Second)
	for i, c := range []struct {
		name, state string
		cause       inventory.Cause
		spoil       func(a *inventory.Agent)
		want        string // the state it leaves the agent in, and the reason of a suspension
	}{
		{
			"T7 without a policy", "validated",
			inventory.Cause{Action: "mark_ready"},
			func(a *inventory.Agent) { f.policies.set(a.ID, false) }, "validated",
		},
		{"T7 of a suspended agent", "suspended from validated", inventory.Cause{Action: "mark_ready"}, nil, "suspended manual"},
		{"T8 with a policy and a harness", "ready", inventory.Cause{Action: "unmark_ready"}, nil, "ready"},
		{
			"T8 without a policy", "ready",
			inventory.Cause{Action: "unmark_ready"},
			func(a *inventory.Agent) { f.policies.set(a.ID, false) }, "validated",
		},
		{"T11 for an owner who is active", "active", inventory.Cause{Action: "auto_suspend", Reason: "owner_inactive"}, nil, "active"},
		{
			"T11 for an owner who left", "active",
			inventory.Cause{Action: "auto_suspend", Reason: "owner_inactive"},
			func(*inventory.Agent) { f.setStatus(t, f.olivia, "inactive") }, "suspended owner_inactive",
		},
		{
			"T11 for an overdue review, which is not", "ready",
			inventory.Cause{Action: "auto_suspend", Reason: "review_overdue"},
			func(*inventory.Agent) { f.setStatus(t, f.olivia, "inactive") }, "ready",
		},
		{
			"T11 for an overdue review", "ready",
			inventory.Cause{Action: "auto_suspend", Reason: "review_overdue"},
			func(a *inventory.Agent) { f.review(t, a.ID, &past) }, "suspended review_overdue",
		},
		{
			"T11 of a suspended agent", "suspended from active",
			inventory.Cause{Action: "auto_suspend", Reason: "owner_inactive"},
			func(*inventory.Agent) { f.setStatus(t, f.olivia, "inactive") }, "suspended manual",
		},
		{"T12 for a halt of another agent", "active", inventory.Cause{Action: "halt_suspend", Halt: uuid.Must(uuid.NewV7())}, nil, "active"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f.setStatus(t, f.olivia, "active")
			a := f.inState(t, fmt.Sprintf("agent-%d", i), c.state)
			if c.spoil != nil {
				c.spoil(a)
			}
			history := scalar[int](t, f, `SELECT count(*) FROM whitetower.lifecycle_transitions WHERE agent_id = $1`, a.ID)
			moved := f.system(t, a.ID, c.cause)
			got := f.get(t, a.ID)
			if got.Suspension != nil {
				got.LifecycleState += " " + got.Suspension.Reason
			}
			grew := scalar[int](t, f, `SELECT count(*) FROM whitetower.lifecycle_transitions WHERE agent_id = $1`, a.ID) - history
			if want := c.want != c.state && c.want != "suspended manual"; got.LifecycleState != c.want || moved != want ||
				got.Version != a.Version+int64(grew) || grew != map[bool]int{true: 1}[want] {
				t.Errorf("%s, moved %v, version %d after %d, %d transitions", got.LifecycleState, moved, got.Version, a.Version, grew)
			}
		})
	}
}

// A cause that names no transition that White Tower takes, or no reason of an
// automatic suspension, is a fault of its caller, whose transaction fails.
func TestACauseThatIsNotOneFailsItsCaller(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "active")
	for _, c := range []inventory.Cause{
		{Action: "suspend"},
		{Action: "create"},
		{Action: "auto_suspend", Reason: "manual"},
	} {
		err := f.pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			_, err := f.inv.SystemTransition(ctx, tx, a.ID, c)
			return err
		})
		var r *inventory.Refusal
		if err == nil || errors.As(err, &r) {
			t.Errorf("%+v: got %v, want an internal error", c, err)
		}
	}
}

// A halt suspends a validated, ready or active agent at its own version, with
// reason halt, and changes nothing else of its governance state: the lease,
// the attributes and the halt stay. An edit read before the halt fails, so
// it never writes over the suspension. A drill, and a halt of an agent in
// any other state, leave the agent as it is (T12; the design of the halt
// path, section 13, decision 1).
func TestAHaltSuspendsItsAgentAtTheHaltsVersion(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, from := range []string{"validated", "ready", "active"} {
		a := f.inState(t, "agent-"+from, from)
		var lease int32
		var attrs string
		read := `SELECT lease_ttl_seconds, attributes::text FROM whitetower.governance_state WHERE agent_id = $1`
		if err := f.pool.QueryRow(ctx, read, a.ID).Scan(&lease, &attrs); err != nil {
			t.Fatal(err)
		}
		if !f.halted(t, a.ID, false) {
			t.Fatalf("%s: the halt did not suspend the agent", from)
		}
		got := f.get(t, a.ID)
		version := f.stateVersion(t, a.ID)
		if s := got.Suspension; got.LifecycleState != "suspended" || s == nil || s.From != from || s.Reason != "halt" || got.Version != a.Version+1 || !got.Halted {
			t.Errorf("%s: state %s, suspension %+v, version %d, halted %v", from, got.LifecycleState, s, got.Version, got.Halted)
		}
		var leaseAfter int32
		var attrsAfter string
		if err := f.pool.QueryRow(ctx, read, a.ID).Scan(&leaseAfter, &attrsAfter); err != nil {
			t.Fatal(err)
		}
		halt := scalar[uuid.UUID](t, f, `SELECT id FROM whitetower.halts WHERE agent_id = $1`, a.ID)
		if f.lifecycleState(t, a.ID) != "suspended" || leaseAfter != lease || attrsAfter != attrs ||
			scalar[int64](t, f, `SELECT state_version FROM whitetower.halts WHERE id = $1`, halt) != version ||
			!scalar[bool](t, f, `SELECT agent_halt_ids = ARRAY[$2::uuid] FROM whitetower.governance_state WHERE agent_id = $1`, a.ID, halt) {
			t.Errorf("%s: governance state %s at %d, lease %d, attributes %s", from, f.lifecycleState(t, a.ID), version, leaseAfter, attrsAfter)
		}
		last, changed := f.lastTransition(t, a.ID)
		if last.Transition != "T12" || last.Reason != "halt" || last.Actor.Type != "system" || last.StateVersion != version ||
			changed.data["suspension_reason"] != "halt" || changed.data["state_version"] != float64(version) {
			t.Errorf("%s: history %+v, event %+v", from, last, changed)
		}
		name := "Invoice sorter"
		_, err := f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{Name: &name})
		refused(t, err, inventory.Stale)
	}
	for _, c := range []struct {
		name  string
		agent *inventory.Agent
		drill bool
	}{
		{"a drill", f.inState(t, "agent-drilled", "active"), true},
		{"a halt of a draft", f.propose(t, "agent-draft"), false},
	} {
		if f.halted(t, c.agent.ID, c.drill) {
			t.Errorf("%s suspended the agent", c.name)
		}
		if got := f.get(t, c.agent.ID); got.LifecycleState != c.agent.LifecycleState || got.Version != c.agent.Version {
			t.Errorf("%s: state %s at version %d", c.name, got.LifecycleState, got.Version)
		}
	}
}

// A halt that holds the version counter waits for nothing to apply T12: the
// entry point finds the agent's row and its governance state locked by the
// halt already, and takes no other lock and reads no setting, no review, no
// owner and no use case. A selector halt under way, which holds its lock,
// and a writer queued for the agent's row hold nothing back. Otherwise every
// halt queued on the counter would wait with it (the design of the halt
// path, sections 2 and 8).
func TestAHaltHoldingTheHeadWaitsForNothingToSuspendItsAgent(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "active")
	_, others := f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, govstate.SelectorHaltsLock); err != nil {
				return err
			}
			for _, sql := range []string{
				`SELECT 1 FROM whitetower.fleet_state FOR UPDATE`,
				`SELECT 1 FROM whitetower.principals WHERE id = '` + f.olivia.ID + `' FOR UPDATE`,
				// Even a plain read of these tables waits. The halt's rows
				// name agents and principals, whose tables their foreign
				// keys open, but none of these.
				`LOCK TABLE whitetower.settings, whitetower.reviews, whitetower.use_cases, whitetower.agent_owners
					IN ACCESS EXCLUSIVE MODE`,
			} {
				if _, err := tx.Exec(ctx, sql); err != nil {
					return err
				}
			}
			return nil
		},
		func(context.Context, *db.Tx) error { return nil })
	var id uuid.UUID
	var moved bool
	proceed, halt := f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '2s'"); err != nil {
				return err
			}
			var err error
			id, err = issueHalt(ctx, tx, a.ID, false)
			return err
		},
		func(ctx context.Context, tx *db.Tx) error {
			var err error
			moved, err = f.inv.SystemTransition(ctx, tx, a.ID, inventory.Cause{Action: "halt_suspend", Halt: id})
			return err
		})
	queued := make(chan error, 1)
	go func() {
		queued <- f.pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `SELECT 1 FROM whitetower.agents WHERE id = $1 FOR NO KEY UPDATE`, a.ID)
			return err
		})
	}()
	f.awaitLockWaits(t, 1) // the writer waits for the agent's row
	proceed()
	if err := <-halt; err != nil || !moved {
		t.Fatalf("the halt waited: moved %v, %v", moved, err)
	}
	if err := <-queued; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-others:
		t.Fatalf("the other locks were let go: %v", err)
	default:
	}
}

// The entry point locks the agent's governance state before it takes the
// version counter, so that it never holds the counter while it waits for a
// row: a selector halt, which locks the state of the agents it covers and
// then takes the counter, finds it free (the design of the halt path,
// section 2).
func TestWhiteTowerLocksTheStateOfItsAgentBeforeTakingTheHead(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "ready")
	f.policies.set(a.ID, false)
	proceed, selector := f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `SELECT 1 FROM whitetower.governance_state WHERE agent_id = $1 FOR NO KEY UPDATE`, a.ID)
			return err
		},
		func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE whitetower.governance_state SET state_version = whitetower.next_governance_version()
				WHERE agent_id = $1`, a.ID)
			return err
		})
	var moved bool
	unmarked := make(chan error, 1)
	go func() {
		unmarked <- f.pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			var err error
			moved, err = f.inv.SystemTransition(ctx, tx, a.ID, inventory.Cause{Action: "unmark_ready"})
			return err
		})
	}()
	f.awaitLockWaits(t, 1) // T8 waits for the agent's state
	proceed()
	if err := <-selector; err != nil {
		t.Fatalf("the selector halt waited for the head: %v", err)
	}
	if err := <-unmarked; err != nil || !moved || f.lifecycleState(t, a.ID) != "validated" {
		t.Fatalf("T8: moved %v, %v, governance state %s", moved, err, f.lifecycleState(t, a.ID))
	}
}

// Reinstatement checks the conditions that hold now, whatever White Tower
// suspended the agent for: once its owner is back, an agent suspended for
// that reason goes back into service (the lifecycle, section 6).
func TestAnAgentThatWhiteTowerSuspendedIsReinstatedByAPerson(t *testing.T) {
	f := setup(t)
	a := f.inState(t, "invoice-triage", "active")
	f.setStatus(t, f.olivia, "inactive")
	if !f.system(t, a.ID, inventory.Cause{Action: "auto_suspend", Reason: "owner_inactive"}) {
		t.Fatal("the agent of an owner who left was not suspended")
	}
	suspended := f.get(t, a.ID)
	_, err := f.act(f.alex, suspended, "reinstate", "Owner is back.")
	refusedBy(t, err, "owner_active")
	f.setStatus(t, f.olivia, "active")
	if back, err := f.act(f.alex, suspended, "reinstate", "Owner is back."); err != nil || back.LifecycleState != "active" {
		t.Fatalf("got %+v, %v", back, err)
	}
}
