package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/govstate"
	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// haltsOf returns the halts that the agent's governance state carries, and
// its run state.
func (f *fixture) haltsOf(t *testing.T, agent uuid.UUID) ([]uuid.UUID, string) {
	t.Helper()
	var ids []uuid.UUID
	var run string
	if err := f.pool.QueryRow(context.Background(),
		`SELECT agent_halt_ids, run_state FROM whitetower.governance_state WHERE agent_id = $1`, agent).Scan(&ids, &run); err != nil {
		t.Fatal(err)
	}
	return ids, run
}

// Every write of an agent's governance state adds the active selector halts
// that the agent matches, so that an agent created, or given the labels, of
// a selector halt under way takes it. No write takes a halt away: only its
// release does. A transition that White Tower takes changes no attribute,
// and adds none (the design of the halt path, section 8).
func TestEveryWriteOfTheStateAddsTheSelectorHaltsTheAgentMatches(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	finance := f.halts.issue("team=finance")
	a := f.inState(t, "invoice-triage", "validated") // labeled team=finance
	if ids, run := f.haltsOf(t, a.ID); fmt.Sprint(ids) != fmt.Sprint([]uuid.UUID{finance}) || run != "halted" || !a.Halted {
		t.Fatalf("a new agent's halts %v, %s", ids, run)
	}

	later := f.halts.issue("team=finance")
	if !f.system(t, a.ID, inventory.Cause{Action: "mark_ready"}) {
		t.Fatal("the agent did not become ready")
	}
	if ids, _ := f.haltsOf(t, a.ID); fmt.Sprint(ids) != fmt.Sprint([]uuid.UUID{finance}) {
		t.Errorf("after T7, halts %v", ids)
	}

	hr := map[string]string{"team": "hr"}
	edited, err := f.inv.Edit(ctx, f.olivia, a.ID, f.get(t, a.ID).Version, inventory.AgentChanges{Labels: &hr})
	if err != nil {
		t.Fatal(err)
	}
	if ids, _ := f.haltsOf(t, a.ID); fmt.Sprint(ids) != fmt.Sprint([]uuid.UUID{finance}) {
		t.Errorf("after the labels changed, halts %v: only a release removes a halt", ids)
	}
	people := f.halts.issue("team=hr")
	block := "block"
	if _, err := f.inv.Edit(ctx, f.olivia, a.ID, edited.Version, inventory.AgentChanges{HaltMode: &block}); err != nil {
		t.Fatal(err)
	}
	if ids, _ := f.haltsOf(t, a.ID); fmt.Sprint(ids) != fmt.Sprint([]uuid.UUID{finance, people}) {
		t.Errorf("after the halt mode changed, halts %v, want %v and not %v", ids, []uuid.UUID{finance, people}, later)
	}
}

// advisoryWaits counts the sessions of the test's database that wait for an
// advisory lock.
func (f *fixture) advisoryWaits(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
		WHERE datname = current_database() AND wait_event_type = 'Lock' AND wait_event = 'advisory'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A proposal, and an edit that names the labels or the risk tier, take the
// selector halts' lock in its shared form first, so that a selector halt
// under way, which holds it exclusively, and they take turns: neither misses
// the other at read committed. While they wait, they hold no lock of their
// agent, which the selector halt may lock next. An edit of anything else
// waits for no selector halt (the design of the halt path, section 8).
func TestWritersOfWhatSelectorHaltsMatchTakeTurnsWithThem(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := f.propose(t, "invoice-triage")
	uc := f.useCase(t, f.olivia)
	selector := func() (proceed func(), result <-chan error) {
		return f.held(t,
			func(ctx context.Context, tx *db.Tx) error {
				_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, govstate.SelectorHaltsLock)
				return err
			},
			func(context.Context, *db.Tx) error { return nil })
	}

	proceed, halt := selector()
	name := "Invoice reader"
	if _, err := f.inv.Edit(ctx, f.olivia, a.ID, a.Version, inventory.AgentChanges{Name: &name}); err != nil {
		t.Fatalf("an edit of the name: %v", err)
	}
	proceed()
	if err := <-halt; err != nil {
		t.Fatal(err)
	}
	hr, critical := map[string]string{"team": "hr"}, "critical"
	for _, c := range []struct {
		name  string
		write func(version int64) error
	}{
		{"a proposal", func(int64) error {
			_, err := f.inv.Propose(ctx, f.olivia, proposal("invoice-reader", uc.ID))
			return err
		}},
		{"an edit of the labels", func(version int64) error {
			_, err := f.inv.Edit(ctx, f.olivia, a.ID, version, inventory.AgentChanges{Labels: &hr})
			return err
		}},
		{"an edit of the risk tier", func(version int64) error {
			_, err := f.inv.Edit(ctx, f.olivia, a.ID, version, inventory.AgentChanges{RiskTier: &critical})
			return err
		}},
	} {
		proceed, halt := selector()
		done := make(chan error, 1)
		version := f.get(t, a.ID).Version
		go func() { done <- c.write(version) }()
		for deadline := time.Now().Add(10 * time.Second); f.advisoryWaits(t) < 1; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s never waited for the selector halts' lock", c.name)
			}
		}
		if err := f.pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `SELECT 1 FROM whitetower.agents a JOIN whitetower.governance_state g ON g.agent_id = a.id
				WHERE a.id = $1 FOR UPDATE NOWAIT`, a.ID)
			return err
		}); err != nil {
			t.Fatalf("%s, which waits for the selector halts' lock, holds the agent: %v", c.name, err)
		}
		proceed()
		if err := <-halt; err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// held runs a transaction in the background: it returns once the
// transaction has run before, and the transaction runs after, with a short
// lock timeout, once the test calls proceed. result gives the transaction's
// outcome.
func (f *fixture) held(t *testing.T, before, after func(ctx context.Context, tx *db.Tx) error) (proceed func(), result <-chan error) {
	t.Helper()
	ready, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	proceed = func() { once.Do(func() { close(release) }) }
	t.Cleanup(proceed)
	go func() {
		done <- f.pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			if err := before(ctx, tx); err != nil {
				return err
			}
			close(ready)
			<-release
			// Well within the second after which PostgreSQL would break a
			// deadlock between the two transactions.
			if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '200ms'"); err != nil {
				return err
			}
			return after(ctx, tx)
		})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	return proceed, done
}

// reassign reassigns the agent to Otto in the background, and returns its
// result.
func (f *fixture) reassign(a *inventory.Agent) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := f.inv.Reassign(context.Background(), f.omar, a.ID, a.Version, uuid.MustParse(f.otto.ID), "reorganization")
		done <- err
	}()
	return done
}

// A writer holds its agent's row with FOR NO KEY UPDATE, never FOR UPDATE,
// while it waits for the version counter: the transaction that holds the
// counter may insert rows that name the agent, such as a halt, whose foreign
// keys take key-share locks, which only FOR UPDATE blocks. The two would
// otherwise wait for each other until PostgreSQL broke the deadlock, a second
// later, and every halt queued on the counter with them (the design of the
// halt path, section 2).
func TestAWriterWaitingForTheHeadNeverBlocksItsHolder(t *testing.T) {
	f := setup(t)
	a := f.propose(t, "invoice-triage")
	var version int64
	proceed, halt := f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			return tx.QueryRow(ctx, "SELECT whitetower.next_governance_version()").Scan(&version)
		},
		func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO whitetower.halts (id, scope, agent_id, reason, issued_by_type, state_version)
				VALUES ($1, 'agent', $2, 'suspected exfiltration', 'system', $3)`, uuid.Must(uuid.NewV7()), a.ID, version)
			return err
		})
	reassigned := f.reassign(a)
	f.awaitLockWaits(t, 1) // the reassignment holds the agent's row, and waits for the head
	proceed()
	if err := <-halt; err != nil {
		t.Fatalf("the halt waited for the agent's row: %v", err)
	}
	if err := <-reassigned; err != nil {
		t.Fatal(err)
	}
}

// A writer locks its agent's governance state before it takes the version
// counter, so that it never holds the counter while it waits for a row: a
// selector halt, which locks the state of the agents it covers and then takes
// the counter, finds the counter free (the design of the halt path, section
// 2).
func TestAWriterLocksTheStateOfItsAgentBeforeTakingTheHead(t *testing.T) {
	f := setup(t)
	a := f.propose(t, "invoice-triage")
	proceed, halt := f.held(t,
		func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, "SELECT 1 FROM whitetower.governance_state WHERE agent_id = $1 FOR NO KEY UPDATE", a.ID)
			return err
		},
		func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE whitetower.governance_state SET state_version = whitetower.next_governance_version()
				WHERE agent_id = $1`, a.ID)
			return err
		})
	reassigned := f.reassign(a)
	f.awaitLockWaits(t, 1) // the reassignment waits for the agent's state
	before := f.stateVersion(t, a.ID)
	proceed()
	if err := <-halt; err != nil {
		t.Fatalf("the halt waited for the head: %v", err)
	}
	if err := <-reassigned; err != nil {
		t.Fatal(err)
	}
	if v := f.stateVersion(t, a.ID); v != before+2 {
		t.Errorf("state version %d, want %d: the halt's, then the reassignment's", v, before+2)
	}
}

// Every agent has its governance state from T1, and no later change creates
// one: a change of what enforcement points see of an agent that has none, as
// the agents of the evaluation seed once had none, fails and changes nothing
// (the design of the halt path, sections 2 and 10).
func TestAChangeOfAnAgentWithoutItsGovernanceStateFails(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	uc := f.useCase(t, f.olivia)
	id, olivia := uuid.Must(uuid.NewV7()), uuid.MustParse(f.olivia.ID)
	f.set(t, `INSERT INTO whitetower.agents (id, slug, name, description, kind, framework, deployment_location,
		environments, risk_tier, data_categories, use_case_id, created_by)
		VALUES ($1, 'invoice-triage', 'Invoice triage', 'Sorts invoices.', 'in_house', 'langgraph', 'eu-west-1',
		'{production}', 'high', '{financial_data}', $2, $3)`, id, uc.ID, olivia)
	f.set(t, `INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by)
		VALUES ($1, $2, $3, 'primary', $3)`, uuid.Must(uuid.NewV7()), id, olivia)

	critical := "critical"
	_, err := f.inv.Edit(ctx, f.olivia, id, 1, inventory.AgentChanges{RiskTier: &critical})
	var r *inventory.Refusal
	if err == nil || errors.As(err, &r) {
		t.Fatalf("got %v, want an internal error", err)
	}
	if got, err := f.inv.Get(ctx, f.alex, id); err != nil || got.RiskTier != "high" || got.Version != 1 {
		t.Fatalf("got %+v, %v: want the agent as it was", got, err)
	}
}
