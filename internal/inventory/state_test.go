package inventory_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

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
