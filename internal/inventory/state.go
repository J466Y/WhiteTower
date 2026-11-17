package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/govstate"
	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// StateVersions numbers the changes of the governance state that enforcement
// points watch (ADR-0005), in one total order. internal/govstate implements
// it with the version counter, whose lock orders the changes as they commit,
// and announces each change to the other replicas once it commits (the
// design of the halt path, in plan P1-08's progress notes, sections 2 and 3).
type StateVersions interface {
	// Next returns the version of the change that tx makes, the same for
	// every call in tx. A writer calls it once its checks pass and it holds
	// every row lock it needs: the version counter stays locked until tx
	// ends, and the writer waits for no lock afterwards.
	Next(ctx context.Context, tx *db.Tx) (int64, error)
}

// SelectorHalts gives the active selector halts that an agent matches, which
// every write of its governance state adds to it, so that an agent that
// comes to match a selector halt takes it (the design of the halt path,
// section 8). Plan P1-08 implements it.
type SelectorHalts interface {
	// Matching returns the IDs of the active selector halts that an agent
	// with these attributes matches, as tx sees them. A writer asks it once
	// it holds the version counter, which every selector halt and its
	// release take too, so that what it answers holds until tx commits; it
	// waits for no lock.
	Matching(ctx context.Context, tx *db.Tx, attrs govstate.Attributes) ([]uuid.UUID, error)
}

// NoSelectorHalts answers that no selector halt is active, until plan P1-08
// brings them.
type NoSelectorHalts struct{}

// Matching implements SelectorHalts.
func (NoSelectorHalts) Matching(context.Context, *db.Tx, govstate.Attributes) ([]uuid.UUID, error) {
	return nil, nil
}

// shareSelectorHaltsLock takes the selector halts' advisory lock in its
// shared form, first in a transaction that creates an agent or changes its
// labels or its risk tier: a selector halt takes it exclusively, first in
// its own, so that the two take turns. At read committed they would
// otherwise miss each other: the halt would not see the new agent or its new
// labels, and the writer would not see the halt (the design of the halt
// path, section 8). Taken first, it is never waited for while a row is held.
func shareSelectorHaltsLock(ctx context.Context, q *inventorydb.Queries) error {
	if err := q.ShareSelectorHaltsLock(ctx, govstate.SelectorHaltsLock); err != nil {
		return fmt.Errorf("taking the selector halts' lock: %w", err)
	}
	return nil
}

// publishState writes again what enforcement points know of an agent, at the
// version of tx, which it returns. It locks the agent's record before it
// takes the version, so that a writer that holds the version counter never
// waits for a record that another writer locked first; the caller has locked
// the agent's row before.
func (inv *Inventory) publishState(ctx context.Context, tx *db.Tx, a *Agent, now time.Time) (int64, error) {
	if err := lockState(ctx, inventorydb.New(tx), a.ID); err != nil {
		return 0, err
	}
	return inv.putState(ctx, tx, a, now)
}

// lockState locks the agent's governance state until the transaction ends.
// Every agent has its record from T1, so a missing record fails the change.
func lockState(ctx context.Context, q *inventorydb.Queries, agentID uuid.UUID) error {
	if _, err := q.LockGovernanceState(ctx, agentID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("agent %s has no governance state", agentID)
		}
		return fmt.Errorf("locking the agent's governance state: %w", err)
	}
	return nil
}

// putState writes what enforcement points know of the agent, at the version
// of tx, which it returns: T1 creates the record, and publishState writes it
// again. Its lease comes from the setting killswitch.lease_ttl_seconds, by
// risk tier (NFR-05), and it gains the active selector halts that the agent
// matches.
func (inv *Inventory) putState(ctx context.Context, tx *db.Tx, a *Agent, now time.Time) (int64, error) {
	q := inventorydb.New(tx)
	var leases map[string]int32
	if err := setting(ctx, q, "killswitch.lease_ttl_seconds", &leases); err != nil {
		return 0, err
	}
	lease, ok := leases[a.RiskTier]
	if !ok {
		return 0, fmt.Errorf("the setting killswitch.lease_ttl_seconds has no lease for the risk tier %s", a.RiskTier)
	}
	seen := govstate.Attributes{
		Slug:           a.Slug,
		Kind:           a.Kind,
		RiskTier:       a.RiskTier,
		DataCategories: a.DataCategories,
		Labels:         a.Labels,
		OwnerID:        a.PrimaryOwner.ID,
	}
	attrs, err := json.Marshal(seen)
	if err != nil {
		return 0, fmt.Errorf("encoding the agent's attributes: %w", err)
	}
	version, err := inv.versions.Next(ctx, tx)
	if err != nil {
		return 0, err
	}
	halts, err := inv.halts.Matching(ctx, tx, seen)
	if err != nil {
		return 0, fmt.Errorf("reading the selector halts that the agent matches: %w", err)
	}
	if halts == nil {
		halts = []uuid.UUID{} // the state holds an array of halts, never NULL
	}
	if err := q.PutGovernanceState(ctx, inventorydb.PutGovernanceStateParams{
		AgentID:         a.ID,
		LifecycleState:  a.LifecycleState,
		SelectorHaltIds: halts,
		LeaseTtlSeconds: lease,
		HaltMode:        a.HaltMode,
		Attributes:      attrs,
		StateVersion:    version,
		UpdatedAt:       now,
	}); err != nil {
		return 0, fmt.Errorf("writing the agent's governance state: %w", err)
	}
	return version, nil
}
