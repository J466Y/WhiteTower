package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// publishState writes again what enforcement points know of an agent, at the
// version of tx, which it returns. It locks the agent's record before it
// takes the version, so that a writer that holds the version counter never
// waits for a record that another writer locked first; the caller has locked
// the agent's row before. Every agent has its record from T1, so a missing
// record fails the change.
func (inv *Inventory) publishState(ctx context.Context, tx *db.Tx, a *Agent, now time.Time) (int64, error) {
	if _, err := inventorydb.New(tx).LockGovernanceState(ctx, a.ID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("agent %s has no governance state", a.ID)
		}
		return 0, fmt.Errorf("locking the agent's governance state: %w", err)
	}
	return inv.putState(ctx, tx, a, now)
}

// putState writes what enforcement points know of the agent, at the version
// of tx, which it returns: T1 creates the record, and publishState writes it
// again. Its lease comes from the setting killswitch.lease_ttl_seconds, by
// risk tier (NFR-05).
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
	attrs, err := json.Marshal(govstate.Attributes{
		Slug:           a.Slug,
		Kind:           a.Kind,
		RiskTier:       a.RiskTier,
		DataCategories: a.DataCategories,
		Labels:         a.Labels,
		OwnerID:        a.PrimaryOwner.ID,
	})
	if err != nil {
		return 0, fmt.Errorf("encoding the agent's attributes: %w", err)
	}
	version, err := inv.versions.Next(ctx, tx)
	if err != nil {
		return 0, err
	}
	if err := q.PutGovernanceState(ctx, inventorydb.PutGovernanceStateParams{
		AgentID:         a.ID,
		LifecycleState:  a.LifecycleState,
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
