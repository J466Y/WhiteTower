package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/inventory/inventorydb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// StateVersions numbers the changes of the governance state that enforcement
// points watch (ADR-0005), in one total order. Plan P1-07 implements it with
// the lock that orders the changes as they commit and the notification that
// tells the other replicas; until then, SequenceVersions numbers them.
type StateVersions interface {
	// Next returns the version of the change that tx makes. A writer calls
	// it once its checks pass, as late in tx as it can: P1-07's
	// implementation holds a lock until tx ends.
	Next(ctx context.Context, tx *db.Tx) (int64, error)
}

// SequenceVersions takes the versions from the global sequence, without the
// lock and the notification that plan P1-07 adds.
type SequenceVersions struct{}

// Next returns the next number of the sequence.
func (SequenceVersions) Next(ctx context.Context, tx *db.Tx) (int64, error) {
	v, err := inventorydb.New(tx).NextStateVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("taking a governance state version: %w", err)
	}
	return v, nil
}

// attributes are what policies may use of an agent (module contracts,
// section 6.2). They name a person only by the owner's pseudonymous ID.
type attributes struct {
	Slug           string            `json:"slug"`
	Kind           string            `json:"kind"`
	RiskTier       string            `json:"risk_tier"`
	DataCategories []string          `json:"data_categories"`
	Labels         map[string]string `json:"labels"`
	OwnerID        uuid.UUID         `json:"owner_id"`
}

// publishState writes what enforcement points know of the agent, at a new
// governance state version, which it returns. Its lease comes from the
// setting killswitch.lease_ttl_seconds, by risk tier (NFR-05).
func (inv *Inventory) publishState(ctx context.Context, tx *db.Tx, a *Agent, now time.Time) (int64, error) {
	q := inventorydb.New(tx)
	var leases map[string]int32
	if err := setting(ctx, q, "killswitch.lease_ttl_seconds", &leases); err != nil {
		return 0, err
	}
	lease, ok := leases[a.RiskTier]
	if !ok {
		return 0, fmt.Errorf("the setting killswitch.lease_ttl_seconds has no lease for the risk tier %s", a.RiskTier)
	}
	attrs, err := json.Marshal(attributes{
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
