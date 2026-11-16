package inventory

import (
	"context"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// AgentPolicies tells the lifecycle whether an agent has an agent-specific
// policy with an active version, which the guard agent_policy_active reads
// (POL-04; docs/architecture/lifecycle.md, section 4). Plan P1-06 implements
// it.
type AgentPolicies interface {
	// Active reports whether the agent has an active agent-specific policy,
	// as tx sees it. A transition asks it under the agent's row lock, and
	// the list of the actions open to a caller without a lock.
	Active(ctx context.Context, tx *db.Tx, agentID uuid.UUID) (bool, error)
}

// NoAgentPolicies answers that no agent has an active agent-specific policy,
// until plan P1-06 brings policies. POL-04 then holds: no agent becomes
// active, and none is reinstated to ready or active (the review's decision of
// 2026-11-12, in plan P1-04's progress notes).
type NoAgentPolicies struct{}

// Active implements AgentPolicies.
func (NoAgentPolicies) Active(context.Context, *db.Tx, uuid.UUID) (bool, error) { return false, nil }
