// Package govstate is the governance state that enforcement points watch
// (ADR-0005; plan P1-07.1, step 5): the versions that order its changes, the
// attributes of each agent that policies see, and the lock that selector
// halts share with the writers of what they match. It follows the design of
// the halt path, in plan P1-08's progress notes.
package govstate

import "github.com/google/uuid"

// Attributes are what policies may use of an agent (module contracts, section
// 6.2), as the attributes column of the agent's governance state holds them:
// the inventory writes them, and the hub reads them. They name a person only
// by the owner's pseudonymous ID.
type Attributes struct {
	Slug           string            `json:"slug"`
	Kind           string            `json:"kind"`
	RiskTier       string            `json:"risk_tier"`
	DataCategories []string          `json:"data_categories"`
	Labels         map[string]string `json:"labels"`
	OwnerID        uuid.UUID         `json:"owner_id"`
}

// SelectorHaltsLock is the key of the transaction-level advisory lock that
// selector halts share with the writers of what they match (the design of
// the halt path, section 8). A selector halt and its release take it
// exclusively, first in their transactions; every writer that creates an
// agent, or changes its labels or its risk tier, takes it shared, first in
// its own. At read committed they would otherwise miss each other: the halt
// would not see the new labels or the new agent, and the writer would not see
// the halt. It is "WTselhlt" in ASCII, a key of the one-key form apart from
// the migrations' lock.
const SelectorHaltsLock int64 = 0x575473656c686c74
