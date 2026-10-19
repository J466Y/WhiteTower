# P1-04: Inventory and lifecycle

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L |
| **Depends on** | P1-03 (and the P1-02 writer) |
| **Unblocks** | P1-05, P1-06, P1-08, P1-10.2, P1-16 (steps 1 to 4) |
| **Requirements** | INV-01 to INV-10, API-01 to API-03; backend of UI-02 (except its MCP and tools, which P1-16 serves), UI-03 and UI-09; the review's part of CAT-09 |
| **Decisions** | ADR-0005, [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) (section 10) |

## Goal

The registry of every agent, in-house or third-party, each with an accountable owner and a use case, moving through a lifecycle whose rules are enforced by the system. Periodic reviews come due, and agents whose owner leaves or whose review lapses are suspended automatically.

## Scope

**In:** agents, ownership, use cases, the lifecycle engine, reviews, the lifecycle guard job, coverage levels, search and export, the inbox and notifications, bulk import.

**Out:** credentials (P1-05); policies (P1-06; this plan defines the interface it uses to check "approved agent-specific policy"); halts (P1-08); the agents' MCP servers, tools and models: the catalog, enablement and declared tooling (P1-16; this plan defines the interface its reviews use to list an agent's enabled tooling and when each entry was last used); screens (P1-10.2).

## Deliverables

- `internal/inventory` with its OpenAPI operations.
- The lifecycle engine, generated or driven from the machine-readable table of P0-02.
- The lifecycle guard job.
- Property tests of the state machine.

## Steps

### 1. API first

Write the OpenAPI operations for agents, ownership, use cases, transitions, reviews (with the unused tooling of step 6), instances (read-only here), the inbox and export. Review them with whoever builds P1-10.2 before implementing.

**Done when:** the operations are merged, the generated clients compile, and the console side has agreed to them.

### 2. Agents

- Create a proposal (the caller becomes the owner and needs the owner role), read, and update metadata with ETag and If-Match.
- Validate the mandatory fields of INV-01, and manage labels.
- Third-party agents without runtime integration (INV-07) are registered with `kind=third_party` and coverage C0. Their owners and operators can declare their tooling in the catalog (CAT-08, P1-16); nothing enforces it.

**Done when:** create, read and update pass validation and permission tests.

### 3. Ownership

- One primary owner and any number of delegates, with history.
- Operators and the advisory committee can reassign ownership directly. A transfer started by the owner needs the new owner to accept it.
- The new owner must be an active principal. The invariant "exactly one primary owner" is enforced by the database.

**Done when:** every path of a transfer is tested, including acceptance by the new owner and an inactive target.

### 4. Use cases

- Owners create and edit use cases. The advisory committee validates or rejects them, or requests changes, never on their own proposals.
- A use case records its conditions and notes, and can justify several agents.

**Done when:** use case transitions are tested with separation of duties.

### 5. Lifecycle engine (subplan candidate)

- A single endpoint, `POST /api/v1/agents/{id}/transitions` with `{action, comment}`, driven by the P0-02 table.
- **Guards:** roles and separation of duties; the `active` invariant (active owner, validated use case, approved agent-specific policy through an interface that P1-06 implements, stubbed until then); a declared harness.
- **Side effects:** audit events, a governance state version bump (through an interface that P1-07 implements), notifications.
- **Suspension** remembers the previous state for reinstatement.
- **Tooling.** Enabling the agent's MCP servers, tools and models (P1-16) is part of "policy and harness assignment", between `validated` and `ready` (RFC-0002, section 10): while the agent is `validated`, its enforcement point runs with non-production credentials and reports the agent's tooling, and the owner requests enabling it. It is not a guard of T7 or T9: agents without an enforcement point (C0 and C1) have nothing to enable and must still be able to become active (INV-07), and an agent with nothing enabled is denied every tool and model call anyway.

**Done when:** property tests run at least 10,000 random sequences of transitions and never violate an invariant.

### 6. Reviews

- A review is scheduled at activation, with a due date set by the risk tier.
- Reminders go out 30, 7 and 1 days before (configurable).
- Completing a review records the owner's attestation: the agent is still needed, the owner is still right, the data categories are unchanged or updated, the policy is still adequate, and the enabled tooling is still needed.
- The review lists, as candidates to disable (CAT-09), the enabled tooling that the agent has not used within `lifecycle.review_unused_tooling_days` (90 days by default). The list comes through an interface defined here, which P1-16 implements from `agent_tooling.last_used_at`; it is empty until P1-16 lands. Disabling stays P1-16's action, and the attestation records which of these entries the owner keeps.
- High and critical risk agents also need advisory sign-off.

**Done when:** reviews can be scheduled, reminded and completed, with sign-off where required, and list the enabled tooling unused within the period (tests with a fake clock).

### 7. Lifecycle guard job

A leader-elected job that is idempotent and audits every action with its reason. It:

- suspends agents whose owner became inactive (from P1-03 events and a periodic sweep), and notifies advisory and operators;
- suspends agents whose review is overdue beyond the grace period;
- sends the review reminders.

**Done when:** deactivating an owner or letting a review lapse suspends the agent within one job interval (fake clock tests and an end-to-end test).

### 8. Coverage levels (Should)

Compute C0 to C3 per agent:

- **C1:** an active credential used recently.
- **C2:** an instance with an active EP and decision events within the period.
- **C3:** a confirmed halt or drill within the period, with data from P1-08.

Compute on read, or keep a table refreshed by a job if reads get expensive. Other domains read the level through the same function: P1-16 accepts declared tooling only for agents below C2 (CAT-08).

**Done when:** each level is reached and lost in tests.

### 9. Search, filter and export (Should)

- Filters on state, owner, risk tier, environment, coverage and labels.
- Text search on name and description (PostgreSQL trigram or full-text).
- Streamed CSV and JSON export that respects permissions.

**Done when:** filters and export are covered by tests with a few thousand agents.

### 10. Inbox and notifications (Should)

An inbox per principal for pending approvals and reviews due, at `/api/v1/inbox` (UI-09). Optionally, email through SMTP (Could) and outgoing webhooks (API-05, Could). Item kinds are open to later plans: P1-16 adds catalog entries and definitions waiting for review, requests to enable tooling and requests to unblock, with the migration of its pull request 2 (its step 3), which widens the check on `inbox_items.kind`.

**Done when:** each pending item appears in the right inboxes and disappears when handled.

### 11. Bulk import (Could)

A YAML format for agents (with references to use cases and owners by email), a dry-run mode, and idempotent upserts keyed on the slug. Every import is audited.

**Done when:** importing the same file twice changes nothing the second time.

### 12. Tests

- API tests per endpoint, including the permission negatives.
- Property tests of the state machine.
- Job tests with a fake clock.
- Separation-of-duties tests.
- Export tests.
- Reviews that list unused enabled tooling, against a stub of P1-16's interface (fake clock).

**Done when:** all run in CI.

## Acceptance criteria

- Every transition of the lifecycle specification is implemented with its guards, and the property tests never find a violated invariant.
- Automatic suspension happens within one job interval after an owner is deactivated or a review lapses past its grace period.
- A third-party agent can be registered at coverage C0 and appears in the inventory.
- The OpenAPI document is updated, the generated clients compile, and the console side has agreed to the API.
- A review lists the enabled tooling that the agent has not used within `lifecycle.review_unused_tooling_days`, through the interface P1-16 implements (CAT-09).
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-04-inventory-and-lifecycle) pass: ST-23 and ST-24.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Lifecycle rules too rigid for the pilot organization | Intervals and grace periods are configurable; the pilot feeds changes back through the requirements |
| Circular dependency with P1-06 (activation needs an approved policy) | Interface defined here, stubbed until P1-06 lands |
| Circular dependency with P1-16 (reviews list unused tooling; P1-16 needs agents and their coverage levels) | Interfaces defined here, stubbed until P1-16 lands, as for P1-06 |
| Notification fatigue | Reminders are configurable, and the inbox groups items |

## Notes for implementers

- Generate the transition guards and the lifecycle documentation from the same table, so they never diverge.
- Treat "system" as an explicit actor in audit events for everything the guard job does.
- The attestation is a JSON object (`reviews.attestation`), so recording the tooling the owner keeps needs no migration.
- Keep the text search simple (trigram); a search engine is not justified at MVP scale.
