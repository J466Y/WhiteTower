# P1-04: Inventory and lifecycle

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | In progress (3 of 8 pull requests) |
| **Size** | L |
| **Depends on** | P1-03 (and the P1-02 writer); the first pull request of P1-07.1 for pull requests 4 to 8 |
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
- **C3:** a halt or drill within the period for which the agent had at least one expected pair of instance and agent, each acknowledged within the maximum of its target (NFR-03 for an enforcement point, NFR-23 for a runtime-control module). It is read per agent through an interface that P1-08 implements ([design note](P1-08-kill-switch.md#progress-notes), section 7); until then, no agent reaches C3.

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

## Progress notes

The plan lands in eight pull requests. The first agrees on the whole API before anything is built (step 1), so that the console and the CLI can work against it; the second brings the agents and their API, which P1-06 and P1-16 wait for. Each pull request brings the tests of its steps (step 12).

| Pull request | Steps | Status |
| --- | --- | --- |
| 1. API | 1; the permission `agent.ownership.reassign` | Done |
| 2. Use cases and agents | 2, 4; the data categories; the ownership check that P1-16 reuses; each new agent's governance state, through P1-07's interface, stubbed | Done |
| 3. Ownership | 3; the inbox items of transfers | Done |
| 4. Lifecycle engine | 5, through P1-06's interface, stubbed; the property tests; ST-23; a token without the action's scope is refused (ST-19); `service_account` in `lifecycle_transitions.actor_type`; the entry point for the transitions White Tower makes, where T12 skips drills; the active selector halts in every write of the state record, through P1-08's interface, stubbed; the shared form of the selector halts' advisory lock, with the key of `internal/govstate`, taken first in T1 and `editAgent`; `state_version` in `whitetower.agent.updated.v1` when a change concerns what enforcement points see; after the first pull request of P1-07.1, and once the lifecycle and the requirements say that drills do not suspend ([design note](P1-08-kill-switch.md#progress-notes), section 13, decision 1) | Not started |
| 5. Reviews and the lifecycle guard job | 6, 7, through P1-16's interface, stubbed; the guard job suspends one agent per transaction | Not started |
| 6. Coverage, instances, search and export | 8, 9; ST-24, with cells that start after a `;` or with a tab or a carriage return; C3 through P1-08's interface, stubbed | Not started |
| 7. Inbox and notifications | 10 | Not started |
| 8. Bulk import | 11, with its operation; at most 100 agents per transaction, one import at a time, each transaction taking the shared form of the selector halts' advisory lock first | Not started |

### 2026-10-19: API (PR 1)

- `api/openapi/openapi.yaml` holds the 29 operations of the plan, under the tags `inventory` and `inbox`:

  | Resource | Operations |
  | --- | --- |
  | Agents | `listAgents`, `proposeAgent` (T1), `getAgent`, `editAgent`, `exportAgents`, `listDataCategories` |
  | Lifecycle | `getAgentActions`, `transitionAgent`, `listAgentTransitions` |
  | Owners | `listAgentOwners`, `reassignAgentOwner`, `addAgentDelegate`, `removeAgentDelegate`, `requestOwnershipTransfer`, `cancelOwnershipTransfer`, `acceptOwnershipTransfer`, `declineOwnershipTransfer` |
  | Use cases | `listUseCases`, `createUseCase`, `getUseCase`, `editUseCase`, `listUseCaseDecisions` |
  | Reviews | `listAgentReviews`, `listReviews`, `getReview`, `completeReview`, `signOffReview` |
  | Instances and the inbox | `listAgentInstances`, `listInboxItems` |

- The conventions of `docs/reference/api-errors.md` and `internal/api/rest/page.go`, written down as shared components:
  - lists are objects with a named array and `nextCursor`, and take `limit` (50 by default, 200 at most) and `cursor`;
  - agents, use cases and reviews return their `ETag`, and their changes need `If-Match`, transitions included. The header is declared optional, and the handler refuses a change without it with `precondition_required`: a required header would be refused before authentication, and `TestEveryOperationIsGuarded` expects 401 and 403. Delegates and ownership transfers act on rows of their own, guarded by their state (one pending transfer per agent), and take no `If-Match`, as `revokeToken` takes none; they change the agent's ETag;
  - the filters of INV-09 are shared by `listAgents` and `exportAgents`.
- The server answers every new operation with `not_implemented` (501) until the pull request of its step builds it (`internal/api/rest/inventory.go`). `TestAgreedOperationsAnswerNotImplementedUntilBuilt` lists the operations not built yet: each pull request removes the ones it builds.
- Two problem codes: `not_implemented` for those answers, and `conflict` (409) for the refusals that come from state, such as a guard that does not hold. P1-16 reuses `conflict`.
- Step 1 asks the console side to agree to the API. P1-10.2 has no owner yet, so the maintainer's review of this pull request stands for it; P1-10.2 can still ask for additive changes, which oasdiff accepts.
- Authorization (`internal/authz`):
  - Every operation maps to a permission. `TestEveryOperationHasAPermission` checks that no operation of the document lacks one, since the authorizer refuses an operation it does not know to everyone. The placeholders `activateAgent`, `suspendAgent`, `reinstateAgent`, `retireAgent` and `validateUsecase`, which `transitionAgent` replaces, are gone.
  - The new permission `agent.ownership.reassign` (advisory and operators, all), and its row in the permission matrix of the requirements: the maintainer's decision of 2026-10-19. ST-17 now checks 25 permissions, 175 pairs.
  - The actions that have no row in the matrix reuse the permissions that fit them: submitting and withdrawing a proposal need `agent.propose`, as the agent's primary owner or a delegate; owners create and edit use cases (`agent.propose`); delegates and transfers need `agent.metadata.edit`; accepting a transfer needs the owner role (`agent.propose`), declining it nothing more than `identity.me.read`; the inbox needs `identity.me.read`, and the export and the data categories `inventory.view`.
  - `transitionAgent` maps to `inventory.view`, and each action needs its own permission too. The lifecycle engine (step 5) checks it with `Authorize`, the action's permission as the operation and `ContextWithRelationship`, never with `AuthorizeResource` or `EffectiveGrant`, which ignore a token's scopes. An API token therefore needs both scopes.
  - `transitionAgent` and `declineOwnershipTransfer` change state under a permission that only reads, so the authorizer refuses them to break-glass sessions, as it refuses token creation. `TestBreakglassCallsNoOperationThatChangesState` checks every operation of the document that is not a read, so that a new one cannot slip through (ST-20).
- Decisions for the steps to come, which the API's descriptions state:
  - **Use cases are final once validated or rejected** (the maintainer's decision of 2026-10-19). `submit`, `withdraw`, `request_changes`, `reject` and `validate` change a use case only while it is neither validated nor rejected. A validated or rejected use case never changes, because the agents it justifies rely on it: a later decision is recorded with its agent, and only the agent changes state. While an agent's use case is rejected, `submit` and `validate` are refused, through the new guard `use_case_not_rejected`, and its owner links another use case while the agent is a draft. A use case cannot be edited while an agent it justifies waits for a decision, so that the committee decides on what it read. `docs/architecture/lifecycle.md`, `agent-lifecycle.yaml` and the domain model say so.
  - **Validating needs a comment** (the maintainer's decision of 2026-10-19): every use case decision stores one in the database, so T6 gains the guard `comment_given` in the lifecycle documents.
  - **People decide** (the maintainer's decision of 2026-10-19): the decisions on a proposal and the sign-offs of reviews are refused to service accounts (HUM-04), which the lifecycle documents now say.
  - **The console explains disabled actions** (P1-10, UX principles) with `getAgentActions`: the actions that the agent's state allows, whether the caller may take each one, and what refuses it, as `permission`, `not_owner_or_creator` or the name of a guard of `agent-lifecycle.yaml`. A refused transition answers `conflict` and names its guard; a missing comment is `bad_request`.
  - **Growing value sets use `x-extensible-enum`**, not `enum`: the kinds of inbox items, which P1-16 extends, and what refuses an action. oasdiff 1.32.1, which CI runs, refuses a new value of a response enum as a breaking change. The descriptions list the known values, since the generated code does not.
  - **People appear with their display name** (`PrincipalRef`) wherever a resource names one, because the API has no principal directory yet. `exportAgents` leaves names out on request (`pseudonymize`, NFR-20).
  - **Edits.** The slug and the kind never change, the use case only while the agent is a draft, and never to a rejected one. A retired or rejected agent no longer changes. A harness can be replaced but not removed, so only a policy can take an agent back from `ready` (T8). An edit that would leave neither a vendor nor a framework is refused.
  - **Delegates and new owners need the owner role,** through which they act for the agent; a transfer offered to anyone else is refused.
  - **Reviews.** The attestation states the five facts of step 6, which must all hold, and names the candidates to disable that the owner keeps. The candidates are tooling, which the user role and break-glass sessions may not see (permission matrix): they are left out for them, and from lists. Pull request 5 builds the sign-off check from the review's `signoffRequired`, which the setting `lifecycle.review_signoff_risk_tiers` sets, not from the fixed tiers of the `sign_off` scope.
  - **Export.** CSV with fixed columns, which the operation lists, or a JSON array of agents; not paged, as step 9 streams it. A cell, or a part of one after a `;`, that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`: spreadsheets in locales whose list separator is `;` would otherwise run it. T-09 and ST-24 name only the first four characters.
- Differences from the plan: the bulk import's operation comes with step 11 (pull request 8), as step 1 does not list it; instances are read in pull request 6, with coverage, which reads the same tables; the data categories get an operation of their own, which the proposal and use case forms need.
- Open questions for the next pull requests:
  - Owner pickers need a principal directory, which P1-03's deliverables name but no operation serves.
  - Who triggers T7 and T8 when an agent-specific policy is activated or retired: P1-06 needs an entry point of the lifecycle engine, which its plan does not mention.
  - What the activation guard answers before P1-06 lands: refusing keeps POL-04 but no agent can become active; allowing breaks POL-04.
  - T14 revokes credentials (P1-05) and retires agent-specific policies (P1-06): neither plan names an interface for it.
  - `lifecycle_transitions.actor_type` has no `service_account`, although service accounts may hold the roles that take the other transitions; a migration widens it in pull request 4.
  - Separation of duties looks at current assignments: a former delegate who holds the advisory role could decide on a proposal they helped write, and an advisory member or operator with the owner role could reassign an agent to themselves.
  - Which lifecycle notifications become inbox items (T4, T7, T8 and T11 notify people): pull requests 5 and 7, with the migration that widens `inbox_items.kind`.

### 2026-10-19: use cases and agents (PR 2)

- `internal/inventory`, the domain package of the plan, with its queries in `internal/inventory/queries` (sqlc package `inventorydb`, which `task verify:gen` now checks). It takes the caller of each operation and checks its permission itself, through the Authorizer, with the agent's relationship in the context, so that a token's scopes and break-glass apply. A `Refusal` says why a request is refused; the REST API maps its kinds to `bad_request`, `not_found`, `forbidden`, `conflict` and `precondition_failed`, with a detail that names nothing internal.
- **Proposals, transition T1** (`proposeAgent`). Only a person with the owner role proposes, and becomes the primary owner (INV-02). The proposal carries the metadata of INV-01: a vendor or a framework, a deployment location, environments, a risk tier, and data categories from the setting `inventory.data_categories`. Its use case must exist and not be rejected, and its slug must be free (`conflict`). One transaction writes the agent, its primary owner, its governance state at a new version, the row of T1 in `lifecycle_transitions`, and `whitetower.agent.created.v1`.
- **The governance state.** P1-07's interface is `inventory.StateVersions`, whose `Next` gives the version of a change, called as late in its transaction as it can be; `SequenceVersions` takes the next number of `governance_state_version_seq` until P1-07 adds its lock and its notification. The record of each agent holds its lifecycle state, its halt mode, the lease of its risk tier (setting `killswitch.lease_ttl_seconds`), and what policies see of it: slug, kind, risk tier, data categories, labels and the owner's ID.
- **Edits** (`editAgent`) need If-Match. The agent's owners and delegates edit it, and operators any agent. The slug and the kind never change, the use case only while the agent is a draft, and never to a rejected one; a retired or rejected agent no longer changes; an edit keeps a vendor or a framework. An edit of the risk tier, the data categories, the labels or the halt mode publishes the governance state at a new version. An edit that changes nothing takes no new version.
- **Use cases.** Only a person with the owner role creates one. Only its creator edits it, while it is a draft or changes were requested, and no agent it justifies waits for a decision. `listUseCaseDecisions` reads the decisions that pull request 4 records.
- **Reads.** The user role sees only active agents and the use cases of active agents; the others answer `not_found`. Agents are listed by slug, use cases and decisions newest first. An agent shows its run state, from its own halts and the fleet's, and coverage C0 until step 8 computes it (pull request 6): nothing records credentials, instances or drills before P1-05, P1-07 and P1-08. `listDataCategories` serves the setting.
- **Filters and text search** of `listAgents` and `listUseCases` answer `not_implemented` until pull request 6 builds them, rather than being ignored.
- **`IsOwner`** tells whether a principal is an agent's primary owner or one of its delegates; P1-16 checks ownership with it.
- Three event types of the core: `whitetower.agent.updated.v1`, with the agent as subject, and `whitetower.use_case.created.v1` and `whitetower.use_case.updated.v1`, without one, since a use case can justify several agents. An update names every member that changed, and copies the values of all but the texts that people write (an agent's description and harness, a use case's texts), as `comment_given` does for the comments of transitions.
- Tests: proposals and their governance state, transition and event; the metadata of INV-01, one case per rule; use cases that do not exist or were rejected; taken slugs; who may propose, edit and create use cases, break-glass, scoped tokens and service accounts included; what the user role sees; pages; edits at a stale version, without changes, of what policies see; owners and delegates; a fleet halt; and the same operations through the API, with each refusal's problem.
- Follow-ups:
  - P1-08 folds the active selector halts into a new agent's governance state, where `Propose` says so.
  - The agents of the evaluation seed have no governance state until their first edit, which writes it.

### 2026-10-19: ownership (PR 3)

- **Owners** (`listAgentOwners`): the agent's assignments, the current ones first, then those that ended, each the latest assigned first, with who made and who ended each one, and why. Whoever sees the agent sees its owners.
- **Reassignments** (`reassignAgentOwner`) by the advisory committee and operators (`agent.ownership.reassign`), for a reason, with If-Match. The former primary owner's assignment ends with that reason, the new owner's assignment as a delegate ends if they had one (`became the primary owner`), and a pending transfer is cancelled. The agent takes a new governance state version, since policies see the owner.
- **Delegates** (`addAgentDelegate`, `removeAgentDelegate`): the agent's owners, delegates included, and operators manage them; a removal needs a reason.
- **Transfers.** Only the primary owner offers one, to someone else (`requestOwnershipTransfer`). It waits in its recipient's inbox, as an item of kind `ownership_transfer` that pull request 7 lists, and the agent shows it (`pendingOwnershipTransfer`). An agent has one pending transfer at most (`conflict`). Its requester or an operator cancels it, and its recipient accepts or declines it; once closed, it answers `conflict`, and it leaves the inbox. Accepting needs the owner role: the former owner's assignment ends (`ownership transferred`), and the agent takes a new governance state version. A transfer whose giver no longer owns the agent is refused (`conflict`), should a later change of the primary owner forget to cancel it.
- **Who may own.** A new owner, a delegate and the recipient of a transfer must be an active person who holds the owner role, from IdP groups through the role mapping or from local role bindings, as authentication resolves them (`inventory.Options.RoleMapping`); anyone else is `bad_request`. The owners of a retired or rejected agent no longer change.
- **One change at a time.** Transactions run at read committed, so two reassignments at the same version both passed their checks, and the second failed on the unique index of primary owners: an internal error instead of `precondition_failed`. Every change of an agent's owners or transfers now locks the agent's row first. `TestReassignmentsUnderWayTogetherHappenOneAfterTheOther` holds the row of the governance state until both reassignments wait, and fails without the lock.
- **Exactly one primary owner.** The database enforces at most one (`agent_owners_one_primary`), and the inventory at least one, by ending the former owner's assignment and adding the new one in the same transaction, as the data model's table of invariants says. Step 3 said that the database enforces both: it would take a deferred constraint trigger, which the data model did not choose.
- **The agent's ETag** changes with its owners and its transfers, so that an edit made on what the caller read before is refused.
- One event type of the core: `whitetower.agent.ownership_changed.v1`, with the agent as subject and the change as the action of its facts: `owner_reassigned`, `delegate_added`, `delegate_removed`, `transfer_requested`, `transfer_cancelled`, `transfer_accepted` or `transfer_declined`. A change of the primary owner carries the former owner and the governance state version; the reasons that people write stay in the inventory.
- Tests: reassignments by the advisory committee and operators, refused to owners, at a stale version, to the same owner and without a reason; targets that are users, inactive, service accounts or no principal at all; delegates added twice, removed without a reason or when they are not one, and acting for the owner; every path of a transfer: declined, cancelled by its requester and by an operator, refused to an inactive recipient, accepted by its recipient, offered by anyone but the primary owner or to oneself, accepted after a reassignment or after its giver lost the agent; delegates who become the primary owner; the history's order and pages; retired agents; concurrent reassignments; and the same operations through the API, with each refusal's problem.
- Follow-ups:
  - A pending transfer has no deadline: `ownership_transfers.status` allows `expired`, which nothing sets. A transfer whose recipient becomes inactive, or loses the owner role, waits until its requester or an operator cancels it. The lifecycle guard job (pull request 5) could expire both.
  - Retiring or rejecting an agent (pull request 4) should cancel its pending transfer, which can no longer be accepted.
  - Reassigning an agent to oneself is allowed, so that an operator or an advisory member who also holds the owner role can take over an agent whose owner left. The separation of duties of pull request 4 should therefore look at who owned the agent when it was submitted, not only at its current owners (open question of pull request 1).

### 2026-10-20: the accepted design of the halt path

The maintainer accepted the design note of the halt path on 2026-10-20 ([P1-08's progress notes](P1-08-kill-switch.md#progress-notes)). It binds every plan that changes what enforcement points see, this one included, and its section 14 says what changes here.

- **The first pull request of P1-07.1 lands before pull request 4,** so that the lifecycle engine and the guard job are built and tested against the version counter (section 2) rather than a stub. It brings the writers of pull requests 2 and 3 under the lock rules of section 2: `LockAgent` takes `FOR NO KEY UPDATE` instead of `FOR UPDATE`, and `publishState` locks the agent's state row before `Next`. It removes `SequenceVersions` and the query `NextStateVersion`, and the evaluation seed writes each seeded agent's state row, as T1 does. That settles the follow-up of pull request 2 on the seed.
- **Pull requests 4 to 8** add:
  - the lifecycle engine's entry point for the transitions White Tower makes itself (T7, T8, T11, T12; section 8). It runs in its caller's transaction and at its version, checks no permission and no If-Match, never refuses, and gives the agent's row a new version. T12 skips drills, which do not suspend the agent (section 13, decision 1);
  - the active selector halts that an agent matches, added after its version in every write of the state record, in `publishState`, through an interface of P1-08: the fold that `Propose` marks becomes a fold in every write;
  - the shared form of the selector halts' advisory lock, with the key that `internal/govstate` defines, taken first in every writer that creates an agent or changes its labels or risk tier (T1, `editAgent` and the bulk import), since at read committed such a writer and a selector halt would otherwise miss each other (section 8);
  - a guard job that suspends one agent per transaction (step 7);
  - a bulk import that writes at most 100 agents per transaction (step 11);
  - coverage C3 through an interface that P1-08 implements (step 8); until then, no agent reaches C3;
  - `state_version` in `whitetower.agent.updated.v1`, required when a change concerns what enforcement points see.
