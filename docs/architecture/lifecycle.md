# Agent lifecycle v0.1

| | |
| --- | --- |
| **Status** | Accepted v0.1, 2026-09-29 (plan [P0-02](../plans/phase-0/P0-02-domain-and-data-model.md), step 4) |
| **Date** | 2026-09-29 |
| **Normative** | Yes. The machine-readable form is [agent-lifecycle.yaml](agent-lifecycle.yaml); plan P1-04 generates the transition guards from it, and the two must never disagree |
| **Related** | [Requirements 5.1.1](../requirements/mvp-requirements.md#511-agent-lifecycle-initial-proposal-refined-in-plan-p0-02), [domain model](domain-model.md), [ADR-0005](../adr/0005-edge-enforcement-with-leases.md) |

The lifecycle turns the charter's governance model into rules the system enforces: **no agent reaches production without an owner, a validated use case and a specific policy**, and an agent whose owner leaves or whose review lapses stops being allowed to run.

## 1. States

| State | Meaning | Credentials White Tower issues | Enforcement point gate |
| --- | --- | --- | --- |
| `draft` | The owner is preparing the proposal | None | Closed |
| `proposed` | Waiting for the advisory committee to validate the use case | None | Closed |
| `validated` | Use case validated; the owner prepares the agent-specific policy and declares the harness | Non-production only | Open |
| `ready` | Agent-specific policy approved and harness declared; can be activated | Non-production only | Open |
| `active` | Running in production under monitoring | Production and non-production | Open |
| `suspended` | Temporarily barred; remembers the state it came from | None | Closed |
| `retired` | Permanently out of service; kept for the record | None, and all credentials revoked | Closed |
| `rejected` | The proposal was rejected | None | Closed |

**What "gate open" means.** The enforcement point may evaluate the agent's policies; it still denies everything while the lease is expired, the bundle is missing or invalid, or the agent is halted (ADR-0005). "Gate closed" means it denies everything regardless of policy.

**Production versus non-production** is enforced where credentials are issued (requirement AID-04), not by the enforcement point. An agent that is not `active` cannot obtain a production token.

## 2. Run state

The run state is separate from the lifecycle state:

- **Values:** `running` or `halted`.
- **Scope:** a halt can hit any agent that has running instances, whatever its lifecycle state.
- **Effective run state:** `halted` if an agent halt or a selector halt covers the agent (`governance_state.agent_halt_ids` is not empty), or the fleet is halted (`fleet_state`); otherwise `running`.

## 3. Transitions

The actors are the roles of the [permission matrix](../requirements/mvp-requirements.md#521-permission-matrix-initial-refined-in-plan-p1-03). `primary_owner` and `delegate` are relationships to this agent. `system` is White Tower itself, recorded as such in the audit log.

| ID | Action | From | To | Who | Guards | Effects |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | create | none | draft | owner role (becomes the primary owner) | metadata complete, use case linked | Assigns the primary owner; creates the governance state |
| T2 | submit | draft | proposed | primary owner, delegate | metadata complete, owner active | Submits the use case; notifies the advisory committee |
| T3 | withdraw | proposed | draft | primary owner, delegate | none | Withdraws the use case |
| T4 | request_changes | proposed | draft | advisory | not owner or creator, comment given | Use case: changes requested; notifies the owner |
| T5 | reject | proposed | rejected | advisory | not owner or creator, comment given | Use case rejected; notifies the owner |
| T6 | validate | proposed | validated | advisory | not owner or creator, use case not prohibited, owner active | Use case validated; notifies the owner |
| T7 | mark_ready | validated | ready | system | agent policy active, harness declared | Notifies the owner |
| T8 | unmark_ready | ready | validated | system | agent policy or harness missing | Notifies the owner |
| T9 | activate | ready | active | primary owner, delegate, operator | owner active, use case validated, agent policy active, harness declared, not halted | Sets `activated_at`; schedules the first review |
| T10 | suspend | validated, ready, active | suspended | primary owner, delegate, advisory, operator | comment given | Remembers the previous state; reason `manual` |
| T11 | auto_suspend | validated, ready, active | suspended | system | owner inactive, or review overdue past its grace period | Remembers the previous state; reason `owner_inactive` or `review_overdue`; notifies advisory and operators |
| T12 | halt_suspend | validated, ready, active | suspended | system | an agent halt was issued for this agent | Remembers the previous state; reason `halt` |
| T13 | reinstate | suspended | previous state | advisory, operator | comment given, owner active, review not overdue, not halted, the previous state's invariants hold | Clears the suspension |
| T14 | retire | draft, proposed, validated, ready, active, suspended | retired | primary owner, delegate, advisory, operator | comment given | Revokes every credential; retires the agent-specific policies; cancels the open review; sets `retired_at` |

Every transition:

- writes a row in `lifecycle_transitions` and an audit event (`whitetower.agent.created.v1` or `whitetower.agent.lifecycle_changed.v1`) in the same transaction;
- updates the agent's governance state and takes a new state version, so enforcement points learn about it within seconds;
- is refused if the agent row changed since the caller read it (optimistic concurrency).

## 4. Guards

| Guard | Holds when |
| --- | --- |
| `metadata_complete` | Every mandatory field of requirement INV-01 is set |
| `use_case_linked` | The agent references a use case |
| `owner_active` | The primary owner is an active principal |
| `not_owner_or_creator` | The actor is neither the primary owner, a delegate, nor the creator of the agent or its use case (separation of duties, HUM-04) |
| `comment_given` | The request carries a non-empty comment |
| `use_case_not_prohibited` | The use case's EU AI Act classification is not `prohibited` |
| `use_case_validated` | The use case's status is `validated` |
| `agent_policy_active` | At least one agent-specific policy of this agent has an active version (POL-04) |
| `harness_declared` | The agent has a harness declaration |
| `agent_policy_or_harness_missing` | The opposite of `agent_policy_active` and `harness_declared` together |
| `not_halted` | The effective run state is `running` |
| `owner_inactive_or_review_overdue` | The primary owner is inactive, or the open review's grace period has ended |
| `agent_halt_issued` | An agent-scoped halt for this agent was just committed |
| `review_not_overdue` | No review of this agent is past its grace period |
| `previous_state_invariants_hold` | Returning to the remembered state keeps its invariants, for example `active` still needs an active agent policy |

## 5. Invariants

| Invariant | Enforced by |
| --- | --- |
| An `active` agent has an active primary owner, a validated use case, at least one active agent-specific policy and a declared harness | Domain services (P1-04); harness also by a database constraint |
| Every agent has at most one primary owner at a time | Database (unique index) and domain services (at least one) |
| A suspended agent records the state it came from, the reason and the time, and only suspended agents do | Database constraint |
| A retired agent records when it was retired, and only retired agents do | Database constraint |
| Lifecycle history is never changed | Database triggers and privileges |
| Nobody validates, rejects or approves their own proposal or policy | Domain services; policy approvals also by a database trigger |

## 6. Suspension and reinstatement

- **Suspension remembers the previous state** (`validated`, `ready` or `active`). Reinstatement returns to it.
- **Reinstatement checks the real conditions, not the recorded reason.** An agent suspended because its owner left can be reinstated only once it has an active owner, no overdue review and no halt covering it, whatever reason was recorded first. An agent that becomes both ownerless and halted needs both causes resolved.
- **Who can reinstate:** the advisory committee or an operator; owners cannot reinstate their own agents.

## 7. Halts and the lifecycle

- **An agent halt** (scope `agent`) sets the run state to `halted` and, in the same transaction, moves an agent in `validated`, `ready` or `active` to `suspended` with reason `halt` (T12). Agents in other states keep their lifecycle state.
- **A fleet or selector halt** blocks every matching agent through the run state and changes no lifecycle state (requirement KIL-06), so releasing it restores operation without reinstating agents one by one.
- **Releasing a halt never reinstates an agent.** Release (two people, KIL-05) sets the run state back to `running`. For an agent halt, the agent stays `suspended` until someone reinstates it (T13), which forces a conscious decision to put it back into service.

## 8. Reviews

| Step | Rule |
| --- | --- |
| Scheduling | At activation (T9) and after each completed review. The interval depends on the risk tier (setting `lifecycle.review_interval_days`: 365, 365, 180 and 90 days for low, medium, high and critical) |
| Reminders | 30, 7 and 1 days before the due date (setting `lifecycle.review_reminder_days`), in the owner's inbox |
| Completion | The owner attests that the agent is still needed, the owner is still right, the data categories are current and the policy is still adequate |
| Sign-off | For high and critical risk (setting `lifecycle.review_signoff_risk_tiers`), a member of the advisory committee other than the owner signs off before the review counts as completed |
| Overdue | Past the due date, the review is overdue and reminders escalate to the advisory committee. Past the grace period (setting `lifecycle.review_grace_days`, 14 days), the agent is suspended (T11) |

## 9. Effects on credentials, bundles and governance state

| State | Token issuance | Policy bundles | Governance state sent to enforcement points |
| --- | --- | --- | --- |
| draft, proposed | Refused | Not built | Published (gate closed) |
| validated, ready | Non-production credentials only | Built from the active global and agent-specific versions; with no agent-specific policy yet, only global policies apply, under default deny | Published (gate open) |
| active | All credentials | Built | Published (gate open) |
| suspended | Refused, credentials kept for reinstatement | Kept, not rebuilt | Published (gate closed) |
| retired | Refused, credentials revoked | Not built | Published (gate closed) so connected instances stop |
| rejected | Refused | Not built | Published (gate closed) |

## 10. Tabletop walkthroughs

The table above was walked through with three scenarios. The people are the test users of the development realm.

**A normal onboarding.**

1. Olivia (owner) creates `invoice-triage` with its use case (T1) and submits it (T2).
2. Alex (advisory) validates it (T6); Olivia may now register a non-production key and test.
3. Olivia writes a Cedar policy for the agent; Alex approves it (P1-06) and it becomes active.
4. Olivia declares the harness; the system moves the agent to `ready` (T7).
5. Olivia activates it (T9). Its risk tier is high, so the first review is due in 180 days.

**The owner leaves.**

1. Olivia is deprovisioned in the IdP; SCIM deactivates her principal (P1-03).
2. The lifecycle guard suspends `invoice-triage` with reason `owner_inactive` (T11), and notifies advisory and operators.
3. Omar (operator) reassigns ownership to another active owner.
4. Alex reinstates the agent (T13): owner active, no overdue review, no halt. It returns to `active`.

**An emergency halt, then back to service.**

1. Omar halts `invoice-triage`, reason "suspected exfiltration" (P1-08). In one transaction: run state `halted`, lifecycle `suspended` with reason `halt` (T12), token issuance refused. Enforcement points close their gates and acknowledge.
2. After the investigation, Olivia requests the release and Alex approves it. The run state returns to `running`; the agent stays `suspended`.
3. Alex reinstates it (T13) once the fix is in place. It returns to `active`.

No gap was found. Two refinements came out of the walkthroughs and are already in the table:

- **Retiring from `proposed` (T14):** the owner can abandon a proposal without withdrawing it first.
- **Reinstatement checks conditions, not the stored reason (section 6):** the owner-leaves scenario can combine with a halt, and both causes must be resolved.
