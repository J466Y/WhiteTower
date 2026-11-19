-- name: GetSetting :one
-- The value of a setting, as JSON (domain model, section 5).
SELECT value FROM whitetower.settings WHERE key = $1;

-- name: CreateUseCase :exec
INSERT INTO whitetower.use_cases (
  id, title, description, business_justification, data_categories, affected_persons,
  ai_act_classification, conditions, created_by, created_at, updated_at
) VALUES (
  sqlc.arg(id), sqlc.arg(title), sqlc.arg(description), sqlc.arg(business_justification),
  sqlc.arg(data_categories), sqlc.narg(affected_persons), sqlc.arg(ai_act_classification),
  sqlc.narg(conditions), sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(created_at)
);

-- name: GetUseCase :one
SELECT * FROM whitetower.use_cases WHERE id = $1;

-- name: LockUseCase :one
-- Locks a use case until the transaction ends, then reads it: the decisions
-- on the agents that it justifies happen one after the other, and each sees
-- the status that the one before it left.
SELECT * FROM whitetower.use_cases WHERE id = $1 FOR NO KEY UPDATE;

-- name: SetUseCaseStatus :exec
-- Moves a use case that no decision has made final to another status. A
-- validated or rejected use case never changes.
UPDATE whitetower.use_cases
SET status = sqlc.arg(status), updated_at = sqlc.arg(updated_at), version = version + 1
WHERE id = sqlc.arg(id) AND status NOT IN ('validated', 'rejected');

-- name: RecordDecision :exec
INSERT INTO whitetower.use_case_decisions (id, use_case_id, agent_id, decision, comment, decided_by, decided_at)
VALUES (sqlc.arg(id), sqlc.arg(use_case_id), sqlc.arg(agent_id), sqlc.arg(decision), sqlc.arg(comment),
  sqlc.arg(decided_by), sqlc.arg(decided_at));

-- name: UpdateUseCase :execrows
-- Changes a use case if it is still at the version the caller read.
UPDATE whitetower.use_cases SET
  title = sqlc.arg(title),
  description = sqlc.arg(description),
  business_justification = sqlc.arg(business_justification),
  data_categories = sqlc.arg(data_categories),
  affected_persons = sqlc.narg(affected_persons),
  ai_act_classification = sqlc.arg(ai_act_classification),
  conditions = sqlc.narg(conditions),
  updated_at = sqlc.arg(updated_at),
  version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version);

-- name: UseCaseAwaitsDecision :one
-- Whether an agent that the use case justifies waits for the advisory
-- committee's decision.
SELECT EXISTS (
  SELECT 1 FROM whitetower.agents WHERE use_case_id = $1 AND lifecycle_state = 'proposed'
);

-- name: UseCaseJustifiesActiveAgent :one
SELECT EXISTS (
  SELECT 1 FROM whitetower.agents WHERE use_case_id = $1 AND lifecycle_state = 'active'
);

-- name: ListUseCases :many
-- A page of use cases, newest first. With active_only, only those that
-- justify an active agent.
SELECT u.* FROM whitetower.use_cases u
WHERE (sqlc.narg(before)::uuid IS NULL OR u.id < sqlc.narg(before)::uuid)
  AND (NOT sqlc.arg(active_only)::boolean OR EXISTS (
    SELECT 1 FROM whitetower.agents a WHERE a.use_case_id = u.id AND a.lifecycle_state = 'active'))
ORDER BY u.id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListUseCaseDecisions :many
-- A page of the decisions on a use case, newest first.
SELECT * FROM whitetower.use_case_decisions
WHERE use_case_id = sqlc.arg(use_case_id)
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: CreateAgent :exec
INSERT INTO whitetower.agents (
  id, slug, name, description, kind, vendor, framework, deployment_location, environments,
  risk_tier, ai_act_classification, data_categories, use_case_id, harness, halt_mode,
  drill_eligible, labels, created_by, created_at, updated_at
) VALUES (
  sqlc.arg(id), sqlc.arg(slug), sqlc.arg(name), sqlc.arg(description), sqlc.arg(kind),
  sqlc.narg(vendor), sqlc.narg(framework), sqlc.arg(deployment_location), sqlc.arg(environments),
  sqlc.arg(risk_tier), sqlc.arg(ai_act_classification), sqlc.arg(data_categories),
  sqlc.arg(use_case_id), sqlc.narg(harness), sqlc.arg(halt_mode), sqlc.arg(drill_eligible),
  sqlc.arg(labels), sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(created_at)
);

-- name: GetAgent :one
SELECT * FROM whitetower.agents WHERE id = $1;

-- name: UpdateAgent :execrows
-- Changes an agent's metadata if it is still at the version the caller read.
UPDATE whitetower.agents SET
  name = sqlc.arg(name),
  description = sqlc.arg(description),
  vendor = sqlc.narg(vendor),
  framework = sqlc.narg(framework),
  deployment_location = sqlc.arg(deployment_location),
  environments = sqlc.arg(environments),
  risk_tier = sqlc.arg(risk_tier),
  ai_act_classification = sqlc.arg(ai_act_classification),
  data_categories = sqlc.arg(data_categories),
  use_case_id = sqlc.arg(use_case_id),
  harness = sqlc.narg(harness),
  halt_mode = sqlc.arg(halt_mode),
  drill_eligible = sqlc.arg(drill_eligible),
  labels = sqlc.arg(labels),
  updated_at = sqlc.arg(updated_at),
  version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version);

-- name: ListAgents :many
-- A page of agents, by slug. With active_only, only the active ones.
SELECT * FROM whitetower.agents
WHERE (sqlc.narg(after)::text IS NULL OR slug > sqlc.narg(after)::text)
  AND (NOT sqlc.arg(active_only)::boolean OR lifecycle_state = 'active')
ORDER BY slug
LIMIT sqlc.arg(page_limit);

-- name: AddOwner :exec
INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by, assigned_at)
VALUES (sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(principal_id), sqlc.arg(role),
  sqlc.arg(assigned_by), sqlc.arg(assigned_at));

-- name: CurrentOwners :many
-- The current primary owners and delegates of the agents.
SELECT o.agent_id, o.role, p.id AS principal_id, p.display_name, p.status
FROM whitetower.agent_owners o
JOIN whitetower.principals p ON p.id = o.principal_id
WHERE o.agent_id = ANY(sqlc.arg(agent_ids)::uuid[]) AND o.ended_at IS NULL
ORDER BY o.agent_id, p.display_name, p.id;

-- name: IsOwner :one
-- Whether the principal is the agent's primary owner or one of its delegates.
SELECT EXISTS (
  SELECT 1 FROM whitetower.agent_owners
  WHERE agent_id = $1 AND principal_id = $2 AND ended_at IS NULL
);

-- name: EverAssigned :one
-- Whether the principal is, or ever was, the agent's primary owner or one of
-- its delegates.
SELECT EXISTS (
  SELECT 1 FROM whitetower.agent_owners WHERE agent_id = $1 AND principal_id = $2
);

-- name: SetLifecycleState :execrows
-- Moves an agent to another state of its lifecycle, with what that state
-- records, if the agent is still at the version the caller read: where a
-- suspension came from, why and when, and when the agent was activated and
-- retired.
UPDATE whitetower.agents SET
  lifecycle_state = sqlc.arg(lifecycle_state),
  suspended_from = sqlc.narg(suspended_from),
  suspension_reason = sqlc.narg(suspension_reason),
  suspended_at = sqlc.narg(suspended_at),
  activated_at = sqlc.narg(activated_at),
  retired_at = sqlc.narg(retired_at),
  updated_at = sqlc.arg(updated_at),
  version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version);

-- name: ReviewOverdue :one
-- Whether an open review of the agent is past its grace period at the time
-- given, which comes from the application's clock.
SELECT EXISTS (
  SELECT 1 FROM whitetower.reviews
  WHERE agent_id = sqlc.arg(agent_id) AND status IN ('scheduled', 'awaiting_signoff')
    AND grace_ends_at < sqlc.arg(now)
);

-- name: HasOpenReview :one
-- Whether the agent has a review that is scheduled or waits for a sign-off.
SELECT EXISTS (
  SELECT 1 FROM whitetower.reviews WHERE agent_id = $1 AND status IN ('scheduled', 'awaiting_signoff')
);

-- name: ScheduleReview :exec
-- Schedules a review, with the terms that the settings gave when it was
-- scheduled: its due date, the end of its grace period and whether it needs a
-- sign-off.
INSERT INTO whitetower.reviews (id, agent_id, due_at, grace_ends_at, signoff_required, created_at)
VALUES (sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(due_at), sqlc.arg(grace_ends_at), sqlc.arg(signoff_required),
  sqlc.arg(created_at));

-- name: GetReview :one
SELECT * FROM whitetower.reviews WHERE id = $1;

-- name: LockReview :one
-- Locks a review until the transaction ends, then reads it. The caller has
-- locked the review's agent before.
SELECT * FROM whitetower.reviews WHERE id = $1 FOR NO KEY UPDATE;

-- name: CompleteReview :execrows
-- Records the owner's attestation of a scheduled review, if it is still at
-- the version the caller read: the review is then completed, or waits for a
-- sign-off.
UPDATE whitetower.reviews SET
  status = sqlc.arg(status),
  attestation = sqlc.arg(attestation),
  completed_by = sqlc.arg(completed_by),
  completed_at = sqlc.arg(completed_at),
  version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version) AND status = 'scheduled';

-- name: SignOffReview :execrows
-- Completes a review that waits for a sign-off, if it is still at the version
-- the caller read.
UPDATE whitetower.reviews SET
  status = 'completed',
  signed_off_by = sqlc.arg(signed_off_by),
  signed_off_at = sqlc.arg(signed_off_at),
  version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version) AND status = 'awaiting_signoff';

-- name: CancelOpenReviews :many
-- Cancels the agent's open review, if it has one, and returns its ID.
UPDATE whitetower.reviews SET status = 'cancelled', version = version + 1
WHERE agent_id = $1 AND status IN ('scheduled', 'awaiting_signoff')
RETURNING id;

-- name: AgentsToSuspend :many
-- The agents in one of the states given whose primary owner is not an active
-- principal, or whose open review's grace period ended before the time given,
-- which comes from the application's clock, with which of the two holds, by
-- ID. A read without a lock: the automatic suspension of each agent checks
-- its reason again under the agent's lock.
SELECT c.id, c.owner_inactive, c.review_overdue FROM (
  SELECT a.id,
    NOT EXISTS (
      SELECT 1 FROM whitetower.agent_owners o
      JOIN whitetower.principals p ON p.id = o.principal_id
      WHERE o.agent_id = a.id AND o.role = 'primary' AND o.ended_at IS NULL AND p.status = 'active'
    ) AS owner_inactive,
    EXISTS (
      SELECT 1 FROM whitetower.reviews r
      WHERE r.agent_id = a.id AND r.status IN ('scheduled', 'awaiting_signoff') AND r.grace_ends_at < sqlc.arg(now)
    ) AS review_overdue
  FROM whitetower.agents a
  WHERE a.lifecycle_state = ANY(sqlc.arg(states)::text[])
) c
WHERE c.owner_inactive OR c.review_overdue
ORDER BY c.id;

-- name: ReviewsToRemind :many
-- The scheduled reviews whose latest reminder point has passed at the time
-- given, which comes from the application's clock, and that were not reminded
-- since that point, with the point: one of the numbers of days before the due
-- date given, or 0 for the due date itself. A day is 24 hours, as when the
-- review was scheduled. A read without a lock: each reminder checks again, as
-- it records itself, that it is still due.
SELECT r.id, r.agent_id, r.due_at, p.days::integer AS days_before_due
FROM whitetower.reviews r
CROSS JOIN LATERAL (
  SELECT min(d) AS days FROM unnest(sqlc.arg(days)::integer[] || 0) AS d
  WHERE r.due_at - make_interval(hours => 24 * d) <= sqlc.arg(now)
) p
WHERE r.status = 'scheduled' AND p.days IS NOT NULL
  AND (r.last_reminder_at IS NULL OR r.last_reminder_at < r.due_at - make_interval(hours => 24 * p.days))
ORDER BY r.due_at, r.id;

-- name: RecordReminder :execrows
-- Records that a scheduled review was reminded at the time given, unless it
-- was reminded at or after the reminder point given, or is no longer
-- scheduled. The review's version stays: a reminder changes nothing that the
-- review shows, so that a completion read before it still applies.
UPDATE whitetower.reviews SET last_reminder_at = sqlc.arg(reminded_at)::timestamptz
WHERE id = sqlc.arg(id) AND status = 'scheduled'
  AND (last_reminder_at IS NULL OR last_reminder_at < sqlc.arg(point)::timestamptz);

-- name: ListAgentReviews :many
-- A page of the agent's reviews, the latest due first.
SELECT * FROM whitetower.reviews
WHERE agent_id = sqlc.arg(agent_id)
  AND (sqlc.narg(before_due)::timestamptz IS NULL
       OR (due_at, id) < (sqlc.narg(before_due)::timestamptz, sqlc.narg(before_id)::uuid))
ORDER BY due_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListReviews :many
-- A page of the reviews in any of the statuses given (all with none), the
-- earliest due first. With active_only, only those of active agents. With
-- overdue, only the open reviews past their due date at the time given, or
-- only the others.
SELECT r.* FROM whitetower.reviews r
JOIN whitetower.agents a ON a.id = r.agent_id
WHERE (NOT sqlc.arg(active_only)::boolean OR a.lifecycle_state = 'active')
  AND (cardinality(sqlc.arg(statuses)::text[]) = 0 OR r.status = ANY(sqlc.arg(statuses)::text[]))
  AND (sqlc.narg(overdue)::boolean IS NULL
       OR (r.status IN ('scheduled', 'awaiting_signoff') AND r.due_at < sqlc.arg(now)) = sqlc.narg(overdue)::boolean)
  AND (sqlc.narg(after_due)::timestamptz IS NULL
       OR (r.due_at, r.id) > (sqlc.narg(after_due)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY r.due_at, r.id
LIMIT sqlc.arg(page_limit);

-- name: ListTransitions :many
-- A page of the agent's lifecycle transitions, newest first, with the display
-- name of whoever took each one; the system has none.
SELECT t.*, p.display_name
FROM whitetower.lifecycle_transitions t
LEFT JOIN whitetower.principals p ON p.id = t.actor_id
WHERE t.agent_id = sqlc.arg(agent_id)
  AND (sqlc.narg(before)::uuid IS NULL OR t.id < sqlc.narg(before)::uuid)
ORDER BY t.id DESC
LIMIT sqlc.arg(page_limit);

-- name: PrincipalRefs :many
SELECT id, display_name, status FROM whitetower.principals WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: FleetHalted :one
SELECT run_state = 'halted' FROM whitetower.fleet_state WHERE id = 1;

-- name: HaltedAgents :many
-- Which of the agents an agent halt covers.
SELECT agent_id FROM whitetower.governance_state
WHERE agent_id = ANY(sqlc.arg(agent_ids)::uuid[]) AND run_state = 'halted';

-- name: LockGovernanceState :one
-- Locks the agent's governance state until the transaction ends, before the
-- transaction takes its version.
SELECT agent_id FROM whitetower.governance_state WHERE agent_id = $1 FOR NO KEY UPDATE;

-- name: PutGovernanceState :exec
-- Writes what enforcement points know of the agent, at a new state version,
-- with the active selector halts that the agent matches. The halts that its
-- state already carries stay: only a release removes a halt.
INSERT INTO whitetower.governance_state (
  agent_id, lifecycle_state, run_state, agent_halt_ids, lease_ttl_seconds, halt_mode, attributes,
  state_version, updated_at
) VALUES (
  sqlc.arg(agent_id), sqlc.arg(lifecycle_state),
  CASE WHEN cardinality(sqlc.arg(selector_halt_ids)::uuid[]) > 0 THEN 'halted' ELSE 'running' END,
  sqlc.arg(selector_halt_ids)::uuid[], sqlc.arg(lease_ttl_seconds), sqlc.arg(halt_mode),
  sqlc.arg(attributes), sqlc.arg(state_version), sqlc.arg(updated_at)
)
ON CONFLICT (agent_id) DO UPDATE SET
  lifecycle_state = EXCLUDED.lifecycle_state,
  run_state = CASE WHEN governance_state.run_state = 'halted' OR EXCLUDED.run_state = 'halted'
    THEN 'halted' ELSE 'running' END,
  agent_halt_ids = governance_state.agent_halt_ids || ARRAY(
    SELECT h FROM unnest(EXCLUDED.agent_halt_ids) AS h WHERE h <> ALL (governance_state.agent_halt_ids)),
  lease_ttl_seconds = EXCLUDED.lease_ttl_seconds,
  halt_mode = EXCLUDED.halt_mode,
  attributes = EXCLUDED.attributes,
  state_version = EXCLUDED.state_version,
  updated_at = EXCLUDED.updated_at;

-- name: SetStateLifecycle :exec
-- Changes only the lifecycle state of the agent's governance state, at a new
-- state version: a transition that White Tower makes itself keeps the lease,
-- the halt mode, the attributes and the halts that the state holds.
UPDATE whitetower.governance_state
SET lifecycle_state = sqlc.arg(lifecycle_state), state_version = sqlc.arg(state_version), updated_at = sqlc.arg(updated_at)
WHERE agent_id = sqlc.arg(agent_id);

-- name: ShareSelectorHaltsLock :exec
-- Takes the selector halts' advisory lock in its shared form until the
-- transaction ends: every selector halt takes it exclusively.
SELECT pg_advisory_xact_lock_shared(sqlc.arg(lock_key)::bigint);

-- name: AgentHaltIssued :one
-- Whether the halt is an agent halt of the agent, other than a drill, issued
-- at the state version given: the transaction's, so that T12 applies only the
-- halt issued in its own transaction.
SELECT EXISTS (
  SELECT 1 FROM whitetower.halts
  WHERE id = sqlc.arg(halt_id) AND agent_id = sqlc.arg(agent_id)::uuid AND scope = 'agent' AND NOT drill
    AND state_version = sqlc.arg(state_version)
);

-- name: RecordTransition :exec
INSERT INTO whitetower.lifecycle_transitions (
  id, agent_id, action, from_state, to_state, actor_type, actor_id, reason, comment,
  state_version, occurred_at
) VALUES (
  sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(action), sqlc.narg(from_state), sqlc.arg(to_state),
  sqlc.arg(actor_type), sqlc.narg(actor_id), sqlc.narg(reason), sqlc.narg(comment),
  sqlc.arg(state_version), sqlc.arg(occurred_at)
);

-- name: LockAgent :one
-- Locks the agent's row until the transaction ends, so that the changes of
-- its owners and of its transfers happen one after the other. The key-share
-- locks of foreign keys pass this lock: the transaction that holds the
-- version counter may insert a row that names the agent, such as a halt,
-- while this one waits for the counter.
SELECT id FROM whitetower.agents WHERE id = $1 FOR NO KEY UPDATE;

-- name: TouchAgent :execrows
-- Gives the agent a new version, for a change of its owners or of an
-- ownership transfer, at the version the caller read when it names one.
UPDATE whitetower.agents SET updated_at = sqlc.arg(updated_at), version = version + 1
WHERE id = sqlc.arg(id) AND (sqlc.narg(version)::bigint IS NULL OR version = sqlc.narg(version)::bigint);

-- name: PrincipalForOwnership :one
-- What decides whether a principal may own an agent: its kind, its status,
-- its IdP groups and its local role bindings.
SELECT p.kind, p.status, p.idp_groups,
  ARRAY(SELECT b.role FROM whitetower.role_bindings b
        WHERE b.principal_id = p.id AND b.revoked_at IS NULL)::text[] AS bound_roles
FROM whitetower.principals p WHERE p.id = $1;

-- name: CurrentAssignment :one
-- The principal's current assignment as the agent's primary owner or delegate.
SELECT * FROM whitetower.agent_owners
WHERE agent_id = sqlc.arg(agent_id) AND principal_id = sqlc.arg(principal_id) AND ended_at IS NULL;

-- name: PrimaryAssignment :one
SELECT * FROM whitetower.agent_owners
WHERE agent_id = $1 AND role = 'primary' AND ended_at IS NULL;

-- name: EndAssignment :exec
UPDATE whitetower.agent_owners
SET ended_by = sqlc.arg(ended_by), ended_at = sqlc.arg(ended_at), end_reason = sqlc.arg(end_reason)
WHERE id = sqlc.arg(id) AND ended_at IS NULL;

-- name: ListAssignments :many
-- A page of the agent's owner assignments: the current ones first, then
-- those that ended, each the latest assigned first.
SELECT o.*, p.display_name, p.status
FROM whitetower.agent_owners o
JOIN whitetower.principals p ON p.id = o.principal_id
WHERE o.agent_id = sqlc.arg(agent_id)
  AND (sqlc.narg(after_id)::uuid IS NULL
       OR (o.ended_at IS NOT NULL) > sqlc.arg(after_ended)::boolean
       OR ((o.ended_at IS NOT NULL) = sqlc.arg(after_ended)::boolean AND o.id < sqlc.narg(after_id)::uuid))
ORDER BY (o.ended_at IS NOT NULL), o.id DESC
LIMIT sqlc.arg(page_limit);

-- name: CreateTransfer :exec
INSERT INTO whitetower.ownership_transfers (id, agent_id, from_principal_id, to_principal_id, requested_by, requested_at)
VALUES (sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(from_principal_id), sqlc.arg(to_principal_id),
  sqlc.arg(requested_by), sqlc.arg(requested_at));

-- name: GetTransfer :one
SELECT * FROM whitetower.ownership_transfers WHERE id = $1 AND agent_id = $2;

-- name: PendingTransfers :many
-- The pending ownership transfers of the agents.
SELECT * FROM whitetower.ownership_transfers
WHERE agent_id = ANY(sqlc.arg(agent_ids)::uuid[]) AND status = 'pending';

-- name: DecideTransfer :execrows
-- Closes a pending transfer.
UPDATE whitetower.ownership_transfers SET status = sqlc.arg(status), decided_at = sqlc.arg(decided_at)
WHERE id = sqlc.arg(id) AND status = 'pending';

-- name: CancelPendingTransfers :many
-- Cancels the agent's pending transfer, if it has one, and returns its ID.
UPDATE whitetower.ownership_transfers SET status = 'cancelled', decided_at = sqlc.arg(decided_at)
WHERE agent_id = sqlc.arg(agent_id) AND status = 'pending'
RETURNING id;

-- name: AddInboxItem :exec
-- Adds an item to the inbox of one principal, or of everyone who holds one
-- role.
INSERT INTO whitetower.inbox_items (id, principal_id, role, kind, subject_type, subject_id, created_at)
VALUES (sqlc.arg(id), sqlc.narg(principal_id), sqlc.narg(role), sqlc.arg(kind), sqlc.arg(subject_type),
  sqlc.arg(subject_id), sqlc.arg(created_at));

-- name: ResolveInboxItems :exec
-- Takes the items of one kind about a subject out of every inbox.
UPDATE whitetower.inbox_items SET resolved_at = sqlc.arg(resolved_at)
WHERE kind = sqlc.arg(kind) AND subject_type = sqlc.arg(subject_type) AND subject_id = sqlc.arg(subject_id)
  AND resolved_at IS NULL;
