-- name: RecordEvent :exec
-- Records an event, and queues it for the sealer, in the caller's
-- transaction.
WITH stored AS (
  INSERT INTO whitetower.audit_events (
    id, source, event_id, type, event_time, subject_agent_id,
    actor_type, actor_id, action, outcome, reason, request_id, trace_id, canonical)
  VALUES (
    sqlc.arg(id), sqlc.arg(source), sqlc.arg(event_id), sqlc.arg(type), sqlc.arg(event_time), sqlc.narg(subject_agent_id),
    sqlc.arg(actor_type), sqlc.narg(actor_id), sqlc.arg(action), sqlc.narg(outcome), sqlc.narg(reason),
    sqlc.narg(request_id), sqlc.narg(trace_id), sqlc.arg(canonical))
  RETURNING id, ingested_at
)
INSERT INTO whitetower.audit_unsealed (audit_id, ingested_at)
SELECT id, ingested_at FROM stored;

-- name: EnsurePartitions :exec
-- Creates the partitions of the audit tables for this month and the next
-- months_ahead.
SELECT whitetower.ensure_audit_partitions(sqlc.arg(months_ahead)::integer);

-- name: QueryEvents :many
SELECT
  e.id, e.event_time, e.source, e.type, e.subject_agent_id,
  e.actor_type, e.actor_id, e.action, e.outcome, e.reason,
  e.request_id, e.trace_id, e.ingested_at, e.canonical
FROM whitetower.audit_events e
WHERE
  (sqlc.narg(from_time)::timestamptz IS NULL OR e.event_time >= sqlc.narg(from_time))
  AND (sqlc.narg(to_time)::timestamptz IS NULL OR e.event_time <= sqlc.narg(to_time))
  AND (sqlc.narg(subject_agent_id)::uuid IS NULL OR e.subject_agent_id = sqlc.narg(subject_agent_id))
  AND (sqlc.narg(actor_id)::text IS NULL OR e.actor_id = sqlc.narg(actor_id))
  AND (sqlc.narg(actor_type)::text IS NULL OR e.actor_type = sqlc.narg(actor_type))
  AND (sqlc.narg(event_type)::text IS NULL OR e.type = sqlc.narg(event_type))
  AND (sqlc.narg(event_action)::text IS NULL OR e.action = sqlc.narg(event_action))
  AND (sqlc.narg(outcome)::text IS NULL OR e.outcome = sqlc.narg(outcome))
  AND (sqlc.narg(event_source)::text IS NULL OR e.source = sqlc.narg(event_source))
  AND (sqlc.narg(cursor_time)::timestamptz IS NULL OR (e.event_time, e.id) < (sqlc.narg(cursor_time)::timestamptz, sqlc.narg(cursor_id)::uuid))
  AND (
    sqlc.narg(owner_principal_id)::uuid IS NULL
    OR e.subject_agent_id IN (
      SELECT ao.agent_id FROM whitetower.agent_owners ao
      WHERE ao.principal_id = sqlc.narg(owner_principal_id) AND ao.ended_at IS NULL
    )
  )
ORDER BY e.event_time DESC, e.id DESC
LIMIT sqlc.arg(page_limit);

-- name: GetEventByID :one
SELECT
  e.id, e.event_time, e.source, e.type, e.subject_agent_id,
  e.actor_type, e.actor_id, e.action, e.outcome, e.reason,
  e.request_id, e.trace_id, e.ingested_at, e.canonical,
  l.leaf_index, l.leaf_hash
FROM whitetower.audit_events e
LEFT JOIN whitetower.audit_leaves l ON l.audit_id = e.id AND l.ingested_at = e.ingested_at
WHERE e.id = sqlc.arg(id);

-- name: IsAgentOwner :one
SELECT EXISTS (
  SELECT 1 FROM whitetower.agent_owners
  WHERE agent_id = sqlc.arg(agent_id)
    AND principal_id = sqlc.arg(principal_id)
    AND ended_at IS NULL
);

-- name: GetLatestCheckpoint :one
SELECT tree_size, root_hash, signed_note, key_id, created_at
FROM whitetower.audit_checkpoints
ORDER BY tree_size DESC
LIMIT 1;

-- name: ListCheckpoints :many
SELECT tree_size, root_hash, signed_note, key_id, created_at
FROM whitetower.audit_checkpoints
ORDER BY tree_size DESC;

