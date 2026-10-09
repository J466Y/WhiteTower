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
