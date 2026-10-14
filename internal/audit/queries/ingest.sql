-- name: RecordEventID :one
-- Inserts an event ID for de-duplication within the current month.
-- Returns the audit ID if the event is fresh, or no rows if already seen.
INSERT INTO whitetower.audit_event_ids (source, event_id, ingest_month, audit_id)
VALUES (sqlc.arg(source), sqlc.arg(event_id), sqlc.arg(ingest_month), sqlc.arg(audit_id))
ON CONFLICT (source, event_id, ingest_month) DO NOTHING
RETURNING audit_id;

-- name: LockSourceSequences :many
-- Locks and returns the sequence rows for the given sources in source order,
-- preventing deadlocks between concurrent batches.
SELECT source, last_seq
FROM whitetower.audit_source_sequences
WHERE source = ANY(sqlc.arg(sources)::text[])
ORDER BY source
FOR UPDATE;

-- name: UpsertSourceSequence :exec
-- Updates or inserts the sequence row for a source with the latest sequence seen.
INSERT INTO whitetower.audit_source_sequences (source, last_seq, last_seen_at)
VALUES (sqlc.arg(source), sqlc.arg(last_seq), sqlc.arg(last_seen_at))
ON CONFLICT (source) DO UPDATE
SET last_seq = greatest(whitetower.audit_source_sequences.last_seq, excluded.last_seq),
    last_seen_at = excluded.last_seen_at;

-- name: IngestEvent :exec
-- Stores an ingested module event and queues it for the sealer in one statement.
WITH stored AS (
  INSERT INTO whitetower.audit_events (
    id, source, event_id, source_seq, type, event_time, subject_agent_id,
    actor_type, actor_id, action, outcome, reason, request_id, trace_id, canonical)
  VALUES (
    sqlc.arg(id), sqlc.arg(source), sqlc.arg(event_id), sqlc.narg(source_seq), sqlc.arg(type), sqlc.arg(event_time), sqlc.narg(subject_agent_id),
    sqlc.arg(actor_type), sqlc.narg(actor_id), sqlc.arg(action), sqlc.narg(outcome), sqlc.narg(reason),
    sqlc.narg(request_id), sqlc.narg(trace_id), sqlc.arg(canonical))
  RETURNING id, ingested_at
)
INSERT INTO whitetower.audit_unsealed (audit_id, ingested_at)
SELECT id, ingested_at FROM stored;

-- name: OldestUnsealedTime :one
-- The ingestion time of the oldest event awaiting sealing, for measuring lag.
SELECT ingested_at
FROM whitetower.audit_unsealed
ORDER BY ingested_at, audit_id
LIMIT 1;
