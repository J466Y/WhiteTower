-- name: SeenEventIDs :many
-- Returns which of a batch's events, by source and ID, the audit log recorded
-- in the months from from_month to to_month.
SELECT e.source, e.event_id
FROM whitetower.audit_event_ids e
JOIN (SELECT unnest(sqlc.arg(sources)::text[]) AS source, unnest(sqlc.arg(event_ids)::text[]) AS event_id) AS k
  ON e.source = k.source AND e.event_id = k.event_id
WHERE e.ingest_month BETWEEN sqlc.arg(from_month)::date AND sqlc.arg(to_month)::date;

-- name: RecordEventIDs :many
-- Records the IDs of a batch's new events in its month, in the order of their
-- keys, so that batches that share events cannot deadlock. It returns the keys
-- it recorded: a key that another transaction recorded since the batch's
-- lookup is left out.
INSERT INTO whitetower.audit_event_ids (source, event_id, ingest_month, audit_id)
SELECT k.source, k.event_id, sqlc.arg(ingest_month)::date, k.audit_id
FROM (SELECT unnest(sqlc.arg(sources)::text[]) AS source, unnest(sqlc.arg(event_ids)::text[]) AS event_id,
             unnest(sqlc.arg(audit_ids)::uuid[]) AS audit_id) AS k
ORDER BY k.source, k.event_id
ON CONFLICT (source, event_id, ingest_month) DO NOTHING
RETURNING source, event_id;

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

-- name: SealingLag :one
-- How long, in microseconds, the oldest event awaiting sealing has waited, on
-- the database's clock: the clock that stamped its ingestion time, and that
-- dates the sealer's leaves. It is 0 when no event waits.
SELECT coalesce(extract(epoch FROM clock_timestamp() - min(ingested_at)) * 1000000, 0)::bigint AS lag_us
FROM whitetower.audit_unsealed;
