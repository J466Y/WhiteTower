-- name: GetExportCursor :one
SELECT sink, last_leaf_index, updated_at
FROM whitetower.audit_export_cursors
WHERE sink = $1;

-- name: SetExportCursor :exec
INSERT INTO whitetower.audit_export_cursors (sink, last_leaf_index, updated_at)
VALUES ($1, $2, $3)
ON CONFLICT (sink) DO UPDATE
SET last_leaf_index = EXCLUDED.last_leaf_index,
    updated_at = EXCLUDED.updated_at;

-- name: ListExportCursors :many
SELECT sink, last_leaf_index, updated_at
FROM whitetower.audit_export_cursors
ORDER BY sink;

-- name: ExportLeaves :many
-- The sealed leaves after after_leaf_index up to batch_limit, with their
-- events and metadata in strictly increasing leaf_index order.
SELECT
  l.leaf_index,
  l.leaf_hash,
  e.id,
  e.ingested_at,
  e.source,
  e.event_id,
  e.source_seq,
  e.type,
  e.event_time,
  e.subject_agent_id,
  e.actor_type,
  e.actor_id,
  e.action,
  e.outcome,
  e.reason,
  e.request_id,
  e.trace_id,
  e.canonical
FROM whitetower.audit_leaves l
JOIN whitetower.audit_events e ON e.ingested_at = l.ingested_at AND e.id = l.audit_id
WHERE l.leaf_index > sqlc.arg(after_leaf_index)
ORDER BY l.leaf_index
LIMIT sqlc.arg(batch_limit);
