-- name: LogLeaves :many
-- The leaves of index from_index to to_index - 1, with their events'
-- canonical bytes, null when an event is missing. The join goes through the
-- events' primary key, so each leaf costs one index lookup (spike S3).
SELECT l.leaf_index, l.leaf_hash, e.canonical
FROM whitetower.audit_leaves l
LEFT JOIN whitetower.audit_events e ON e.ingested_at = l.ingested_at AND e.id = l.audit_id
WHERE l.leaf_index >= sqlc.arg(from_index) AND l.leaf_index < sqlc.arg(to_index)
ORDER BY l.leaf_index;

-- name: LogCheckpoints :many
SELECT tree_size, root_hash, signed_note FROM whitetower.audit_checkpoints ORDER BY tree_size;

-- name: CheckpointKeys :many
-- The public halves of the checkpoint keys: active, next and retired.
SELECT public_jwk FROM whitetower.signing_keys WHERE purpose = 'checkpoint' ORDER BY key_id;
