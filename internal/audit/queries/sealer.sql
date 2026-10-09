-- name: ClaimUnsealed :many
-- Takes the next events off the queue of events to seal, without row locks:
-- one sealer runs, and if a second one ever did, the primary key of the
-- leaves would refuse one of their batches.
DELETE FROM whitetower.audit_unsealed
WHERE audit_id IN (
  SELECT q.audit_id FROM whitetower.audit_unsealed q ORDER BY q.ingested_at, q.audit_id LIMIT sqlc.arg(max_events))
RETURNING audit_id, ingested_at;

-- name: CanonicalEvents :many
-- The canonical bytes of events, by their audit IDs.
SELECT id, canonical FROM whitetower.audit_events WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: SealingTime :one
-- The database's clock, for the leaves of a batch.
SELECT clock_timestamp()::timestamptz AS now;

-- name: InsertLeaves :copyfrom
INSERT INTO whitetower.audit_leaves (leaf_index, audit_id, ingested_at, leaf_hash, sealed_at)
VALUES ($1, $2, $3, $4, $5);

-- name: InsertTreeHashes :copyfrom
INSERT INTO whitetower.audit_tree_hashes (hash_index, hash) VALUES ($1, $2);

-- name: TreeSize :one
-- The number of leaves in the tree.
SELECT (coalesce(max(leaf_index), -1) + 1)::bigint AS size FROM whitetower.audit_leaves;

-- name: TreeHashes :many
SELECT hash_index, hash FROM whitetower.audit_tree_hashes WHERE hash_index = ANY(sqlc.arg(indexes)::bigint[]);

-- name: LatestCheckpoint :one
SELECT tree_size, created_at FROM whitetower.audit_checkpoints ORDER BY tree_size DESC LIMIT 1;

-- name: InsertCheckpoint :exec
INSERT INTO whitetower.audit_checkpoints (tree_size, root_hash, signed_note, key_id)
VALUES (sqlc.arg(tree_size), sqlc.arg(root_hash), sqlc.arg(signed_note), sqlc.arg(key_id));

-- name: AddCheckpointKey :exec
-- Registers the public half of a checkpoint key, unless it is already.
INSERT INTO whitetower.signing_keys (key_id, purpose, algorithm, public_jwk, status)
VALUES (sqlc.arg(key_id), 'checkpoint', sqlc.arg(algorithm), sqlc.arg(public_jwk), 'next')
ON CONFLICT (key_id) DO NOTHING;

-- name: RetireOtherCheckpointKeys :exec
-- Retires the checkpoint keys other than key_id. Their public halves stay,
-- so that the checkpoints they signed still verify.
UPDATE whitetower.signing_keys SET status = 'retired', retired_at = now()
WHERE purpose = 'checkpoint' AND status = 'active' AND key_id <> sqlc.arg(key_id);

-- name: ActivateCheckpointKey :exec
UPDATE whitetower.signing_keys SET status = 'active', activated_at = now(), retired_at = NULL
WHERE key_id = sqlc.arg(key_id) AND status <> 'active';
