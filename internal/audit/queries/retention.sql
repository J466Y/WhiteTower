-- name: RecordPrunedRange :exec
INSERT INTO whitetower.audit_pruned_ranges (from_leaf_index, to_leaf_index, partition_name)
VALUES ($1, $2, $3);

-- name: ListPrunedRanges :many
SELECT from_leaf_index, to_leaf_index, partition_name, dropped_at
FROM whitetower.audit_pruned_ranges
ORDER BY from_leaf_index ASC;

-- name: PartitionLeafBounds :one
SELECT coalesce(min(leaf_index), -1)::bigint AS min_leaf_index,
       coalesce(max(leaf_index), -1)::bigint AS max_leaf_index,
       count(*)::bigint AS leaf_count
FROM whitetower.audit_leaves
WHERE ingested_at >= $1 AND ingested_at < $2;

-- name: DropAuditPartition :exec
SELECT whitetower.drop_audit_partition($1);

-- name: ListAuditPartitions :many
SELECT whitetower.list_audit_partitions() AS partition_name;

