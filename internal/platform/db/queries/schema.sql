-- name: SchemaVersion :one
-- The version of the last migration applied to the database.
SELECT coalesce(max(version_id), 0)::bigint AS version FROM goose_db_version;
