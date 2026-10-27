-- name: NextVersion :one
-- The version of the transaction's change, and whether this call took it:
-- the first call in a transaction moves the head, and later calls return the
-- same version. The setting is read once, before the function can set it, and
-- COALESCE calls the function only while the setting is unset.
WITH taken AS MATERIALIZED (
  SELECT NULLIF(current_setting('whitetower.governance_version', true), '')::bigint AS version
)
SELECT coalesce(taken.version, whitetower.next_governance_version())::bigint AS version,
  (taken.version IS NULL)::boolean AS first
FROM taken;
