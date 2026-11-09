-- +goose Up
-- The role mapping that resolved a session's roles (plan P1-03, the fix of
-- 2026-11-09: sessions after a change of the role mapping; ST-14).
--
-- A session copies its roles at sign-in, from the person's groups through the
-- setting auth.oidc.role_mapping, which the server reads at start-up. The
-- column holds the SHA-256 of that mapping in a canonical form, and the
-- server refuses a session whose hash is not its own mapping's, as it refuses
-- an expired one, so that after a change everyone signs in again. Break-glass
-- sessions, whose roles do not come from the mapping, have none, and are
-- exempt. The sessions created before this migration have none either: they
-- are refused, and their people sign in again. The runtime role's grants on
-- sessions cover the new column.
ALTER TABLE whitetower.sessions
  ADD COLUMN role_mapping_sha256 bytea
    CONSTRAINT sessions_role_mapping_sha256_length CHECK (octet_length(role_mapping_sha256) = 32);
