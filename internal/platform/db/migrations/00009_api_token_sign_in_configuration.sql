-- +goose Up
-- The sign-in configuration that accepted the ID token of a token of the
-- CLI's exchange (plan P1-03, the fix of 2026-11-10: the CLI's tokens record
-- the sign-in configuration; ST-14).
--
-- The exchange turns an ID token into an API token of 12 hours. The column
-- holds the SHA-256 of the settings of auth.oidc that accepted the ID token,
-- in the canonical form whitetower-cli-sign-in-configuration-v1: those whose
-- hash a session records, with auth.oidc.cli_client_id in place of
-- auth.oidc.client_id. The server refuses a token whose hash is not that of
-- its own settings, as one that does not exist, so that after a change of any
-- of them everyone logs in again with the CLI. The tokens that people create,
-- and those of service accounts, have none, and are not affected.
--
-- The exchange's tokens created before this migration have none either, and
-- would be accepted until they expire, 12 hours at most after it. They are
-- the only tokens named wtctl that last 12 hours: people and service accounts
-- create tokens of whole days. They get 32 zero bytes, the hash of no
-- configuration, so that the server refuses them, as it refuses the sessions
-- created before sessions recorded a hash, and their people log in again with
-- the CLI. The runtime role's grants on api_tokens cover the new column.
ALTER TABLE whitetower.api_tokens
  ADD COLUMN sign_in_configuration_sha256 bytea
    CONSTRAINT api_tokens_sign_in_configuration_sha256_length CHECK (octet_length(sign_in_configuration_sha256) = 32);
UPDATE whitetower.api_tokens
  SET sign_in_configuration_sha256 = decode(repeat('00', 32), 'hex')
  WHERE name = 'wtctl' AND expires_at - created_at = interval '12 hours';
