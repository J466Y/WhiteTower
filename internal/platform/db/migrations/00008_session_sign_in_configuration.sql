-- +goose Up
-- The sign-in configuration that created a session (plan P1-03, the fix of
-- 2026-11-10: the session's hash covers the sign-in configuration; ST-14).
--
-- Migration 00007 added role_mapping_sha256, the SHA-256 of the role mapping
-- that resolved a session's roles. The hash now covers every setting that
-- decides which ID tokens the server accepts, which person a sign-in is and
-- what roles it gives: auth.oidc.issuer, client_id, allowed_algorithms,
-- external_id_claim, groups_claim and role_mapping, in a canonical form of
-- its own. The column and its constraint take the name of what they hold.
-- The hashes that the column holds are of the former form, which the server
-- no longer writes: it refuses their sessions, as those of another
-- configuration, and their people sign in again once. Break-glass sessions
-- still have none, and are exempt. The runtime role's grants on sessions
-- cover the renamed column.
ALTER TABLE whitetower.sessions
  RENAME COLUMN role_mapping_sha256 TO sign_in_configuration_sha256;
ALTER TABLE whitetower.sessions
  RENAME CONSTRAINT sessions_role_mapping_sha256_length TO sessions_sign_in_configuration_sha256_length;
