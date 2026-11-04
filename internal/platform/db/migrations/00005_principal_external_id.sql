-- +goose Up
-- The external ID of a person's principal (plan P1-03, the fix of 2026-11-03:
-- SCIM and sign-in share one principal).
--
-- The identity provider names a person by the same value in the externalId
-- that SCIM sends and in a claim of the ID token: sub by default, oid for
-- Entra ID (setting auth.oidc.external_id_claim). A sign-in finds the
-- principal by it, so that the principal that SCIM provisions is the one the
-- person signs in as, and a SCIM deactivation reaches their sessions and
-- tokens. Service accounts and the break-glass custodian have none. The
-- principals that people signed in as before this migration have none either:
-- their next sign-in finds them by issuer and subject, and gives them theirs.
-- No backfill from the subject: it is the external ID only when the claim is
-- sub. The runtime role's grants on principals cover the new column.
ALTER TABLE whitetower.principals
  ADD COLUMN external_id text
    CONSTRAINT principals_external_id_length CHECK (length(external_id) BETWEEN 1 AND 255),
  ADD CONSTRAINT principals_external_id_human CHECK (kind = 'human' OR external_id IS NULL);
CREATE UNIQUE INDEX principals_external_id ON whitetower.principals (external_id)
  WHERE kind = 'human' AND external_id IS NOT NULL;
