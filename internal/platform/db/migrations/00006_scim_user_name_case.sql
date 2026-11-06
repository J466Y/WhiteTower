-- +goose Up
-- SCIM's userNames are unique without regard to case (plan P1-03, the fix of
-- 2026-11-06: what identity records, and SCIM).
--
-- RFC 7643 makes userName case-insensitive (section 4.1.1), so SCIM's filter
-- finds a user whatever the case of the userName it is given, and a creation
-- whose userName differs from a user's only in case is a userName that exists.
-- SCIM's principals have the issuer scim and their userName as subject, which
-- keeps the case that SCIM gave it; principals_idp_identity compares it
-- exactly. This index compares lower(subject), in the database's collation,
-- as the filter's query does, so that both agree on which userNames are one.
-- No deployment stack turns SCIM on, and no release came before this
-- migration: should two userNames of SCIM's differ only in case, the index is
-- not created, and the migration fails with the userName.
CREATE UNIQUE INDEX principals_scim_user_name ON whitetower.principals (lower(subject))
  WHERE kind = 'human' AND issuer = 'scim';
