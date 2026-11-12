-- +goose Up
-- Service accounts in the lifecycle's history (plan P1-04, pull request 4a;
-- the design of the halt path, section 12, in plan P1-08's progress notes).
--
-- A service account takes the lifecycle actions that its roles allow, and
-- the maintainer's decision of 2026-11-12 leaves it one, suspend (T10). The
-- history records who took each transition, so it names service accounts as
-- such, as the audit log does, rather than as people.
ALTER TABLE whitetower.lifecycle_transitions
  DROP CONSTRAINT lifecycle_transitions_actor_type_check,
  ADD CONSTRAINT lifecycle_transitions_actor_type_check
    CHECK (actor_type IN ('human', 'service_account', 'system', 'breakglass'));
