-- +goose Up
-- The audit log's queue of events to seal, and the actors and outcomes of the
-- event catalog (plan P1-02, step 2).

-- Events that the sealer has yet to append to the Merkle tree (ADR-0006). An
-- event enters the queue in its own transaction, and the sealer takes it off
-- in a batch, so that an event whose transaction commits late is sealed in a
-- later batch, never skipped. The sealer claims events with DELETE ...
-- RETURNING, so the runtime role needs no UPDATE.
CREATE TABLE whitetower.audit_unsealed (
  audit_id    uuid PRIMARY KEY,
  ingested_at timestamptz NOT NULL
);
CREATE INDEX audit_unsealed_order ON whitetower.audit_unsealed (ingested_at, audit_id);
GRANT SELECT, INSERT, DELETE ON whitetower.audit_unsealed TO whitetower_runtime;

-- The event catalog (contracts, section 8) came after the schema: service
-- accounts act too, and an action an enforcement point ran may end cancelled.
ALTER TABLE whitetower.audit_events DROP CONSTRAINT audit_events_actor_type_check;
ALTER TABLE whitetower.audit_events ADD CONSTRAINT audit_events_actor_type_check
  CHECK (actor_type IN ('human', 'service_account', 'agent', 'module', 'system', 'breakglass'));
ALTER TABLE whitetower.audit_events DROP CONSTRAINT audit_events_outcome_check;
ALTER TABLE whitetower.audit_events ADD CONSTRAINT audit_events_outcome_check
  CHECK (outcome IN ('success', 'failure', 'cancelled', 'allow', 'deny', 'blocked', 'error'));
