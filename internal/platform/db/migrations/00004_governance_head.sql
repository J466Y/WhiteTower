-- +goose Up
-- The version counter of the governance state (plan P1-07.1, pull request 1;
-- the design of the halt path, sections 2 and 12, in plan P1-08's progress
-- notes).
--
-- Every change that enforcement points see takes one version per transaction,
-- and every record the transaction changes carries it. The head, the single
-- row of governance_head, holds the last version handed out. A transaction
-- takes its version by moving the head, and the row's lock, held until
-- commit, makes the next writer wait until this one commits: commit order is
-- version order.

CREATE TABLE whitetower.governance_head (
  id      smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version bigint NOT NULL CHECK (version >= 0)
);
-- The head starts from the last number that the sequence handed out.
INSERT INTO whitetower.governance_head (id, version)
  SELECT 1, CASE WHEN is_called THEN last_value ELSE last_value - 1 END
  FROM whitetower.governance_state_version_seq;

-- The version of the calling transaction's change. The first call in a
-- transaction moves the head and keeps the version in a transaction-local
-- setting; a later call returns that version without moving the head. On a
-- pooled connection, a setting that an earlier transaction set locally reads
-- as an empty string, not as NULL. It runs with the owner's rights: the
-- runtime role may read the head, but moves it only through this function and
-- advance_governance_version.
-- +goose StatementBegin
CREATE FUNCTION whitetower.next_governance_version() RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v bigint := NULLIF(current_setting('whitetower.governance_version', true), '')::bigint;
BEGIN
  IF v IS NULL THEN
    UPDATE whitetower.governance_head SET version = version + 1 RETURNING version INTO STRICT v;
    PERFORM set_config('whitetower.governance_version', v::text, true);
  END IF;
  RETURN v;
END
$$;
-- +goose StatementEnd

-- Moves the head forward to target, unless it is there already, and returns
-- the head's version; it never moves the head back. A replica calls it when
-- the database lost versions that it had read, after an asynchronous failover
-- or a restore, and when an instance resumes from a version above the head
-- (the design of the halt path, section 10), so that the versions that follow
-- are above every version an instance applied. Like a writer, it holds the
-- head's lock until its transaction ends.
-- +goose StatementBegin
CREATE FUNCTION whitetower.advance_governance_version(target bigint) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v bigint;
BEGIN
  UPDATE whitetower.governance_head SET version = greatest(version, target) RETURNING version INTO STRICT v;
  RETURN v;
END
$$;
-- +goose StatementEnd

-- Refuses a state version that is not the one its transaction took, so that a
-- writer that forgets to take its version fails in its tests, instead of
-- breaking the resumption of watch streams in production. The triggers run
-- after the row, so that the CHECK constraints answer first.
-- +goose StatementBegin
CREATE FUNCTION whitetower.check_state_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state_version IS DISTINCT FROM NULLIF(current_setting('whitetower.governance_version', true), '')::bigint THEN
    RAISE EXCEPTION 'whitetower: % on %.% writes state version %, which is not the version of its transaction',
      TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME, NEW.state_version
      USING ERRCODE = 'integrity_constraint_violation',
            HINT = 'Take the version with whitetower.next_governance_version() first.';
  END IF;
  RETURN NULL;
END
$$;
-- +goose StatementEnd

-- Every write of an agent's state or of the fleet's takes a new version. A
-- halt and a lifecycle transition carry the version of the transaction that
-- inserts them; the updates of a halt that leave its version as it is, such
-- as its propagation outcome, need none.
CREATE TRIGGER governance_state_version_check AFTER INSERT OR UPDATE ON whitetower.governance_state
  FOR EACH ROW EXECUTE FUNCTION whitetower.check_state_version();
CREATE TRIGGER fleet_state_version_check AFTER INSERT OR UPDATE ON whitetower.fleet_state
  FOR EACH ROW EXECUTE FUNCTION whitetower.check_state_version();
CREATE TRIGGER halts_version_check AFTER INSERT ON whitetower.halts
  FOR EACH ROW EXECUTE FUNCTION whitetower.check_state_version();
CREATE TRIGGER lifecycle_transitions_version_check AFTER INSERT ON whitetower.lifecycle_transitions
  FOR EACH ROW EXECUTE FUNCTION whitetower.check_state_version();

-- The runtime role takes versions only from the head.
REVOKE ALL ON SEQUENCE whitetower.governance_state_version_seq FROM whitetower_runtime;
GRANT SELECT ON whitetower.governance_head TO whitetower_runtime;
REVOKE ALL ON FUNCTION whitetower.next_governance_version() FROM PUBLIC;
REVOKE ALL ON FUNCTION whitetower.advance_governance_version(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION whitetower.next_governance_version() TO whitetower_runtime;
GRANT EXECUTE ON FUNCTION whitetower.advance_governance_version(bigint) TO whitetower_runtime;
