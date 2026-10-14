-- +goose Up
-- Audit retention: pruned range tracking and secure partition dropping (plan P1-02, step 9).

-- Leaf index ranges whose events were dropped by retention. Leaves and tree
-- hashes stay in the database so the log still verifies; this table records
-- the pruned ranges so that verification can distinguish lawful retention
-- drops from tampering.
CREATE TABLE whitetower.audit_pruned_ranges (
  from_leaf_index bigint NOT NULL CHECK (from_leaf_index >= 0),
  to_leaf_index   bigint NOT NULL CHECK (to_leaf_index > from_leaf_index),
  partition_name  text NOT NULL,
  dropped_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (from_leaf_index, to_leaf_index)
);

CREATE TRIGGER audit_pruned_ranges_append_only BEFORE UPDATE OR DELETE ON whitetower.audit_pruned_ranges
  FOR EACH ROW EXECUTE FUNCTION whitetower.reject_change();
CREATE TRIGGER audit_pruned_ranges_no_truncate BEFORE TRUNCATE ON whitetower.audit_pruned_ranges
  FOR EACH STATEMENT EXECUTE FUNCTION whitetower.reject_change();

GRANT SELECT, INSERT ON whitetower.audit_pruned_ranges TO whitetower_runtime;

-- Drops the monthly partitions of the audit tables for a given year and month (YYYY_MM).
-- Security definer so the runtime role can drop partitions without general DDL privileges.
-- +goose StatementBegin
CREATE FUNCTION whitetower.drop_audit_partition(suffix text) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  IF suffix !~ '^[0-9]{4}_[0-9]{2}$' THEN
    RAISE EXCEPTION 'whitetower: partition suffix must match YYYY_MM';
  END IF;

  IF to_regclass('whitetower.audit_events_' || suffix) IS NOT NULL THEN
    EXECUTE format('DROP TABLE whitetower.%I', 'audit_events_' || suffix);
  END IF;

  IF to_regclass('whitetower.audit_event_ids_' || suffix) IS NOT NULL THEN
    EXECUTE format('DROP TABLE whitetower.%I', 'audit_event_ids_' || suffix);
  END IF;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION whitetower.drop_audit_partition(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION whitetower.drop_audit_partition(text) TO whitetower_runtime;

-- Lists the existing partition table names of whitetower.audit_events.
-- +goose StatementBegin
CREATE FUNCTION whitetower.list_audit_partitions() RETURNS SETOF text
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
  RETURN QUERY
  SELECT c.relname::text
  FROM pg_class c
  JOIN pg_inherits i ON i.inhrelid = c.oid
  JOIN pg_class p ON p.oid = i.inhparent
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'whitetower' AND p.relname = 'audit_events'
  ORDER BY c.relname ASC;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION whitetower.list_audit_partitions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION whitetower.list_audit_partitions() TO whitetower_runtime;

