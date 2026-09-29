-- Checks the invariants the database itself enforces (plan P0-02, step 7).
-- Run as a superuser on a database where 00001_init.sql has been applied:
--   psql -v ON_ERROR_STOP=1 -f hack/db/schema_checks.sql
-- Every block raises an exception, and psql stops, if an invariant is broken.
-- P1-01 turns these checks into Go integration tests.

\set QUIET on
SET client_min_messages = notice;

-- A login role for the core, member of the runtime group role.
DROP ROLE IF EXISTS wt_app;
CREATE ROLE wt_app LOGIN IN ROLE whitetower_runtime;

-- Fixture data, created by the runtime role as the core would.
SET ROLE wt_app;
INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name, email) VALUES
  ('00000000-0000-7000-8000-000000000001', 'human', 'http://idp', 'olivia', 'Olivia Owner', 'owner@example.test'),
  ('00000000-0000-7000-8000-000000000002', 'human', 'http://idp', 'alex', 'Alex Advisory', 'advisory@example.test'),
  ('00000000-0000-7000-8000-000000000003', 'human', 'http://idp', 'omar', 'Omar Operator', 'operator@example.test');
INSERT INTO whitetower.use_cases (id, title, description, business_justification, created_by) VALUES
  ('00000000-0000-7000-8000-000000000010', 'Invoice triage', 'Sorts incoming invoices', 'Saves time',
   '00000000-0000-7000-8000-000000000001');
INSERT INTO whitetower.agents (id, slug, name, description, kind, risk_tier, use_case_id, created_by) VALUES
  ('00000000-0000-7000-8000-000000000020', 'invoice-triage', 'Invoice triage', 'Sorts invoices', 'in_house', 'high',
   '00000000-0000-7000-8000-000000000010', '00000000-0000-7000-8000-000000000001');
INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by) VALUES
  (gen_random_uuid(), '00000000-0000-7000-8000-000000000020', '00000000-0000-7000-8000-000000000001', 'primary',
   '00000000-0000-7000-8000-000000000001');
INSERT INTO whitetower.audit_events (id, source, event_id, type, event_time, actor_type, actor_id, action, outcome, canonical)
  VALUES (gen_random_uuid(), 'core', 'evt-1', 'whitetower.agent.created.v1', now(), 'human',
          '00000000-0000-7000-8000-000000000001', 'agent.create', 'success', convert_to('{}', 'UTF8'));
INSERT INTO whitetower.lifecycle_transitions (id, agent_id, action, from_state, to_state, actor_type, actor_id, state_version)
  VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000020', 'create', NULL, 'draft', 'human',
          '00000000-0000-7000-8000-000000000001', nextval('whitetower.governance_state_version_seq'));
INSERT INTO whitetower.outbox (topic, payload) VALUES ('test', '{}');
SELECT whitetower.ensure_audit_partitions(6);
RESET ROLE;

-- Helper: runs a statement and requires it to fail with the given SQLSTATE.
CREATE FUNCTION pg_temp.must_fail(what text, stmt text, expected text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE stmt;
  RAISE EXCEPTION 'CHECK FAILED: % was allowed', what;
EXCEPTION WHEN OTHERS THEN
  IF SQLSTATE = 'P0001' AND SQLERRM LIKE 'CHECK FAILED%' THEN
    RAISE;
  END IF;
  IF SQLSTATE <> expected THEN
    RAISE EXCEPTION 'CHECK FAILED: % failed with % (%) instead of %', what, SQLSTATE, SQLERRM, expected;
  END IF;
  RAISE NOTICE 'ok: % (%)', what, SQLSTATE;
END
$$;
GRANT EXECUTE ON FUNCTION pg_temp.must_fail(text, text, text) TO wt_app;

-- 1. The runtime role cannot change or delete audit evidence.
SET ROLE wt_app;
SELECT pg_temp.must_fail('runtime role updates an audit event',
  $$UPDATE whitetower.audit_events SET action = 'tampered'$$, '42501');
SELECT pg_temp.must_fail('runtime role deletes an audit event',
  $$DELETE FROM whitetower.audit_events$$, '42501');
SELECT pg_temp.must_fail('runtime role truncates the audit events',
  $$TRUNCATE whitetower.audit_events$$, '42501');
SELECT pg_temp.must_fail('runtime role deletes a Merkle tree hash',
  $$DELETE FROM whitetower.audit_tree_hashes$$, '42501');
SELECT pg_temp.must_fail('runtime role deletes an agent',
  $$DELETE FROM whitetower.agents$$, '42501');
SELECT pg_temp.must_fail('runtime role creates a table',
  $$CREATE TABLE whitetower.backdoor (id int)$$, '42501');
RESET ROLE;

-- 2. Not even the owner can rewrite audit evidence without disabling triggers.
SELECT pg_temp.must_fail('owner updates an audit event',
  $$UPDATE whitetower.audit_events SET action = 'tampered'$$, '42501');
SELECT pg_temp.must_fail('owner deletes an audit event',
  $$DELETE FROM whitetower.audit_events$$, '42501');
SELECT pg_temp.must_fail('owner truncates the audit leaves',
  $$TRUNCATE whitetower.audit_leaves$$, '42501');
SELECT pg_temp.must_fail('owner rewrites the lifecycle history',
  $$UPDATE whitetower.lifecycle_transitions SET to_state = 'active'$$, '42501');
SELECT pg_temp.must_fail('owner truncates the audit events',
  $$TRUNCATE whitetower.audit_events$$, '42501');
SELECT pg_temp.must_fail('owner truncates the lifecycle history',
  $$TRUNCATE whitetower.lifecycle_transitions CASCADE$$, '42501');

-- 3. Separation of duties and two-person rules.
SET ROLE wt_app;
INSERT INTO whitetower.policies (id, name, scope, agent_id, language, created_by) VALUES
  ('00000000-0000-7000-8000-000000000030', 'invoice-triage tools', 'agent',
   '00000000-0000-7000-8000-000000000020', 'cedar', '00000000-0000-7000-8000-000000000001');
INSERT INTO whitetower.policy_versions (id, policy_id, version_number, content, content_sha256, status, author_id) VALUES
  ('00000000-0000-7000-8000-000000000031', '00000000-0000-7000-8000-000000000030', 1, 'permit(principal, action, resource);',
   sha256(convert_to('permit(principal, action, resource);', 'UTF8')), 'submitted', '00000000-0000-7000-8000-000000000001');
SELECT pg_temp.must_fail('the author approves their own policy version',
  $$INSERT INTO whitetower.policy_approvals (id, policy_version_id, approver_id, approver_role, decision)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000031', '00000000-0000-7000-8000-000000000001', 'advisory', 'approved')$$,
  '42501');
INSERT INTO whitetower.policy_approvals (id, policy_version_id, approver_id, approver_role, decision)
  VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000031', '00000000-0000-7000-8000-000000000002', 'advisory', 'approved');
SELECT pg_temp.must_fail('a submitted policy version changes its content',
  $$UPDATE whitetower.policy_versions SET content = 'permit(principal, action, resource) when { true };'
    WHERE id = '00000000-0000-7000-8000-000000000031'$$, '23000');

INSERT INTO whitetower.halts (id, scope, agent_id, reason, issued_by_type, issued_by, state_version) VALUES
  ('00000000-0000-7000-8000-000000000040', 'agent', '00000000-0000-7000-8000-000000000020', 'suspected exfiltration',
   'human', '00000000-0000-7000-8000-000000000003', nextval('whitetower.governance_state_version_seq'));
SELECT pg_temp.must_fail('a halt is released without an approved request',
  $$UPDATE whitetower.halts SET status = 'released', released_at = now()
    WHERE id = '00000000-0000-7000-8000-000000000040'$$, '42501');
SELECT pg_temp.must_fail('the requester approves their own release',
  $$INSERT INTO whitetower.halt_release_requests (id, halt_id, reason, requested_by, status, decided_by, decided_at)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000040', 'false alarm',
            '00000000-0000-7000-8000-000000000001', 'approved', '00000000-0000-7000-8000-000000000001', now())$$,
  '23514');
INSERT INTO whitetower.halt_release_requests (id, halt_id, reason, requested_by, status, decided_by, decided_at)
  VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000040', 'false alarm',
          '00000000-0000-7000-8000-000000000001', 'approved', '00000000-0000-7000-8000-000000000002', now());
UPDATE whitetower.halts SET status = 'released', released_at = now() WHERE id = '00000000-0000-7000-8000-000000000040';
SELECT pg_temp.must_fail('a released halt is reopened',
  $$UPDATE whitetower.halts SET status = 'propagating', released_at = NULL
    WHERE id = '00000000-0000-7000-8000-000000000040'$$, '23000');

-- 4. Structural invariants.
SELECT pg_temp.must_fail('a second primary owner',
  $$INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000020', '00000000-0000-7000-8000-000000000003',
            'primary', '00000000-0000-7000-8000-000000000003')$$, '23505');
SELECT pg_temp.must_fail('a private key stored as an agent credential',
  $$INSERT INTO whitetower.machine_credentials (id, agent_id, key_id, public_jwk, algorithm, thumbprint, environment, created_by)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000020', 'k1',
            '{"kty":"OKP","crv":"Ed25519","x":"abc","d":"secret"}', 'EdDSA', 'tp-1', 'production',
            '00000000-0000-7000-8000-000000000001')$$, '23514');
SELECT pg_temp.must_fail('an agent suspended without a reason',
  $$UPDATE whitetower.agents SET lifecycle_state = 'suspended' WHERE slug = 'invoice-triage'$$, '23514');
SELECT pg_temp.must_fail('an agent becomes ready without a declared harness',
  $$UPDATE whitetower.agents SET lifecycle_state = 'ready' WHERE slug = 'invoice-triage'$$, '23514');
SELECT pg_temp.must_fail('a halted agent without a halt',
  $$INSERT INTO whitetower.governance_state (agent_id, lifecycle_state, run_state, lease_ttl_seconds, state_version)
    VALUES ('00000000-0000-7000-8000-000000000020', 'draft', 'halted', 30, 1)$$, '23514');
SELECT pg_temp.must_fail('a lease shorter than 10 seconds',
  $$INSERT INTO whitetower.governance_state (agent_id, lifecycle_state, lease_ttl_seconds, state_version)
    VALUES ('00000000-0000-7000-8000-000000000020', 'draft', 5, 1)$$, '23514');
SELECT pg_temp.must_fail('an agent slug with capitals',
  $$INSERT INTO whitetower.agents (id, slug, name, description, kind, risk_tier, use_case_id, created_by)
    VALUES (gen_random_uuid(), 'Invoice', 'x', 'x', 'in_house', 'low', '00000000-0000-7000-8000-000000000010',
            '00000000-0000-7000-8000-000000000001')$$, '23514');

-- A cluster's network quarantine module is bound to every agent (KIL-10).
INSERT INTO whitetower.modules (id, slug, name, vendor, module_version, manifest, manifest_sha256, capabilities,
                                contract_versions, registered_by)
  VALUES ('00000000-0000-7000-8000-000000000050', 'k8s-quarantine', 'Network quarantine', 'White Tower', '0.1.0', '{}',
          sha256(convert_to('{}', 'UTF8')), '{runtime-control}', '{v1alpha1}', '00000000-0000-7000-8000-000000000003');
INSERT INTO whitetower.module_agent_bindings (id, module_id, scope, created_by)
  VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000050', 'all', '00000000-0000-7000-8000-000000000003');
INSERT INTO whitetower.module_instances (id, module_id, instance_key, identity_kind, module_version, contract_version,
                                         status, lease_ttl_seconds, connected_at, last_seen_at)
  VALUES ('00000000-0000-7000-8000-000000000051', '00000000-0000-7000-8000-000000000050', 'kind/quarantine-0', 'module',
          '0.1.0', 'v1alpha1', 'connected', 30, now(), now());
SELECT pg_temp.must_fail('a binding to all agents that names one agent',
  $$INSERT INTO whitetower.module_agent_bindings (id, module_id, scope, agent_id, created_by)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000050', 'all', '00000000-0000-7000-8000-000000000020',
            '00000000-0000-7000-8000-000000000003')$$, '23514');
SELECT pg_temp.must_fail('a second active binding to all agents',
  $$INSERT INTO whitetower.module_agent_bindings (id, module_id, scope, created_by)
    VALUES (gen_random_uuid(), '00000000-0000-7000-8000-000000000050', 'all', '00000000-0000-7000-8000-000000000003')$$,
  '23505');
SELECT pg_temp.must_fail('a negative count of quarantined workloads',
  $$INSERT INTO whitetower.halt_acks (halt_id, instance_id, agent_id, expected, quarantined_at, quarantined_workloads)
    VALUES ('00000000-0000-7000-8000-000000000040', '00000000-0000-7000-8000-000000000051',
            '00000000-0000-7000-8000-000000000020', true, now(), -1)$$, '23514');
RESET ROLE;

-- 5. Partitions exist for the months ahead.
DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM pg_inherits WHERE inhparent = 'whitetower.audit_events'::regclass;
  IF n < 7 THEN
    RAISE EXCEPTION 'CHECK FAILED: expected at least 7 monthly audit partitions, found %', n;
  END IF;
  RAISE NOTICE 'ok: % monthly audit partitions', n;
END
$$;

\echo 'All schema checks passed.'
