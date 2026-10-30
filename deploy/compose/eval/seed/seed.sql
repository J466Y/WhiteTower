-- Evaluation seed data for White Tower (P1-12.1).
-- Seeds principals, use cases, sample agents across lifecycle states, and ownership.
-- It runs on every start of the stack: each insert skips the rows it wrote before.

-- The people of the realm (keycloak/whitetower-realm.json). Each principal has
-- the core's issuer, and the ID of its user in the realm as its subject: the
-- sub of the user's ID tokens. Signing in as a user therefore finds its
-- principal, matched on issuer and subject, and updates it. The groups are
-- written as ID tokens carry them, without a leading slash.
INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name, email, status, idp_groups)
VALUES
  ('00000000-0000-7000-8000-000000000001', 'human', 'http://127.0.0.1:8180/realms/whitetower', '00000000-0000-4000-8000-000000000001', 'Olivia Owner', 'owner@example.test', 'active', ARRAY['wt-owners']),
  ('00000000-0000-7000-8000-000000000002', 'human', 'http://127.0.0.1:8180/realms/whitetower', '00000000-0000-4000-8000-000000000002', 'Ana Auditor', 'auditor@example.test', 'active', ARRAY['wt-auditors']),
  ('00000000-0000-7000-8000-000000000003', 'human', 'http://127.0.0.1:8180/realms/whitetower', '00000000-0000-4000-8000-000000000003', 'Sam Steering', 'steering@example.test', 'active', ARRAY['wt-steering']),
  ('00000000-0000-7000-8000-000000000004', 'human', 'http://127.0.0.1:8180/realms/whitetower', '00000000-0000-4000-8000-000000000004', 'Omar Operator', 'operator@example.test', 'active', ARRAY['wt-operators']),
  ('00000000-0000-7000-8000-000000000005', 'human', 'http://127.0.0.1:8180/realms/whitetower', '00000000-0000-4000-8000-000000000005', 'Alex Advisory', 'advisory@example.test', 'active', ARRAY['wt-advisory']),
  ('00000000-0000-7000-8000-000000000006', 'human', 'http://127.0.0.1:8180/realms/whitetower', '00000000-0000-4000-8000-000000000006', 'Uma User', 'user@example.test', 'active', ARRAY['wt-users']),
  ('00000000-0000-7000-8000-000000000007', 'human', 'http://127.0.0.1:8180/realms/whitetower', '00000000-0000-4000-8000-000000000007', 'Adrian Admin', 'admin@example.test', 'active', ARRAY['wt-admins'])
ON CONFLICT (id) DO NOTHING;

-- Role bindings for local authority
INSERT INTO whitetower.role_bindings (id, principal_id, role, reason, granted_by, granted_at)
VALUES
  ('00000000-0000-7000-8000-000000000011', '00000000-0000-7000-8000-000000000001', 'owner', 'Evaluation seed', '00000000-0000-7000-8000-000000000007', now()),
  ('00000000-0000-7000-8000-000000000012', '00000000-0000-7000-8000-000000000002', 'auditor', 'Evaluation seed', '00000000-0000-7000-8000-000000000007', now()),
  ('00000000-0000-7000-8000-000000000013', '00000000-0000-7000-8000-000000000003', 'steering', 'Evaluation seed', '00000000-0000-7000-8000-000000000007', now()),
  ('00000000-0000-7000-8000-000000000014', '00000000-0000-7000-8000-000000000004', 'operator', 'Evaluation seed', '00000000-0000-7000-8000-000000000007', now()),
  ('00000000-0000-7000-8000-000000000015', '00000000-0000-7000-8000-000000000005', 'advisory', 'Evaluation seed', '00000000-0000-7000-8000-000000000007', now())
ON CONFLICT (id) DO NOTHING;

-- Use Cases
INSERT INTO whitetower.use_cases (id, title, description, business_justification, data_categories, ai_act_classification, status, conditions, created_by, created_at, updated_at)
VALUES
  ('00000000-0000-7000-8000-000000000021', 'Customer Support Triage', 'Automated tier-1 ticket routing and customer inquiry assistance.', 'Reduces customer response time from 4h to 10m.', ARRAY['customer_data', 'support_history'], 'limited', 'validated', 'Must not access direct customer financial records or change passwords.', '00000000-0000-7000-8000-000000000001', now(), now()),
  ('00000000-0000-7000-8000-000000000022', 'Financial Portfolio Risk Analyzer', 'Portfolio scenario analysis and risk metric calculations.', 'Provides real-time exposure calculation for the advisory desk.', ARRAY['financial_records', 'market_data'], 'high_risk', 'submitted', NULL, '00000000-0000-7000-8000-000000000001', now(), now())
ON CONFLICT (id) DO NOTHING;

-- Agents across lifecycle states (active, proposed, suspended)
INSERT INTO whitetower.agents (id, slug, name, description, kind, source, vendor, framework, deployment_location, environments, risk_tier, ai_act_classification, data_categories, use_case_id, lifecycle_state, suspended_from, suspension_reason, suspended_at, harness, activated_at, created_by, created_at, updated_at)
VALUES
  ('00000000-0000-7000-8000-000000000101', 'support-bot-alpha', 'Support Bot Alpha', 'Customer support tier-1 conversational agent.', 'in_house', 'registered', NULL, 'langgraph', 'k8s-prod-eu', ARRAY['production'], 'low', 'limited', ARRAY['customer_data'], '00000000-0000-7000-8000-000000000021', 'active', NULL, NULL, NULL, '{"type": "declared", "description": "LangGraph in Kubernetes"}'::jsonb, now(), '00000000-0000-7000-8000-000000000001', now(), now()),
  ('00000000-0000-7000-8000-000000000102', 'portfolio-analyst-v1', 'Portfolio Risk Analyst', 'Candidate agent for investment risk simulation.', 'in_house', 'registered', NULL, 'crewai', 'k8s-staging-eu', ARRAY['staging'], 'high', 'high_risk', ARRAY['financial_records'], '00000000-0000-7000-8000-000000000022', 'proposed', NULL, NULL, NULL, NULL, NULL, '00000000-0000-7000-8000-000000000001', now(), now()),
  ('00000000-0000-7000-8000-000000000103', 'doc-indexer', 'Documentation Indexer', 'Batch search indexer temporarily suspended during review.', 'in_house', 'registered', NULL, 'custom', 'k8s-dev', ARRAY['development'], 'medium', 'minimal', ARRAY['public_docs'], '00000000-0000-7000-8000-000000000021', 'suspended', 'active', 'manual', now(), '{"type": "declared", "description": "Container on dev cluster"}'::jsonb, now() - interval '10 days', '00000000-0000-7000-8000-000000000001', now() - interval '30 days', now())
ON CONFLICT (id) DO NOTHING;

-- Agent Owners
INSERT INTO whitetower.agent_owners (id, agent_id, principal_id, role, assigned_by, assigned_at)
VALUES
  ('00000000-0000-7000-8000-000000000201', '00000000-0000-7000-8000-000000000101', '00000000-0000-7000-8000-000000000001', 'primary', '00000000-0000-7000-8000-000000000001', now()),
  ('00000000-0000-7000-8000-000000000202', '00000000-0000-7000-8000-000000000102', '00000000-0000-7000-8000-000000000001', 'primary', '00000000-0000-7000-8000-000000000001', now()),
  ('00000000-0000-7000-8000-000000000203', '00000000-0000-7000-8000-000000000103', '00000000-0000-7000-8000-000000000001', 'primary', '00000000-0000-7000-8000-000000000001', now())
ON CONFLICT (id) DO NOTHING;

-- What enforcement points know of each agent, as T1 writes it when an agent
-- is proposed: its lease by risk tier, its halt mode and the attributes that
-- policies see, at a version from the version counter.
INSERT INTO whitetower.governance_state (agent_id, lifecycle_state, lease_ttl_seconds, halt_mode, attributes, state_version)
SELECT a.id, a.lifecycle_state, (s.value ->> a.risk_tier)::integer, a.halt_mode,
  jsonb_build_object('slug', a.slug, 'kind', a.kind, 'risk_tier', a.risk_tier,
    'data_categories', to_jsonb(a.data_categories), 'labels', a.labels, 'owner_id', o.principal_id),
  whitetower.next_governance_version()
FROM whitetower.agents a
JOIN whitetower.agent_owners o ON o.agent_id = a.id AND o.role = 'primary' AND o.ended_at IS NULL
JOIN whitetower.settings s ON s.key = 'killswitch.lease_ttl_seconds'
WHERE a.id IN ('00000000-0000-7000-8000-000000000101', '00000000-0000-7000-8000-000000000102', '00000000-0000-7000-8000-000000000103')
ON CONFLICT (agent_id) DO NOTHING;
