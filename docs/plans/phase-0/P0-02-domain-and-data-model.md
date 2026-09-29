# P0-02: Domain and data model v0.1

| | |
| --- | --- |
| **Phase** | 0 Foundations |
| **Status** | Done (see [progress notes](#progress-notes)) |
| **Size** | M |
| **Depends on** | none |
| **Unblocks** | P0-03, P0-04, P1-01, and the schema of every Phase 1 plan |
| **Requirements** | INV-01 to INV-07, HUM-04, AID-01, AID-04, POL-01, POL-04, AUD-01, KIL-06, NFR-19, NFR-20; open questions Q2 and Q3 |
| **Decisions** | ADR-0003, ADR-0005, ADR-0006 |

## Goal

A reviewed domain model, a normative lifecycle specification and a first database schema that every Phase 1 plan builds on. The model covers the MVP and leaves room for the Phase 2 and 3 capabilities without a redesign.

## Scope

**In:** vocabulary, entities and invariants, the agent lifecycle and run state, reviews and automatic suspension, risk tiers and data taxonomy, the governance state record, the physical PostgreSQL schema, data protection classification.

**Out:** the wire format of the module API and events (P0-03); query code and services (Phase 1 plans).

## Deliverables

- `docs/architecture/domain-model.md`: glossary, entities, attributes, invariants, entity-relationship diagram, traceability to requirements.
- `docs/architecture/lifecycle.md`: normative state machine for agents, run state, reviews and suspension rules.
- `internal/platform/db/migrations/00001_init.sql`: first schema, applied for real in P1-01.
- A data classification and retention table, inside the domain model document.

## Steps

### 1. Settle the modeling questions

Decide and record, with the reasoning:

- **Environments (Q2).** Proposal: one logical agent; credentials labeled per environment (production or non-production); running instances reported by enforcement points. Deployment location stays descriptive metadata.
- **Tenancy (Q3).** Proposal: one organization per deployment, no tenant column.
- **Identifiers:** UUIDv7 everywhere; human-readable slugs for agents and modules.
- **Deletion:** governance records are never deleted, only retired or superseded.
- **Time:** `timestamptz` in UTC; each event keeps both server ingestion time and source time (NFR-19).
- **Concurrency:** a `version` column on every table the console edits, exposed as an ETag.
- **JSONB:** only for extensible metadata and labels, never for fields that are queried or constrained.

**Done when:** the decisions are written at the top of the domain model document.

### 2. Glossary

Write the vocabulary used in code, API and console, starting from section 3 of the requirements: agent, instance, owner, delegate, use case, lifecycle state, run state, review, credential, policy, policy version, bundle, effective set, module, module instance, enforcement point, halt, release, lease, coverage level, audit event, checkpoint. One name per concept; no synonyms in code.

**Done when:** the plans and the architecture document use only glossary terms.

### 3. Entity model

Define attributes, constraints and invariants for:

- **People and access:** principals (IdP issuer and subject, name, email, status), role bindings, sessions, API tokens.
- **Inventory:** agents (metadata, labels, kind, source `registered` or `imported` with `discovered` reserved for Phase 3, risk tier, data categories, harness declaration, halt mode), ownership (one primary owner, delegates, history), use cases and their decisions, lifecycle transitions, reviews.
- **Identity:** agent and module credentials (public key, key ID, environment label, status, expiry), token signing keys (metadata only; private keys live outside the database).
- **Policies:** policies, versions (immutable content, language, hash), approvals, bundles.
- **Runtime:** governance state per agent, fleet state, modules, manifests, module instances and the agents each instance serves.
- **Kill switch:** halts (target: agent, fleet or selector), acknowledgements per instance, release requests and approvals, drills.
- **Audit:** events, Merkle tree hashes, checkpoints, export cursors.
- **Platform:** settings, outbox, job state.

**Done when:** the entity-relationship diagram and the attribute tables are complete, and every Must requirement in the inventory, identity, policy, audit and kill switch areas maps to at least one entity or field.

### 4. Lifecycle specification

Turn section 5.1.1 of the requirements into a normative table: for each transition, the starting state, the action, the resulting state, the roles allowed, the guards, the side effects and the audit event type. Include:

- the invariant for `active` (active owner, validated use case, approved agent-specific policy);
- suspension from `validated`, `ready` and `active`, remembering the previous state for reinstatement;
- the interplay with the run state: a halt moves the agent to `suspended`, and a release does not reinstate it by itself;
- separation of duties for each approval;
- what happens to credentials, bundles and governance state at each transition.

**Done when:** a tabletop walkthrough of three scenarios (a normal onboarding, an owner leaving the company, an emergency halt followed by reinstatement) runs through the table without gaps.

### 5. Reviews, risk tiers and taxonomies

- Risk tiers `low`, `medium`, `high`, `critical`, with default review intervals of 365, 365, 180 and 90 days, and a 14-day grace period before automatic suspension. All configurable.
- An optional EU AI Act classification field (`prohibited`, `high_risk`, `limited`, `minimal`, `not_assessed`).
- A configurable taxonomy of data categories.
- Default lease TTL per risk tier, taken from NFR-05 and updated by P0-05.

**Done when:** defaults are listed in the domain model and marked configurable.

### 6. Governance state record

Define the per-agent record the core publishes (lifecycle state, run state, halt reference, bundle reference, lease TTL, the labels EPs need), the fleet state record, and the global version sequence that orders every change. The wire format belongs to P0-03, which uses this record as input.

**Done when:** P0-03 authors confirm the record contains everything the watch stream needs.

### 7. Physical schema

Write `00001_init.sql`:

- tables, keys, foreign keys, check constraints for states and enumerations, and indexes for the known queries;
- audit tables partitioned by month;
- two roles, a migration owner and a runtime role, where the runtime role can only INSERT into audit tables and triggers reject UPDATE and DELETE on them;
- a handful of representative `sqlc` queries, to prove the schema generates usable code.

**Done when:** the migration applies cleanly on PostgreSQL 16 and 17, and a test shows the runtime role cannot change or delete audit rows.

### 8. Data protection review

List every field holding personal data (principal name, email, IdP subject, IP addresses in audit events), its purpose, its retention and whether it is pseudonymized on export (NFR-20). Note the GDPR tension between the right to erasure and audit retention, and the proposed answer: pseudonymous principal IDs in events, with the mapping kept in the principals table.

**Done when:** the classification table is in the domain model and has been read by P0-04.

### 9. Forward compatibility check

Sketch how later entities attach without breaking the model: quotas and cost (LLM gateway), gateway instances as enforcement points, skills and their signatures, enforced harness profiles, discovery findings linked to agents, the catalog of accepted providers and jurisdictions. Do not create their tables.

**Done when:** each later capability has a short paragraph showing where it attaches.

### 10. Review and sign-off

Review the model with the maintainers and, if possible, with someone who plays each charter role. Resolve comments and tag the documents as v0.1.

**Done when:** approved by two maintainers.

## Acceptance criteria

- Traceability table: every Must requirement of INV, AID, POL, AUD and KIL points to entities or fields (reviewed).
- The lifecycle specification covers every transition of the requirements, with roles, guards, side effects and audit events, and passed the tabletop walkthrough.
- The migration applies on PostgreSQL 16 and 17, and the audit privilege test passes.
- Open questions Q2 and Q3 are closed with recorded decisions.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Over-modeling for later phases | Only sketch later entities (step 9); create no tables for them |
| The single-organization decision is later regretted | Keep organization-wide settings in one table, so a tenant key can be added in one migration |
| Lifecycle rules too rigid for real organizations | Guards and review intervals configurable; tabletop with real roles in step 4 |

## Notes for implementers

- Model states as PostgreSQL enumerations or check constraints, never as free text.
- Keep the lifecycle table machine-readable (for example YAML next to the document): P1-04 can generate the transition guards and the documentation from it, so they never diverge.
- The governance state version must come from one sequence, so every change across all agents has a total order that watch streams can resume from.

## Progress notes

### 2026-09-29: first version, ready for review

| Step | Status | Result |
| --- | --- | --- |
| 1. Modeling questions | Done | Q2 and Q3 decided; see [domain model, section 1](../../architecture/domain-model.md#1-modeling-decisions) |
| 2. Glossary | Done | [Domain model, section 2](../../architecture/domain-model.md#2-glossary) |
| 3. Entity model | Done | [Domain model, section 3](../../architecture/domain-model.md#3-entities), with the traceability table in section 6 |
| 4. Lifecycle specification | Done | [lifecycle.md](../../architecture/lifecycle.md) and [agent-lifecycle.yaml](../../architecture/agent-lifecycle.yaml), checked for consistency by script; three tabletop walkthroughs, which added two refinements |
| 5. Risk tiers and taxonomies | Done | Defaults stored in `settings` |
| 6. Governance state record | Done | [Domain model, section 4](../../architecture/domain-model.md#4-the-governance-state-record); input for P0-03 |
| 7. Physical schema | Done | `00001_init.sql`: applies on PostgreSQL 16.15 and 17.11; 28 invariant checks pass on both (three added on 2026-09-29 for the network quarantine bindings and acknowledgements) ([`hack/db/schema_checks.sql`](../../../hack/db/schema_checks.sql)); `sqlc` 1.31.1 generates code from it |
| 8. Data protection | Done | [Domain model, section 7](../../architecture/domain-model.md#7-personal-data); argument redaction handed to P0-03 |
| 9. Forward compatibility | Done | [Domain model, section 8](../../architecture/domain-model.md#8-forward-compatibility) |
| 10. Review and sign-off | Done | Approved by the maintainer (@J466Y) on 2026-09-29. With a single maintainer, one approval stands in for two, as in GOVERNANCE.md |

