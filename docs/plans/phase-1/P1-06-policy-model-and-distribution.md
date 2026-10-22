# P1-06: Policy model and distribution

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L |
| **Depends on** | P0-03 (decision profile, bundle format), P1-04 (can start once agent records and their API are merged, about two weeks into P1-04); for the parts that come from RFC-0002, its acceptance and P0-03 step 12, which puts it in the contracts |
| **Unblocks** | P1-09, P1-10.3, P1-16 (steps 5 and 6) |
| **Requirements** | POL-01 to POL-10; with P1-16, the policy and bundle side of CAT-03, CAT-05 and CAT-06 |
| **Decisions** | ADR-0004, ADR-0005, [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) |

## Goal

Global and agent-specific policies, written in a standard language, validated, approved by the right committee and never by their author, then compiled into a signed bundle per agent, with the agent's catalog file and its own Cedar schema, and delivered to every enforcement point. Which bundle each instance actually runs is always visible.

## Scope

**In:** policies and immutable versions, validation, the approval workflow, the seeded permit of the lifecycle actions, the activation guard used by the lifecycle, effective sets and signed bundles, distribution through the governance state, drift detection, diff, simulation. Once [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) is accepted and in the contracts (P0-03, step 12), with plan P1-16: the catalog file and the per-agent Cedar schema in bundles, the seeded global policy `wt-catalog`, the check of usage-rule statements at submission, and the rebuilds that catalog changes cause.

**Out:** evaluation at runtime (the enforcement points: P1-09 and the mock module of P1-07); the catalog of MCP servers, tools and models, enablement, argument declarations and the usage-rule generator (P1-16, through interfaces defined here); the accepted providers and jurisdictions of POL-10 (Phase 2).

**With P1-16.** This plan defines the interfaces and builds the bundles; P1-16 implements the interfaces and supplies the catalog's content:

| Item | This plan | P1-16 |
| --- | --- | --- |
| The seeded policies: the permit of the lifecycle actions, and `wt-catalog` | Seeds them (step 4) | None |
| The Cedar schema of each bundle | Builds it (step 6) | Supplies the argument declarations and their types |
| The catalog file of each bundle | Carries it, signed (step 6) | Supplies its content (its step 5) |
| The check of `@rule` statements | Runs it at submission (step 3) | Supplies the generator, which compiles usage rules (its step 6) |
| The usage-rule form and the transforms | None | Builds them (its step 6) |
| Rebuilds after a catalog change | Provides the triggers (step 6) | Calls them when an enablement, an observation or an entry changes |

## Deliverables

- `internal/policy` with its OpenAPI operations.
- A built-in validator for Cedar; Rego's waits for Phase 2 (contracts, section 6.7).
- The bundle builder and signer.
- The per-agent Cedar schema and catalog file of each bundle.
- The seeded global policies: the permit of the lifecycle actions and `wt-catalog`.
- The setting `policy.approval_quorum`, with the migration that inserts its default (step 4).
- Drift metrics and alerts.

## Steps

### 1. API first

Write the OpenAPI operations for policies, versions, validation, approvals, diff, effective policy per agent, bundle metadata (with the catalog file's hash and size) and the Cedar schemas that versions validate against (step 3), which the editor of P1-10.3 uses. Review them with P1-10.3.

**Done when:** the operations are merged and agreed with the console side.

### 2. Policies and versions

- A policy has a scope (global, or agent-specific with its agent) and a language.
- Supported languages are those with a built-in validator that at least one approved enforcement module declares: Cedar, the only language of the contracts' `v1alpha1`. The seeded versions of step 4 are exempt, since a fresh installation has no approved module yet. A policy's record of its language may keep `rego` for Phase 2.
- Versions are immutable: content, SHA-256, author, creation time and a change note. The seeded versions of step 4 have the system as their author.
- Version states: draft, submitted, approved, active, superseded, rejected, withdrawn.
- Usage rules (RFC-0002, section 8) are Cedar `forbid` statements of ordinary policies, global or agent-specific, each annotated with its rule (`@rule`). They have no table, version or workflow of their own: the policy text is the only source of truth.

**Done when:** content cannot change once submitted (test), and the version states follow their table.

### 3. Validation

- **Cedar:** parse with `cedar-go`, and validate in strict mode against a schema generated from the catalog: the profile's schema, whose `ToolArgs` holds one record per tool with the arguments policies may see, typed as the catalog declares them (RFC-0002, sections 7.5 and 7.6). An agent-specific version validates against its agent's schema, and a global version against one schema that covers the whole catalog. The arguments of the agent's own tools (`agent/<name>`) are only in their agent's schema, so a global version cannot read them (RFC-0002, section 7.5). This replaces the deployment-wide `ToolArgs` extension of the contracts (section 6.7).
- **Rego** waits for Phase 2, with the mapping that section 12 of the contracts lists.
- **Fixed values must be valid.** A version is refused when a Cedar statement compares an attribute whose values the profile fixes with a literal outside its set, through `==`, `!=` or `like`, or through `contains`, `containsAny` or `containsAll` on set literals. The sets are read from `decision-request.schema.json`, so RFC-0002's attributes are covered as soon as the schema has them. Tests use `non-production`, `Critical`, `third-party` and `MCP`: strict Cedar validation lets each through, and the comparison would silently never match, or always (contracts, section 6.7).
- **Policy tests (Should, POL-07):** optional test files with expected decisions run in the core. Results are attached to the version, and a version with failing tests cannot be submitted.
- **Arguments must be visible.** A version is refused when one of its Cedar statements reads a tool argument outside the sets policies see: those a reviewer declared, and those usage rules use. Enforcement points fill only those (EP-19), so such a condition never holds, and strict validation does not report it when `has` guards the read.
- **Usage-rule statements.** At submission, every statement annotated `@rule` is regenerated from its annotation, and the version is refused unless each rule's statements are exactly the generator's output: one per tool, none missing, none added, the annotation in canonical JSON. The generator is P1-16's compiler of usage rules, behind an interface defined here: what a rule compiles to depends on the types of its arguments, which the catalog holds. Until P1-16 lands, a version with an `@rule` statement is refused.

**Done when:** syntax errors are reported with line and column, failing tests block submission, a hand-edited, missing or extra rule statement is refused, and so are a statement that reads an argument policies cannot see and a comparison with a fixed value outside the profile's set.

### 4. Approval workflow

- Submitted versions are approved by the steering committee (global scope) or the advisory committee (agent scope).
- Separation of duties: the author never approves, and so never counts toward the quorum. Rejections need a comment.
- **Quorum** (the maintainer's decision of 2026-10-21, on RFC-0002's unresolved question 2). A version is approved once the quorum of its scope has approved it.
  - The setting `policy.approval_quorum` holds one value per scope, `{"global": 1, "agent": 1}` by default: the number of distinct people of the approving committee (POL-02) who must approve a version, from 1 to 5. It is a row of the `settings` table, which administrators edit at runtime (domain model, section 5): a migration of this plan inserts its default, and the core reads it from that table, not from `internal/platform/config`.
  - The platform administrator sets it through P1-17's API (`settings.manage`), with which this plan registers the key, its validator and its notification; if P1-17 lands after this step, P1-17 registers them on this plan's behalf. The change is audited like any change to a setting (`whitetower.setting.changed.v1`, AUD-01).
  - Approvals are made by people, never by service accounts (`forbidden`), and a person and their own service account count once (P1-03's notes of 2026-10-19), as for the decisions on proposals (P1-04) and halt releases (P1-08). So the person responsible for a service account that authored a version cannot approve it.
  - Submitting a version records the quorum of its scope then in force, and the version needs that quorum, so lowering the setting approves nothing already waiting.
  - One rejection, with its comment, by a member of the approving committee rejects the version, whatever the quorum. Rejections, like approvals, come from people.
  - The key's validator refuses a value outside 1 to 5 for a scope, and a quorum larger than the number of active people who hold the committee's role, since no version could reach it. A change of the quorum notifies the steering committee's inbox (P1-17, step 4), as grants of steering, advisory or operator do (DC-4).
- The approval that completes the quorum activates the version and supersedes the previous active one.
- Rollback creates a new version with earlier content, which needs approval again (POL-08).
- Approval runs the checks of step 3 again, against the catalog of that moment: a version that reads an argument no longer declared, or whose rule statements the generator no longer produces, cannot be approved.
- Usage rules follow this workflow like any other statement, so adding one needs the quorum of its scope too (RFC-0002, unresolved question 2). An urgent restriction uses a disable or a block, which take effect at once (P1-16).
- Seeded policies: the core seeds two global policies, once each, as submitted versions authored by the system. They are the permit of the lifecycle actions that the contracts expect (section 6.3), and `wt-catalog`, with the text of RFC-0002, section 7.1. The steering committee approves them like any global policy, and may narrow them. Until it does, the actions they permit are denied unless another policy permits them (`policy.no_permit`).
  - `policies.created_by` and `policy_versions.author_id` must reference a principal, and principals are humans or service accounts. A forward migration adds one reserved system principal, of a kind of its own that can hold no session, token or role, as `authn.BreakglassPrincipalID` is reserved for break-glass; it authors the seeded versions, and only them.
  - Seeding writes its audit event, whose actor is `system`, in the same transaction, and stays idempotent when two replicas start at once.
  - The database refuses an approval by the version's author (`reject_self_approval`), so any member of the steering committee can approve a seeded version.

**Done when:** every path is tested, including an author trying to approve through any role they hold; a version with fewer distinct approvals than its quorum stays submitted; and a fresh installation has the seeded versions waiting for the steering committee, seeded once even when two replicas start together.

### 5. Activation guard

Implement the interface P1-04 uses: an agent can be activated only if it has at least one active agent-specific policy (POL-04).

**Done when:** the lifecycle property tests run against the real implementation instead of the stub.

### 6. Effective sets and bundles

- The **effective set** of an agent is the active global versions plus its active agent-specific versions.
- The **bundle** follows the P0-03 format, as RFC-0002 extends it: a manifest with a monotonic version per agent, the combination algorithm ID and the entries with their hashes, plus the policy files, the agent's Cedar schema (`schema.cedarschema`) and its catalog file (`catalog.json`, format `whitetower.catalog.v1`, in the manifest's `catalog` field). The serialization is deterministic (RFC 8785, with the catalog's entries sorted by key), and the content hash is kept apart from the version. The catalog file holds no observation times, so a report that changes only when entries were last seen changes no bundle.
- **Every bundle carries a catalog file**, empty when nothing is observed or enabled for the agent, so `wt-catalog` never travels without one: an enforcement point that does not support catalogs rejects the bundle, keeping its last valid bundle or, with none, staying closed, and never applies the permit without the catalog check (T-82, ST-32).
- **What the schema and the catalog file hold** comes through an interface defined here, which P1-16 implements (its step 5): the entries enabled for the agent and those observed for it, and, for each tool, the arguments policies may see and their types (RFC-0002, sections 5 and 7.5). Until P1-16 lands, the catalog file is empty.
- The manifest is signed with the bundle key (Ed25519, detached JWS) and the bundle stored in PostgreSQL.
- **Size.** The builder refuses, and alerts on, a bundle beyond the limits of step V1 (2 MiB, at most 1,000 files; contracts, section 7.4), rather than publish one that every enforcement point would reject.
- **Rebuilds:** activating a global version rebuilds every agent's bundle, as a chunked background job; activating an agent-specific version rebuilds only that agent's bundle.
  - A change to an agent's catalog file (its enablement, its observations, or an entry it lists) rebuilds its bundle, coalesced per agent; a change to an entry that many agents list rebuilds theirs in the same chunked job (T-80). P1-16 asks for these rebuilds through an interface defined here.
  - Each chunk's transaction writes the governance state last, so that it holds the version counter only to bump the version and commit (P1-07, step 5).
  - Blocks never rebuild bundles: they travel in the watch stream (P1-16, step 7).
  - Suspended agents' bundles are rebuilt too, so that a disable or a global forbid made during a suspension holds at reinstatement ([lifecycle](../../architecture/lifecycle.md), section 9).

**Done when:** the same effective set and catalog file always give the same content hash, and 1,000 bundles, each with its catalog file and schema, rebuild in under 60 seconds.

### 7. Distribution

- In the same transaction that stores a bundle, the agent's governance state gets the new bundle reference (through `govstate`, P1-07). Rebuilds run in chunks of at most 100 agents per transaction, one job at a time. Each chunk first locks each agent's row and then its state row, in ascending ID order, with `FOR NO KEY UPDATE`, and only then calls `StateVersions.Next` (the [design note](P1-08-kill-switch.md#progress-notes) of the halt path, section 2).
- `PolicyService.GetBundle` serves a bundle only to instances that serve that agent, with an ETag equal to the content hash.
- Bundle public keys are published on the machine listener.

**Done when:** a connected mock enforcement point receives, verifies and activates a new bundle, with its catalog file and schema (P1-07 teaches its mock module catalog files).

### 8. Drift detection

Acknowledgements and `bundle.activated` events record the bundle each instance runs. When an instance stays behind the current version longer than a threshold (2 minutes by default), the API, the console and a metric show drift, and an alert fires. A rejection shows with its reason, so an enforcement point that does not support catalogs (`invalid_manifest`, RFC-0002, section 5) is visible at once.

**Done when:** a mock enforcement point that withholds activation is flagged as drifting within the threshold.

### 9. Diff (Should)

A server-side unified diff between two versions, for the console.

**Done when:** the console can show what changed before approval.

### 10. Simulation (Could)

Evaluate a draft version, together with the current global set, against test inputs, using `cedar-go` or embedded OPA. It is advisory only: it shows what would happen, and enforcement stays at the edge. Tool and model inputs take their resource properties and arguments from the catalog, as enforcement points do, and the result gives the catalog check's reason before any policy is evaluated (RFC-0002, sections 7.1 and 7.2).

**Done when:** a policy author sees the decision and reasons for each test input.

### 11. Tests

- Separation of duties.
- The quorum: a version with fewer distinct approvals than its quorum stays submitted.
- The version state machine.
- Seeding, idempotent when two replicas start at once.
- The check of usage-rule statements: a hand-edited, missing or extra statement is refused, and so is a read of an argument policies cannot see.
- Schema generation: deterministic, and generated rules validate in strict mode.
- Deterministic bundles.
- Catalog files: in every bundle, deterministic, covered by the signature, and accepted by the kit's reference bundle verifier (`test/conformance/bundle`), which P0-03 step 12 extends to catalogs.
- Signature verification with the published keys.
- Rebuild performance, and rebuilds coalesced per agent.
- Drift detection.

**Done when:** all run in CI.

## Acceptance criteria

- An approved global policy and agent-specific policy produce a signed bundle that a connected mock enforcement point receives and activates within 5 seconds of approval; the version it runs is visible through the API.
- Drift is flagged when an instance does not activate a bundle.
- Activating a global version rebuilds 1,000 bundles, each with its catalog file and schema, in under 60 seconds.
- Validation rejects Cedar syntax errors with positions.
- No path lets an author approve their own version (tests).
- Every bundle carries its agent's catalog file and Cedar schema, both covered by the signed manifest; the mock enforcement point activates it, and an enforcement point without catalogs rejects it, keeping its last valid bundle or, with none, staying closed.
- A fresh installation has the seeded policies waiting for the steering committee; until they are approved, the actions they permit are denied unless another policy permits them.
- A version whose `@rule` statements differ from the generator's output, or that reads an argument policies cannot see, cannot be submitted.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-06-policy-model-and-distribution) pass: ST-31 to ST-33.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Strict validation, which usage rules rely on, is experimental in `cedar-go` (`x/exp/schema/validate`, outside semantic versioning) | Pin the version and call it from one place; re-check its results against `cedarpy` in CI, with the vectors shared with P1-09 ([engine mappings](../../contracts/engine-mappings.md), section 3) |
| The core's Cedar validator (cedar-go) and the enforcement point's evaluator (`cedarpy`) disagree on a language feature | Pin matching versions; the validator rejects features the enforcement point cannot evaluate; shared vectors run against both in CI (P1-09) |
| Global activations cause rebuild storms | Chunked job, and bundle references only change when the content hash changes |
| Tooling reports rebuild bundles, since the catalog file lists observed entries | Rebuilds coalesced per agent; no observation times in the file; a bundle reference changes only when the content hash changes |
| The catalog file grows with the agent's tooling: an entry like RFC-0002's example takes about 340 bytes, so the 4,096 tools of one report take about 1.4 MB of the 2 MiB that step V1 allows | The builder checks the limits of V1 and alerts (step 6); P1-16 keeps entries compact |
| A change to the generator makes earlier versions fail the `@rule` check, rollbacks included (POL-08) | Golden tests keep the generator's output stable; a change to its output is reviewed like a change to the contracts, since a rollback submits the old text again |
| `wt-catalog` and usage rules are Cedar, and a bundle holds one language | Rego bundles, for the engines of Phase 2, need equivalents |

## Notes for implementers

- Combination semantics live in the contract and in the test vectors, not in this package: the core distributes and never evaluates in the enforcement path.
- Store bundle contents by content hash, so identical sets share storage. `policy_bundles` is append-only, so every rebuild adds a row: storing files by hash lets a rebuild that changes only the catalog file store only that file (domain model, section 10).
- Keep policy text as uploaded (no reformatting), so its hash matches what the author signed off.
- Compare a `@rule` statement with the generator's output as parsed statements, not as bytes, so line endings and spacing never refuse a correct one.
