# P1-06: Policy model and distribution

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L |
| **Depends on** | P0-03 (decision profile, bundle format), P1-04 (can start once agent records and their API are merged, about two weeks into P1-04) |
| **Unblocks** | P1-09, P1-10.3 |
| **Requirements** | POL-01 to POL-10 |
| **Decisions** | ADR-0004, ADR-0005 |

## Goal

Global and agent-specific policies, written in a standard language, validated, approved by the right committee and never by their author, then compiled into a signed bundle per agent and delivered to every enforcement point. Which bundle each instance actually runs is always visible.

## Scope

**In:** policies and immutable versions, validation, the approval workflow, the activation guard used by the lifecycle, effective sets and signed bundles, distribution through the governance state, drift detection, diff, simulation.

**Out:** evaluation at runtime (the enforcement points: P1-09 and the mock module of P1-07); the catalog of accepted providers and jurisdictions (Phase 2).

## Deliverables

- `internal/policy` with its OpenAPI operations.
- Built-in validators for Cedar and Rego.
- The bundle builder and signer.
- Drift metrics and alerts.

## Steps

### 1. API first

Write the OpenAPI operations for policies, versions, validation, approvals, diff, effective policy per agent and bundle metadata. Review them with P1-10.3.

**Done when:** the operations are merged and agreed with the console side.

### 2. Policies and versions

- A policy has a scope (global, or agent-specific with its agent) and a language.
- Supported languages are those with a built-in validator (Cedar and Rego) that at least one approved enforcement module declares.
- Versions are immutable: content, SHA-256, author, creation time and a change note.
- Version states: draft, submitted, approved, active, superseded, rejected, withdrawn.

**Done when:** content cannot change once submitted (test), and the version states follow their table.

### 3. Validation (Should)

- **Cedar:** parse with `cedar-go`, and validate against the White Tower Cedar schema from P0-03 where the library supports it.
- **Rego:** compile with the OPA Go library against the published input document.
- **Policy tests:** optional test files with expected decisions run in the core. Results are attached to the version, and a version with failing tests cannot be submitted.

**Done when:** syntax errors are reported with line and column, and failing tests block submission.

### 4. Approval workflow

- Submitted versions are approved by the steering committee (global scope) or the advisory committee (agent scope).
- Separation of duties: the author never approves; the quorum is configurable and 1 by default. Rejections need a comment.
- Approval activates the version and supersedes the previous active one.
- Rollback creates a new version with earlier content, which needs approval again (POL-08).

**Done when:** every path is tested, including an author trying to approve through any role they hold.

### 5. Activation guard

Implement the interface P1-04 uses: an agent can be activated only if it has at least one active agent-specific policy (POL-04).

**Done when:** the lifecycle property tests run against the real implementation instead of the stub.

### 6. Effective sets and bundles

- The **effective set** of an agent is the active global versions plus its active agent-specific versions.
- The **bundle** follows the P0-03 format: a manifest with a monotonic version per agent, the combination algorithm ID and the entries with their hashes, plus the policy files. The serialization is deterministic, and the content hash is kept apart from the version.
- The manifest is signed with the bundle key (Ed25519, detached JWS) and the bundle stored in PostgreSQL.
- **Rebuilds:** activating a global version rebuilds every agent's bundle, as a chunked background job; activating an agent-specific version rebuilds only that agent's bundle.

**Done when:** the same effective set always gives the same content hash, and 1,000 bundles rebuild in under 60 seconds.

### 7. Distribution

- In the same transaction that stores a bundle, the agent's governance state gets the new bundle reference (through `govstate`, P1-07).
- `PolicyService.GetBundle` serves a bundle only to instances that serve that agent, with an ETag equal to the content hash.
- Bundle public keys are published on the machine listener.

**Done when:** a connected mock enforcement point receives, verifies and activates a new bundle.

### 8. Drift detection

Acknowledgements and `bundle.activated` events record the bundle each instance runs. When an instance stays behind the current version longer than a threshold (2 minutes by default), the API, the console and a metric show drift, and an alert fires.

**Done when:** a mock enforcement point that withholds activation is flagged as drifting within the threshold.

### 9. Diff (Should)

A server-side unified diff between two versions, for the console.

**Done when:** the console can show what changed before approval.

### 10. Simulation (Could)

Evaluate a draft version, together with the current global set, against test inputs, using `cedar-go` or embedded OPA. It is advisory only: it shows what would happen, and enforcement stays at the edge.

**Done when:** a policy author sees the decision and reasons for each test input.

### 11. Tests

- Separation of duties.
- The version state machine.
- Deterministic bundles.
- Signature verification with the published keys.
- Rebuild performance.
- Drift detection.

**Done when:** all run in CI.

## Acceptance criteria

- An approved global policy and agent-specific policy produce a signed bundle that a connected mock enforcement point receives and activates within 5 seconds of approval; the version it runs is visible through the API.
- Drift is flagged when an instance does not activate a bundle.
- Activating a global version rebuilds 1,000 bundles in under 60 seconds.
- Validation rejects Cedar and Rego syntax errors with positions.
- No path lets an author approve their own version (tests).
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#P1-06-policy-model-and-distribution) pass: ST-31 to ST-33.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| `cedar-go` lacks full schema validation | Parse-only validation plus policy tests; follow `cedar-go` releases |
| The core's Cedar validator (cedar-go) and the enforcement point's evaluator (`cedarpy`) disagree on a language feature | Pin matching versions; the validator rejects features the enforcement point cannot evaluate; shared vectors run against both in CI (P1-09) |
| Global activations cause rebuild storms | Chunked job, and bundle references only change when the content hash changes |

## Notes for implementers

- Combination semantics live in the contract and in the test vectors, not in this package: the core distributes and never evaluates in the enforcement path.
- Store bundle contents by content hash, so identical sets share storage.
- Keep policy text as uploaded (no reformatting), so its hash matches what the author signed off.
