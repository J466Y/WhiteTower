# P0-03: Module contracts v0.1

| | |
| --- | --- |
| **Phase** | 0 Foundations |
| **Status** | In progress: everything but the RFC review is done (see [progress notes](#progress-notes)) |
| **Size** | L |
| **Depends on** | P0-02 (entities, governance state record), P0-05 spike S1 (AGT facts) |
| **Unblocks** | P0-04, P1-07, P1-09, P1-15, and the Phase 0 gate |
| **Requirements** | MOD-01 to MOD-05, MOD-08, POL-03, POL-05, POL-06, KIL-03, KIL-04, KIL-07, KIL-10, AUD-02 |
| **Decisions** | ADR-0004, ADR-0005, ADR-0006, ADR-0011 |

## Goal

Versioned contracts that let any product be wrapped as a White Tower module: a manifest, a module API, a governance state and lease protocol, a policy decision profile, a bundle format and an event catalog. They are validated against Microsoft AGT and at least two other engines, and accepted through the project's first RFC. This plan produces the deliverable of the Phase 0 gate: **"Contracts v0.1 reviewed"**.

## Scope

**In:** capability taxonomy, manifest schema, module API (protobuf), governance state and lease semantics, decision profile and combination semantics, bundle format and signatures, event catalog, the design and skeleton of the conformance kit, the versioning policy, RFC-0001.

**Out:** the core implementation of the module API (P1-07), the full conformance kit (P1-07), the Python enforcement point (P1-09), the network quarantine module (P1-15), detailed contracts of Phase 2 and 3 capabilities (only their identifiers are reserved).

## Deliverables

- `docs/contracts/module-contract-v0.1.md`: the normative specification, written with RFC 2119 keywords (MUST, SHOULD, MAY).
- `api/manifest/module-manifest.schema.json`, with example manifests for the mock module, the Python enforcement point and the network quarantine module.
- `api/proto/whitetower/module/v1alpha1/*.proto`, with `buf.yaml` and `buf.gen.yaml`.
- `api/events/`: the catalog and one JSON Schema per event type.
- `test/conformance/vectors/`: language-neutral test vectors for combination semantics and fail-closed behavior.
- The conformance kit design, and a skeleton able to run one scenario.
- RFC-0001 accepted, and the tag `contracts/v0.1.0`.

## Steps

### 1. Capability taxonomy

Define an identifier and the responsibilities of each capability:

- **Fully specified in v0.1:** `enforcement-point` (applies governance at runtime, including halts), `policy-engine` (evaluates policies; may be embedded in an enforcement point, as in White Tower's Python enforcement point), `runtime-control` (acts on halts outside the agent's process, such as the network quarantine of KIL-10; evaluates no policy), `event-source` (publishes events).
- **Reserved, specified later:** `mcp-gateway`, `llm-gateway`, `skills-repository`, `harness`, `observability`, `compliance`, `discovery`, `identity-source`.

For each, list what the core expects from it, which RPCs and events it uses, and in which phase it is specified.

**Done when:** the taxonomy table is in the specification, and the charter's eight module types are all placed.

### 2. Manifest schema

JSON Schema (draft 2020-12) with `apiVersion`, `kind: ModuleManifest`, `metadata` (name, version, vendor, license, homepage) and `spec`: capabilities, supported contract versions, events emitted and consumed, endpoints the core may call (none are required in v0.1), permissions requested (for example, "watch the agents I serve", "publish these event types") and a JSON Schema for the module's own configuration.

**Done when:** both example manifests validate in CI, and invalid examples are rejected.

### 3. Module API (subplan candidate)

The protobuf services of the architecture document (`RegistryService`, `GovernanceService`, `PolicyService`, `EventService`), with normative semantics for:

- **Authentication:** bearer access tokens from the White Tower token endpoint, with the module API as audience.
- **Authorization:** an instance may only watch the agents it is bound to, and publish the event types its manifest declares.
- **Version negotiation:** the client lists the versions it supports and the server picks one.
- **Errors:** ConnectRPC codes, and which ones are retryable.
- **Retries:** jittered exponential backoff with a cap; idempotency keys on acknowledgements and event batches.
- **Limits:** message size, batch size, keepalives.

**Done when:** the protobuf files pass `buf lint`, and every method has normative text and a JSON example.

### 4. Governance state and leases

Wire model of the governance state record from P0-02: agent state (lifecycle state, run state, halt ID and reason, bundle reference with version, SHA-256 and signature, lease TTL, the labels needed locally), fleet state, lease renewal. Specify:

- the snapshot on connection, then changes ordered by version, and resumption from the last version seen;
- renewals every third of the TTL, and expiry computed on the EP's monotonic clock;
- the EP obligations of the architecture document (section 6): start closed, fail closed on expiry or halt, acknowledge, buffer durably, reconnect with backoff;
- halt acknowledgements that report each halt layer separately: gate closed, in-flight action interrupted, process terminated, and network quarantined for runtime-control modules. Spike S1 showed a kill callback reporting success while blocking work kept running, so the contract must not pretend any layer did more than it did.

**Done when:** the obligations are written as numbered MUST statements, each paired with a conformance scenario (step 8).

### 5. Policy decision profile (subplan candidate)

- **Request, aligned with AuthZEN Authorization API 1.0:** subject of type `agent`, with its SPIFFE ID, owner, environment, risk tier and labels, and a reserved on-behalf-of user for Phase 2; action; resource; context (task, trace, time).
- **Action taxonomy aligned with the intervention points agents actually have.** Microsoft AGT's policy runtime uses `agent_startup`, `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, `post_tool_call`, `output` and `agent_shutdown`. Names such as `agent.start`, `input.receive`, `model.invoke`, `model.result`, `tool.invoke`, `tool.result`, `output.emit` and `agent.stop` must be mappable one to one.
- **Resource types:** `tool`, `mcp_server`, `model`, `dataset`, `skill`, `agent`, `url`.
- **Response:** an AuthZEN boolean decision, with reasons, policy references and a reserved obligations field in `context`.
- **Combination semantics** of requirements section 5.4.1, with test vectors.
- **Fail-closed rules:** errors, timeouts, missing or unverifiable bundle, unknown agent, expired lease and halted run state all deny.
- **Policy languages.** Recommendation, confirmed by the P0-05 spike: **Cedar as the primary language**, because its "forbid overrides permit" and default-deny semantics are exactly POL-03, and a Cedar schema of White Tower entities lets policies be validated before approval. **Rego as the second language**, with a standard decision wrapper implementing the same semantics. Publish the Cedar schema and the Rego input document as part of the profile.

**Done when:** the vectors cover every combination rule and every fail-closed condition, and each has an expected decision and reason.

### 6. Bundle format and signatures

- **Manifest (JSON):** bundle version, monotonic per agent; agent ID; combination algorithm ID; the list of policies, each with ID, version, scope, language, SHA-256 and path; creation time.
- **Contents:** the policy files.
- **Signature:** a detached JWS over the manifest with an Ed25519 key ID; public keys published by the core on the machine listener.
- **Rules:** EPs MUST verify the signature and every file hash, MUST refuse a bundle older than the active one (rollback protection), and MUST deny everything while they have no valid bundle.
- **Packaging:** one archive or one JSON document; the choice is made here.

Enforcement points fetch bundles through `GetBundle`. Engines that load policies themselves, such as AGT or OPA, get the verified content from their adapter.

**Done when:** a signed example bundle and a tampered copy exist as test vectors.

### 7. Event catalog (subplan candidate)

- **CloudEvents envelope rules:** `source` URI scheme for instances; unique `id` per source; `time`; `subject` set to the White Tower agent ID; `dataschema`; extensions `wtseq` (per-source sequence) and W3C trace context.
- **Types emitted by EPs:** `decision.made`, `action.executed`, `instance.started`, `instance.halted`, `bundle.activated`, `bundle.rejected`, `lease.expired`. **Types emitted by runtime-control modules:** `quarantine.applied`, `quarantine.lifted`. **Types emitted by the core:** lifecycle, policy, halt and checkpoint events.
- **Delivery:** at-least-once, de-duplicated on source and ID, ordered per source by `wtseq`.
- **Mapping from AGT,** for the Phase 2 adapter: AGT emits CloudEvents 1.0 (types `ai.agentmesh.*` and `ai.agentos.*`). Document how they map, keeping the original type in an extension attribute.

**Done when:** every event type has a schema and a valid example, both checked in CI.

### 8. Conformance kit design (subplan candidate)

The kit plays the core: a fake token endpoint, a watch server, a bundle server and an event sink, driven by scripted scenarios. Minimum scenarios:

- the EP allows nothing until it has state;
- lease expiry leads to deny and halt within the TTL plus a tolerance;
- a halt is acknowledged within the target, with each layer reported;
- reconnecting while halted stays halted;
- an unsigned, tampered or older bundle leads to deny;
- the combination vectors produce the expected decisions;
- events are schema-valid with a monotonic `wtseq`;
- reconnection uses backoff;
- a runtime-control module never lifts a quarantine without fresh state from the core.

Implement the skeleton in Go under `test/conformance`, speaking the module API over the network so an EP in any language can be tested. The full implementation happens in P1-07.

**Done when:** one scenario runs end to end against a stub.

### 9. Validate against real engines

Map v0.1 onto:

- **Microsoft AGT**, from the P0-05 spike: an in-process EP and policy engine; a cooperative kill; CloudEvents audit. White Tower's own enforcement point (ADR-0011) implements the contracts first, so these mappings are what keep the contracts from being shaped like it.
- **OPA:** bundles, decision logs and the status API; AuthZEN through an adapter, since OPA declined native support.
- **Cedar** (cedar-go, or a Cedar agent).
- **An engine with native AuthZEN** (Cerbos or Topaz).

Record gaps and change the contracts where needed. Record in the risk register that Galileo Agent Control, named in the charter, was acquired by Cisco in 2026. Prefer foundation-hosted or clearly independent engines for the Phase 2 module replacement demonstration.

**Done when:** a mapping table per engine shows no blocking gap, or each gap has an agreed resolution.

### 10. Versioning and compatibility policy

Rules for `v1alpha1`, `v1beta1` and `v1`: deprecation windows, the `buf breaking` configuration, a compatibility matrix template (core version × contract version × module version), and what a module must do with unknown fields and event types (ignore and continue, never fail open).

**Done when:** the policy is in the specification and the CI checks from P0-01 enforce it.

### 11. RFC-0001, "Module contracts v0.1"

Write the RFC and circulate it to the maintainers and at least one external reviewer, ideally someone who runs AGT or builds a gateway. Hold a review period of at least two weeks, resolve every comment, accept it and tag `contracts/v0.1.0`.

**Done when:** RFC-0001 is accepted; this closes the main criterion of gate G0.

## Acceptance criteria

- RFC-0001 accepted by the maintainers, with at least one external review.
- `buf lint` passes; manifest and event examples validate against their schemas in CI.
- The test vectors cover every combination rule and every fail-closed condition.
- Mapping tables for AGT and two other engines show no unresolved blocking gap.
- The conformance kit skeleton runs one scenario against a stub module.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| The contracts end up shaped like White Tower's own enforcement point (ADR-0011), or like AGT | Step 9 maps them onto AGT, OPA, Cedar and an AuthZEN engine before the RFC |
| Over-specifying later capabilities | Only reserve identifiers for Phase 2 and 3 capabilities |
| AGT's policy runtime changes its verdict set (allow, deny, transform) before GA | Keep `transform` and approval flows out of v0.1 (reserved obligations field); decisions stay booleans |
| Streaming is hard for simple modules | The Connect protocol allows plain HTTP; the conformance kit documents a minimal client |

## Notes for implementers

- Keep v0.1 small: four services and about ten event types.
- Write every obligation as a numbered MUST with a scenario in the kit; an obligation nobody tests will be broken.
- Reference implementations of signed notes and JWS exist in Go (`golang.org/x/mod/sumdb/note`, `go-jose`); use them in the test vectors to avoid homemade formats.

## Progress notes

### 2026-09-29: contracts v0.1 drafted, ready for the RFC review

The normative specification is [module-contract-v0.1.md](../../contracts/module-contract-v0.1.md), proposed in [RFC-0001](../../rfcs/0001-module-contracts-v0.1.md).

| Step | Status | Result |
| --- | --- | --- |
| 1. Capability taxonomy | Done | Four capabilities specified (`enforcement-point`, `policy-engine`, `runtime-control`, `event-source`), eight reserved; the charter's eight module types all placed |
| 2. Manifest schema | Done | Schema, three valid examples and seven invalid ones, checked in CI by `test/contracts` |
| 3. Module API | Done | Four services plus server information; `buf lint` clean; normative text and a JSON example for every method (appendix A) |
| 4. Governance state and leases | Done | Obligations EP-1 to EP-12, RC-1 to RC-6, I-1 to I-6, MAN-1 to MAN-4 and CORE-1 to CORE-9; every module obligation has a scenario. The P0-02 record gained the halt mode and the policy attributes (schema checks still pass on PostgreSQL 16 and 17) |
| 5. Decision profile | Done | Cedar schema; AuthZEN request and response schemas; 20 combination and 13 fail-closed vectors, passing on `cedar-go` 1.8.0 and on `cedarpy` 4.12.1; Rego wrapper checked with OPA 1.21. One deliberate difference from Cedar: an evaluation error always denies |
| 6. Bundle format | Done | One JSON manifest (RFC 8785) with a detached JWS (EdDSA); 15 signed vectors, including tampered, unsigned, forged and older bundles, verified in Go and in Python |
| 7. Event catalog | Done | 15 types, each with a schema and an example, validated in CI; privacy rules for arguments, prompts and outputs |
| 8. Conformance kit design | Done | Kit design, driver protocol and 16 scenarios; the skeleton runs S-01 end to end against a Go stub over HTTP/2 with TLS |
| 9. Real engines | Done | [engine-mappings.md](../../contracts/engine-mappings.md): AGT, OPA, Cedar, Cerbos and Topaz; no blocking gap |
| 10. Versioning policy | Done | Section 10 of the specification; CI now compares the protobuf files with the latest `contracts/v*` tag |
| 11. RFC-0001 | In progress | Draft written. Next: open the review for at least two weeks with an external reviewer, resolve the comments, accept, and tag `contracts/v0.1.0` |
