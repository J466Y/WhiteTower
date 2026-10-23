# P0-03: Module contracts v0.1

| | |
| --- | --- |
| **Phase** | 0 Foundations |
| **Status** | In progress: RFC-0001 is accepted provisionally (2026-10-23). Its changes to `api/`, then, once RFC-0002 is accepted, step 12 and the tag remain (see [progress notes](#progress-notes)) |
| **Size** | L |
| **Depends on** | P0-02 (entities, governance state record), P0-05 spike S1 (AGT facts); RFC-0002 accepted, for step 12 |
| **Unblocks** | P0-04, P1-07, P1-09, P1-15, and the Phase 0 gate; through step 12, the parts of P1-06, P1-07, P1-09 and P1-16 that build on RFC-0002 |
| **Requirements** | MOD-01 to MOD-05, MOD-08, POL-03, POL-05, POL-06, KIL-03, KIL-04, KIL-07, KIL-10, AUD-02; through step 12, the contract side of CAT-01, CAT-04 to CAT-07 and CAT-10 |
| **Decisions** | ADR-0004, ADR-0005, ADR-0006, ADR-0011, [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) |

## Goal

Versioned contracts that let any product be wrapped as a White Tower module: a manifest, a module API, a governance state and lease protocol, a policy decision profile, a bundle format and an event catalog. They are validated against Microsoft AGT and at least two other engines, and accepted through the project's first RFC. This plan produces the deliverable of the Phase 0 gate: **"Contracts v0.1 reviewed"**.

## Scope

**In:** capability taxonomy, manifest schema, module API (protobuf), governance state and lease semantics, decision profile and combination semantics, bundle format and signatures, event catalog, the design and skeleton of the conformance kit, the versioning policy, RFC-0001, and RFC-0002 folded into the contracts before the tag (step 12).

**Out:** the core implementation of the module API (P1-07), the full conformance kit (P1-07), the Python enforcement point (P1-09), the network quarantine module (P1-15), detailed contracts of Phase 2 and 3 capabilities (only their identifiers are reserved).

## Deliverables

- `docs/contracts/module-contract-v0.1.md`: the normative specification, written with RFC 2119 keywords (MUST, SHOULD, MAY).
- `api/manifest/module-manifest.schema.json`, with example manifests for the mock module, the Python enforcement point and the network quarantine module.
- `api/proto/whitetower/module/v1alpha1/*.proto`, with `buf.yaml` and `buf.gen.yaml`.
- `api/events/`: the catalog and one JSON Schema per event type.
- `test/conformance/vectors/`: language-neutral test vectors for combination semantics and fail-closed behavior.
- The conformance kit design, and a skeleton able to run one scenario.
- RFC-0001 accepted, RFC-0002 folded in (step 12), and the tag `contracts/v0.1.0`.

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

Write the RFC and review it as [GOVERNANCE.md](../../../GOVERNANCE.md#rfc-process) says: resolve every point the review raises, and accept it. While the project has a single maintainer and no external reviewer, the maintainer reviews it and accepts it provisionally, with no minimum period, and the RFC keeps the record of the review (the maintainer's decision of 2026-10-21). An external reviewer, ideally someone who runs AGT or builds a gateway, reviews it before the contracts leave alpha (`v1beta1`). The tag `contracts/v0.1.0` waits for step 12.

**Done when:** RFC-0001 is accepted, provisionally while the project has no external reviewer; with step 12 and the tag, this closes the main criterion of gate G0.

### 12. RFC-0002 in the contracts (once RFC-0002 is accepted, before the tag)

[RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) lands in `v1alpha1` before `contracts/v0.1.0` is tagged, so its changes that are not additive need no `v1alpha2` (specification, section 10). P1-06, P1-07, P1-09 and P1-16 build on it, so it comes first.

- **Specification:** the text of RFC-0002 goes into new sections (4.10, 5.10, 6.9 to 6.11 and 7.7), so that no section other documents cite changes its number, together with the changes it makes to sections 2, 4.3, 4.4, 4.8, 5.1, 5.2, 5.4, 5.7, 5.9, 6.3, 6.4, 6.6, 6.7, 7.1, 7.4, 8.5 and 9 to 12, and to the appendices. It supersedes the `ToolArgs` extension point of section 6.7, and closes the question of section 12 on tool arguments.
- **Protobuf:** `RegistryService.ReportTooling` and `RegistryService.ReportDefinitions`, and the blocks record of the watch stream (`Block`, in snapshots and in changes). Schemas and annotations travel as JSON text, never as `google.protobuf.Struct`, whose numbers would change definition hashes. The kit's fake core gains the new methods in the same pull request, because it embeds no unimplemented handler; P1-07 gives them the behavior its scenarios need.
- **Decision profile (`api/policy`):** the action `tool.expose`, the `catalog.*` reasons, the kind `builtin`, the properties and context fields, per-tool argument records, the Cedar schema of RFC-0002 section 7.6, the manifest's `catalog` field, and a JSON Schema of the catalog file (`whitetower.catalog.v1`).
- **Manifest (`api/manifest`):** `tool.expose` among the actions an enforcement point must declare, with `tool.invoke` and `model.invoke`, and the examples updated.
- **Events (`api/events`):** `tool.expose` and the `catalog.*` reasons in `common.schema.json`; the usage rules that decided, named by policy and rule, and the resource's origin in `decision.made`; the origin in `action.executed`, whose `decision_id` becomes optional for provider-run calls. Without them, ingestion refuses the enforcement point's new events. The new core event types of RFC-0002, section 9, are P1-16's.
- **Vectors:** references and their string forms, redaction, definition hashes, the catalog check (blocks included), arguments and transforms, exposure, and bundles with a catalog file; the combination vectors that use a tool or a model gain a catalog and per-tool records. Both stacks pass them: the Go profile (`test/conformance/profile`) and the Python checker (`test/conformance/python/check_vectors.py`). The reference bundle verifier (`test/conformance/bundle`) learns the catalog file.

The specification text is reserved for the reviewer ([AGENTS.md](../../../AGENTS.md)); the protobuf, the schemas and the vectors follow it.

**Done when:** `task verify:gen` passes, both stacks pass every vector, the specification, `api/` and the vectors agree with RFC-0002 as accepted, and `contracts/v0.1.0` is tagged.

## Acceptance criteria

- RFC-0001 accepted as GOVERNANCE.md's RFC process says: provisionally by the maintainer while the project has no external reviewer, with the record of the review in the RFC.
- RFC-0002, once accepted, is in the specification, `api/` and the vectors before the tag, and both stacks pass its vectors.
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
| Streaming is hard for simple modules | The Connect protocol allows plain HTTP, with HTTP/2 for `Watch`; appendix A shows its framing, and the kit documents a minimal client (P1-07 step 9) |

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

### 2026-09-30: changes before the review opens

The draft changed after the spikes and the [threat model](../../security/threat-model.md). The review of RFC-0001 covers these changes like the rest:

| Change | Source | Where |
| --- | --- | --- |
| Reconnection backoff bounded by the lease, and reset after a renewal | Spike S2 | I-4, scenario S-12 |
| The enforcement point of a halted or suspended agent still gets tokens for the module API | Threat model, DC-1 | CORE-8, section 11 |
| A lease renewal counts only if it is fresh: it carries the core's time, and an instance ignores one older than its tolerance, 5 seconds by default | Threat model, DC-2 | Sections 4.8, 5.2, 5.3 and 11; `LeaseRenewal.server_time`; scenario S-17, which runs end to end against the stub |
| No DNS during network quarantine | Threat model, DC-7 | Section 12 |

### 2026-09-30: approved by the maintainer

The maintainer reviewed the specification and approved RFC-0001, and agreed to settle each open question of section 12 when the work that needs it starts. While the project has a single maintainer, acceptance also needs an external reviewer, after a review of at least two weeks from the day the RFC is announced ([GOVERNANCE.md](../../../GOVERNANCE.md)). Then the RFC is accepted and `contracts/v0.1.0` is tagged. Only P1-07 needs the accepted contracts; the other Phase 1 plans can start before.

### 2026-10-02 and 2026-10-09: changes from P1-01 and P1-02

Two plans changed the specification as they built on it, and recorded the changes in their own progress notes. The review of RFC-0001 found them missing here, so this entry, written on 2026-10-23, lists them. That review covered them like the rest:

| Change | Source | Where |
| --- | --- | --- |
| A message's size is that of its encoding in the call, once decompressed. The core refuses a larger request with `RESOURCE_EXHAUSTED` and never sends a larger message, and a message over the limits is never retried as it is | P1-01, step 6 ([progress notes](../phase-1/P1-01-core-platform-skeleton.md#progress-notes), 2026-10-02) | Sections 4.6 and 4.8 |
| The core's events carry the ID of the request that made the change, in the extension attribute `wtrequestid` | P1-02, step 1 ([progress notes](../phase-1/P1-02-audit-log.md#progress-notes), 2026-10-09) | Section 8.2; `cloudevent.schema.json` |

### 2026-10-19: RFC-0002 joins the contracts before the tag

The maintainer brought the MCP servers, tools and models of agents into the MVP (decision of 2026-10-13), and [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) proposes the contract changes. Its follow-up added step 12: RFC-0002 lands in `v1alpha1` before the tag, and the tag waits for it. With it, P1-06, P1-09 and P1-16 also build on the contracts: their parts that need RFC-0002 wait for step 12.

| Pull request | Content | Status |
| --- | --- | --- |
| 1. Specification text | RFC-0002 in the specification (reserved for the reviewer) | Waits for RFC-0002's acceptance |
| 2. Protobuf, schemas and examples | `api/proto`, `api/policy`, `api/manifest`, `api/events`, and the kit's fake core | Not started |
| 3. Vectors on both stacks | The new vectors, the rewritten combination vectors, the Go profile, the Python checker and the reference bundle verifier | Not started |

### 2026-10-20: changes from the halt-path design

The maintainer accepted the [design of the halt path](../phase-1/P1-08-kill-switch.md#progress-notes) on 2026-10-20. Its decisions 2 and 6 change the contracts while RFC-0001 is in review, when changes are free (specification, section 10). The external review of RFC-0001 covers these changes like the rest:

| Change | Source | Where |
| --- | --- | --- |
| A halt applies wherever the instance runs: no field of `Halt` limits where it applies, and an unknown field never narrows a halt. A new field that narrows halts stays in the version only because an instance that ignores it halts more | Decision 2 | Sections 5.1 and 10, EP-10, scenarios S-05, S-06 and S-13; the comments of `AgentState.halts`, `FleetState.halts` and `Halt` in `governance.proto` |
| A selector halt names risk tiers and at most 16 labels, never an environment | Decision 2, and P1-08 step 1 for the bound | `$defs.selector` in `api/events/schemas/common.schema.json` |
| An instance applies every agent state a change carries, whatever that state's own version, since an agent that enters the scope keeps its older version | Decision 6 | Section 5.2, EP-9, scenario S-12 |
| A failure of an established `Watch` stream, one that has delivered its first message, is transient whatever its code, except `PERMISSION_DENIED`, and `UNAUTHENTICATED`, which needs a new token first. Before then, an error that the core sends follows the error table, while a failure that the instance's own library reports is transient, such as connect-go's `INVALID_ARGUMENT` for a stream cut in the middle of a message | Decision 6 | Section 4.6, EP-9, scenario S-12 |
| A renewal's version may pass versions that carried nothing for the stream | Decision 6 | CORE-6, scenario S-12 |
| The core may answer any resumption with a snapshot, including one at a version it moved forward after a regression | Decision 6 | CORE-5, scenario S-12 |

RFC-0001 sums up the watch stream in words these changes keep true (Proposal, item 2), so that item does not change.

Decision 7, of the same day, has the core tell each instance the environment of its credential. The external review of RFC-0001 covers it too:

| Change | Source | Where |
| --- | --- | --- |
| The core returns, in `RegisterInstanceResponse`, the environment recorded for the credential the instance registered with, and refuses with `PERMISSION_DENIED` to register an enforcement point whose credential has none | Decision 7 | MAN-5, section 4.6 and appendix A; `RegisterInstanceResponse.environment` and the enum `Environment` in `registry.proto` |
| An enforcement point puts in the subject of every decision the environment its registration returned, never one from its configuration or from its access token. It treats a registration that returns none, or one it does not know, as refused, and allows nothing | Decision 7 | I-7, section 6.2, and scenario S-25, numbered after RFC-0002's S-18 to S-24; the description of `environment` in `api/policy/decision-request.schema.json` |

RFC-0001's count of scenarios (Proposal, item 7) becomes 18, with S-25, and the kit's [README](../../../test/conformance/README.md) counts sixteen designed scenarios rather than fifteen.

Besides the core's side, which P1-07 builds with registration and P1-05 step 7 with module credentials, and the console's, which P1-10.5 builds (section 14 of the design), decision 7 leaves work for two plans:

- **P1-07.2:** the kit's fake core returns the environment at registration, and the kit runs S-25. `WT_CONFORMANCE_ENVIRONMENT` in the [driver protocol](../../../test/conformance/driver-protocol.md), and `Config.Environment` of the stub enforcement point (`test/conformance/stubep`), give way to it, and the driver protocol's `POST /v1/decide` has the module build the subject from its state and its registration, not its credential.
- **P1-09:** the enforcement point takes the environment of its decisions from its registration (I-7), never from its configuration or from its access token, and passes S-25.

### 2026-10-21: a scenario for every module obligation

The contract says that the obligations of modules each have a conformance scenario (section 1), and so did the notes of 2026-09-29 (step 4), but nine had none in the table of section 9.3: I-1, I-2, I-5, I-6, EP-11, EP-12, RC-1, RC-5 and RC-6. The maintainer asked on 2026-10-21 to close the gap before the external review of RFC-0001. Four new scenarios cover eight of them:

| Scenario | What it checks | Obligations |
| --- | --- | --- |
| S-26 | The module calls only a core whose certificate chains to the trust anchors from its configuration, and an enforcement point inside an agent authenticates as that agent and serves it only | I-1, EP-11 |
| S-27 | The module registers before any other call, also after a restart; it deregisters before the restart, and rolls its token over on a replacement stream | I-2, I-5 |
| S-28 | The module's heartbeats follow the interval the core sets, and an enforcement point acknowledges the state version it applied at least every 60 seconds while that state changes | I-6, EP-12 |
| S-29 | A runtime-control module applies its layer to every halted agent in scope, whether by an agent, a selector or a fleet halt, including a workload started after the halt, and emits its events when it applies or lifts the layer | RC-1, RC-5 |

Two existing scenarios grow by a sentence each. S-15 also checks the ninth, RC-6, with the second sentence of I-6: a runtime-control module's heartbeats report as served agents those that have workloads it controls. S-09 also checks the bundle keys of EP-11: the fake core's `GetBundleKeys` lists the key that signs the `unknown-key` vector, and the module must still reject that vector.

I-2, and the deregistration of I-5, are recommendations (SHOULD), so S-27 reports a module that does not follow them, and does not fail it. Every module obligation, I-1 to I-7, EP-1 to EP-12 and RC-1 to RC-6, now appears in the obligations of at least one scenario. RFC-0001's count of scenarios (Proposal, item 7) becomes 22, the kit's [README](../../../test/conformance/README.md) counts twenty designed scenarios rather than sixteen, and P1-07 builds the kit with S-01 to S-29. The external review of RFC-0001 covers these scenarios like the rest.

The kit's skeleton cannot drive them yet. P1-07.2 adds what they need:

| Addition | Scenarios |
| --- | --- |
| The fake core records every call it receives, with its time, its method, its instance, the identity of its token and what it carries, and when each stream ends. Today it keeps registrations, acknowledgements and events, without their times | S-15, S-26, S-27, S-28 |
| The kit makes two certificate authorities: the trust anchor it names in `WT_CONFORMANCE_CA_FILE`, and another, which issues the certificate the fake core serves first. The skeleton's tests serve the fake core with the test certificate of Go's `net/http/httptest` | S-26 |
| `GetBundleKeys` also lists the untrusted key of the bundle vectors. Today it lists only the trusted key | S-09 |
| The fake token endpoint, which the [driver protocol](../../../test/conformance/driver-protocol.md) says P1-07 adds, issues tokens that expire within a minute. The fake core ends each stream with `UNAUTHENTICATED` when its token expires (CORE-1), and keeps two streams per instance, ending the oldest with `ABORTED` when a third opens, as the core does (CORE-16, P1-07 step 5) | S-26, S-27 |
| The fake core sets the heartbeat interval at registration and changes it in heartbeat responses. Both are 30 seconds today | S-28 |
| The fake core changes the fleet state, which never changes today | S-29 |
| The driver protocol gains endpoints for runtime-control modules: start and stop a workload of an agent, and tell whether the module's layer covers it, as the platform shows it rather than as the module reports it | S-15, S-29 |
| The kit's report shows, apart from failures, the recommendations a module does not follow, and the scenario still passes. The report that P1-07 step 9 plans, JUnit XML and a readable one, has no such outcome yet | S-27 |

S-27 restarts the module through `POST /v1/restart`, which the driver protocol already plans.

### 2026-10-22: a provisional review of RFC-0001

Nobody outside the project follows its RFCs yet: there is no second maintainer, no external reviewer and no community. A review period would bring no comments, and nobody could give the second approval. So on 2026-10-21 the maintainer decided that, until one of them appears, RFCs are accepted provisionally ([GOVERNANCE.md](../../../GOVERNANCE.md#rfc-process)):

- the maintainer reviews the RFC and decides every point the review raises, with no minimum review period;
- the RFC keeps the record of that review: each point, and how it was resolved;
- once a second maintainer, an external reviewer or a community appears, RFCs go back to a review of at least two weeks with an external reviewer, and every RFC accepted provisionally gets that review before the contracts leave alpha (`v1beta1`).

The review of RFC-0001 covered the specification as it stands, with every change since the approval of 2026-09-30, from seven perspectives: a module author, security, a policy engine, operations, standards, an implementer, and consistency with the other documents. It raised 39 points, 3 of them blocking, 13 major and 23 minor, and 11 editorial corrections. The maintainer decided every point on 2026-10-21 and 2026-10-22, each time with the recommended option, except for point 5: the core ends the oldest of an instance's three streams, so that a dead stream it has not noticed never refuses a live reconnection.

| Pull request | Content | Status |
| --- | --- | --- |
| 1. Provisional review | The rule in GOVERNANCE.md, the status and review period of both RFCs, and the governance part of point 38 | Done |
| 2. The watch stream, leases and instances | Points 1, 5, 11, 18, 25, 26 and 29 | Done |
| 3. Authentication, authorization and transport | Points 4, 6, 8, 23 and 30 | Done |
| 4. Decision profile and policies | Points 2, 15, 17, 19, 24, 31, 32 and 37 | Done |
| 5. Manifests, bundles and versions | Points 9, 13, 14, 16, 20, 21 and 39 | Done |
| 6. Events and halt reports | Points 3, 7, 10, 12, 22, 27, 28, 35 and 36 | Done |
| 7. Conformance, runtime control and the rest | Points 33 and 34, the rest of point 38, and the editorial corrections | Done |
| Code parts | What follows each part of the text in `api/`, the vectors, the stub and the kit, as parts for the coding agents | Queued: AGENTS.md, rows 2 to 11 |
| Last. Acceptance | The record of the review in RFC-0001, the commit of the accepted text, the roadmap's summary and risks of the reviews, and step 11 closed | Done |

RFC-0002's review follows, the same way.

The governance part of point 38 comes with the rule: GOVERNANCE.md, CONTRIBUTING.md, the index of RFCs and section 10 name `api/policy` and what the vectors expect among the changes that need an RFC. The rest of point 38, in RFC-0001 and the specification, is a correction like the others. The RFC template gains a section for the record of the review, and gate G0 of the roadmap asks for both RFCs accepted, provisionally while the rule applies. The comment at the top of `.github/CODEOWNERS` still names three directories, and is the maintainer's to change.

### 2026-10-22: corrections, part 1: the watch stream, leases and instances

The first part of the corrections changes the specification where the halt path meets the module API, as the maintainer decided points 1, 5, 11, 18, 25, 26 and 29 of the review:

| Point | Change | Where |
| --- | --- | --- |
| 1 | An instance keeps the highest version it applied, across all its streams, and never lowers it, so the two streams of a token rollover cannot undo a halt, even on two replicas. A lease belongs to the instance, not to a stream, and outlives a reconnection; "session" is gone. The core renews right after a resumed stream catches up, and may withhold renewals while it cannot show that it is current. The parts of a snapshot are consecutive | I-2, I-3, sections 5.2 and 5.3, CORE-6, EP-9, RC-2 and section 11; KIL-07, aligned with S-07; RFC-0001's reading of ADR-0005, decision 6 |
| 5 | An instance is one process: its key is unique to the process and stays the same across restarts (I-8), and appendix A no longer uses a host name. An instance belongs to the principal that registered it, and every call that names an instance must be that principal's (CORE-2). The core keeps at least two streams per instance and may end the oldest when another opens (CORE-16), the maintainer's option B, so that a dead stream it has not noticed never refuses a live reconnection | Sections 4.3, 4.4, 4.6, 4.8, 4.9 and 5.2, appendix A |
| 11 | A stream silent for the renewal interval plus 5 seconds has failed, and the instance reconnects on a new connection (I-9). The core accepts client PINGs every 10 seconds (CORE-14), and no rate limit refuses a halt acknowledgement (CORE-15). I-4 bounds the session calls, a library's own backoff included, and the other calls get a backoff of their own, capped at 60 seconds. `RESOURCE_EXHAUSTED` may carry `RetryInfo`, unary calls carry deadlines, and tokens are renewed between half and four fifths of their lifetime | Sections 4.1, 4.2, 4.6, 4.7, 4.8, 5.2 and 5.8; RFC-0002, section 4 |
| 18 | A renewal more than the tolerance before or after the instance's clock renews nothing, and the tolerance is at most 30 seconds | Sections 4.8, 5.3 and 11 |
| 25 | An instance bounds what the core sends: a lease TTL above 300 seconds counts as 300, and a zero or absent one renews nothing; a snapshot whose first part lacks the fleet state is malformed; a missing heartbeat interval keeps the one in force; a state that stops naming a bundle closes the gate; and the backoff's cap never falls below its first step | I-4, I-6, sections 5.2 and 5.3, EP-7; scenario S-30 |
| 26 | Loss depends on the kind of instance: one that watches, with an agent in scope, is lost once it has held no stream for the shortest TTL in its scope, whatever its heartbeats; any other after three heartbeat intervals without a heartbeat or a stream. A heartbeat carries the served agents when they changed since the last call the core accepted | CORE-4, section 4.4 |
| 29 | An enforcement point closes its gate before it deregisters (I-5). A version claimed above the core's is no evidence of lost changes | I-5, section 4.4 and section 11 |

The scenarios follow. S-12 adds a core black-holed by a TCP proxy, and a core that refuses connections for over two minutes. S-17 adds a renewal from the future. S-27 adds two replicas of the core one read apart, in both orders, a deregistration that closes the gate, and the keys of two processes of the module. S-30 is new, for values out of range. The new obligations of modules have their scenarios: I-8 in S-27, and I-9 in S-12. RFC-0001 counts 23 scenarios, and the kit's README twenty-one designed.

The design note of the halt path follows in [P1-08](../phase-1/P1-08-kill-switch.md#progress-notes) (its note of 2026-10-22), and so do P1-07 (the key per module and principal, the instance check on every call, the heartbeat interval in every response, pings, `RetryInfo`, and the columns that lost instances need) and P1-09 (a key per process, the version applied, the silence of a stream, the two backoffs and the bounds). The threat model becomes version 0.1.4: T-31, T-32 and T-37 change, T-84 is new, AT-1, AT-6 and AT-7 gain leaves, and DC-2 checks both ways. The security test catalog becomes version 0.1.3: ST-35 and ST-38 change, and ST-86 is new, for P1-08.

What follows in `api/` and the conformance kit is a part for the coding agents ([AGENTS.md](../../../AGENTS.md), work queue):

- comments only in `governance.proto` and `registry.proto`, then `task gen`: `WatchResponse.version` (the version applied never goes back), `LeaseRenewal.server_time` (the tolerance both ways), the agent state's `lease_ttl` (its bounds), the ends of a `Watch` stream and their codes (section 4.6, CORE-1, CORE-7, CORE-16), `instance_key` (unique to the process, the same across restarts, a random ID rather than a pod name), the heartbeat interval (in every response), the served agents (when they changed since the last call the core accepted), and `DeregisterInstance` (the gate closes first);
- the stub enforcement point (`test/conformance/stubep`) follows sections 5.2 and 5.3 and EP-7: it never lowers the version it applied, checks `server_time` both ways, bounds the lease TTL, refuses a snapshot whose first part lacks the fleet state, and deactivates its bundle when the state stops naming one;
- S-17 gains the renewal from the future.

P1-07.2 adds to the kit what the other scenarios need:

| Addition | Scenarios |
| --- | --- |
| A TCP proxy between the module and the fake core, which can drop traffic without closing connections, and refuse new ones | S-12 |
| The fake core plays two replicas one read apart, each serving its own stream | S-27 |
| The driver protocol gains an endpoint that starts one more process of the module, with an evidence buffer of its own, as a deployment that scales out would | S-27 |
| The fake core sends values out of range: a lease TTL of an hour, zero and absent TTLs, a snapshot whose first part lacks the fleet state, heartbeat responses without an interval or with zero, and a state that stops naming a bundle | S-30 |

Step 12 extends two of these rules to what RFC-0002 adds: the first part of a snapshot also carries the blocks, and CORE-2's check of the instance covers `ReportTooling` and `ReportDefinitions`.

### 2026-10-22: corrections, part 2: authentication, authorization and transport

The second part follows the maintainer's decisions on points 4, 6, 8, 23 and 30 of the review:

| Point | Change | Where |
| --- | --- | --- |
| 4 | An instance checks the core's certificate as HTTPS does: it chains to the configured anchors and is valid for the host of the core's configured URL, also when the instance dials an address it kept | I-1, section 11; S-26 |
| 6 | A failure of the call refuses the whole call, and a failure of one item decides that item only: an `Acknowledge` item about an agent outside the scope is counted and not recorded, and a `Publish` event outside the rules is rejected on its own. An agent that leaves the scope loses its state and its lease at once (I-11), and the gate closes with `gate.no_state`. `PERMISSION_DENIED` from `RegisterInstance` or `Watch` ends every lease at once, and the instance registers again with backoff, never treating the code as final; a version or a manifest hash that registration refuses follows the same rule | CORE-2, sections 4.6, 5.2, 5.4 and 8.4; S-02 and S-12 |
| 8 | Token requests follow one profile (I-10): the issuer and its metadata, the client ID of each identity, an assertion whose `aud` is the issuer identifier alone, the module API's resource, `expires_in`, and what an OAuth error means. Workload identity stays out of `v1alpha1` until P1-05 profiles it | Section 4.2; scenario S-31 |
| 23 | `Watch` uses HTTP/2, and the core refuses it over HTTP/1.x. The contract names the version of the Connect protocol, says where a stream's error travels, and that a body without an end-of-stream message is a cut; appendix A shows the framing. An intermediary that buffers streams makes every lease run out | Sections 4.1 and 4.6, appendix A; RFC-0001 |
| 30 | Revoking a credential stops new tokens, and tokens already issued stay valid until they expire. Removing a bundle key from an enforcement point's configuration revokes it, and the enforcement point verifies its active bundle again when its keys change. Keys learned from the core, if `v1beta1` brings them, need an offline root | Sections 7.3, 11 and 12, EP-11; S-09 |

RFC-0001 counts 24 scenarios, and the kit's README twenty-two designed. The new obligations of modules have their scenarios: I-10 in S-31, and I-11 in S-02.

P1-05 follows: the assertion's audience, the module API's resource and `expires_in` in step 4, the client ID of module identities in step 7, and the audience of workload identity in step 8. So do P1-07 (`Watch` refuses HTTP/1.x, the validation of acknowledgements, the kit's minimal client, and a risk for proxies that buffer), P1-08 (the validation of acknowledgements, in section 6 of the design note), P1-09, P1-12 (the settings of intermediaries in the operations guide, and the same risk) and P1-13 (a bundle key rotated with no overlap). The threat model changes T-20, T-33 and AT-1, and the security test catalog ST-35, ST-40, ST-49 and ST-51.

Two changes of the core wait for the fix of P1-02 that the fifth part brings with point 3: the ingester checks de-duplication before scope, so that a retry of an accepted event stays `DUPLICATE`, and it decides the evidence about an agent recently unbound from a module with the delivery period that P1-05 step 5 decides.

What follows in `api/` and the vectors is a part for the coding agents ([AGENTS.md](../../../AGENTS.md), work queue):

- comments only in `governance.proto` and `events.proto`, then `task gen`: an `Acknowledge` item about an agent outside the scope is counted and not recorded, and a `Publish` event outside the rules is rejected with its reason;
- the manifest example `ep-python.yaml` loses `workloadIdentityTokenFile`, since workload identity is outside `v1alpha1`;
- a fail-closed vector F-14, an agent missing from the state applied, with a new input `agent_in_state`, in both stacks: `profile.go`, `fail-closed.json` and `check_vectors.py`;
- the stub enforcement point drops an agent's state and lease when the agent leaves the scope (I-11), and on `PERMISSION_DENIED` from `RegisterInstance` or `Watch` ends every lease at once, then registers again with backoff.

The counts of vectors in the specification (section 9.1) and in RFC-0001 (its item 7) follow the new vector in the pull request that accepts RFC-0001.

P1-07.2 adds to the kit what the scenarios need:

| Addition | Scenarios |
| --- | --- |
| The fake core removes an agent from the state while its lease is valid, and brings it back before the next renewal | S-02 |
| The driver protocol gains an endpoint that reloads the module's bundle keys | S-09 |
| The fake core refuses a registration, and ends an established stream, with `PERMISSION_DENIED`, then accepts; and it ends a stream body without an end-of-stream message | S-12 |
| The kit's certificate authority also issues a certificate for another host | S-26 |
| The fake token endpoint follows section 4.2: the issuer's metadata, the client IDs, the assertion's `aud`, the module API's resource and `expires_in`; it can refuse an assertion with a 400, and answer 503 | S-31 |

### 2026-10-22: corrections, part 3: the decision profile and policies

The third part follows the maintainer's decisions on points 2, 15, 17, 19, 24, 31, 32 and 37 of the review:

| Point | Change | Where |
| --- | --- | --- |
| 2 | `v1alpha1` is Cedar only, run inside the enforcement point or beside it in an embedded policy engine. The review found the Rego wrapper failing open on OPA 1.21, and decision points without what makes them interoperate, so both wait for Phase 2; section 12 lists what each must settle. POL-01 says that Rego comes in Phase 2 | Sections 2, 6.7, 6.8, 7.1 and 12; engine-mappings.md; RFC-0001; POL-01 |
| 15 | An enforcement point checks that a request is inside the profile before it evaluates, and denies one outside it with `error.invalid_request`. Integers are signed 64-bit and decoded exactly, `args` values are never null, and `on_behalf_of` makes a request invalid even when empty. Determining policies are listed once, in ascending order, and the order of reasons is fixed | Sections 6.4, 6.6 and 6.7 |
| 17 | No decision is labeled production for an agent that is not active: the gate closes in `validated` and `ready` when the registration returned `production` | Section 5.4, EP-6; S-02; the lifecycle; T-73, AT-4 |
| 19 | An enforcement point that serves several agents establishes the agent of each call without trusting its caller, acknowledges state per agent, and reports as served the agents it holds a bundle for; a lease expiry is one event per agent. An instance may apply the halts of a snapshot part as soon as the part arrives | Sections 2, 4.9, 5.2, 5.3, 6.2, 6.6 and 9.2, EP-11, EP-12 |
| 24 | What a denial does, action by action; a denial never keeps an agent from stopping. The gate is checked when a call is made, and no governed call waits for the core; an enforcement point may wait, for a bounded time, before the framework starts the agent | Sections 5.3 to 5.5 and 6.3, EP-3 |
| 31 | The subject properties built from the state always match the request schema (CORE-17). An enforcement point need not validate them, and one that finds them invalid denies with `error.invalid_request` | Sections 5.9 and 6.2 |
| 32 | The core refuses a policy that compares a fixed attribute with a value outside the profile's set, and section 6.2 lists the agent's kinds and risk tiers | Sections 6.2 and 6.7; P1-06 step 3 |
| 37 | A model's provider takes a value of a table pinned from OpenTelemetry's well-known names (semantic conventions v1.41.1), or a lowercase name of its own; `trace_id` is the trace ID of the event's `traceparent` | Sections 6.3 and 6.4; RFC-0002, section 3 |

The documents follow: the lifecycle (its gate column, its section 9, and `agent-lifecycle.yaml`, whose `enforcement_gate` gains the value `non_production`), the engine mappings, RFC-0001 (its item 4, and the gaps the mapping missed), RFC-0002 (the providers, and EP-15's acknowledgement per agent), POL-01, P1-05 (step 5), P1-06 (Cedar only, and the check of fixed values in step 3), P1-07 (steps 7 and 9) and P1-09 (step 8). The threat model changes T-73 and AT-4. Step 12 adds RFC-0002's `tool.expose` to the table of what a denial does, and its catalog check to the order of reasons.

What follows is for the coding agents ([AGENTS.md](../../../AGENTS.md), work queue), in three parts:

- **`api/`, then `task gen`.** `bundle-manifest.schema.json` allows the language `cedar` only, and policy paths that end in `.cedar`. `module-manifest.schema.json` gives a policy engine the language `cedar` only and `embedded: true` only, with an invalid example in `api/manifest/testdata/invalid`. `decision-request.schema.json` refuses null values in `args`, makes `on_behalf_of` a false schema that keeps its description, and bounds labels (at most 64, with values of at most 255 characters) and data categories (at most 32, of at most 63 characters). `decision.rego` moves from `api/policy/rego` to `docs/contracts/rego` as a sketch, and `api/policy/README.md` loses its row. Comments change in `governance.proto` (labels follow the request schema's syntax; state acknowledgements per agent), in `registry.proto` (the served agents of an enforcement point that serves several) and in the Cedar schema (the providers, without `local`; `on_behalf_of` stays), and so do the descriptions of `lease.expired` (one event per agent) and `decision.made` (a denied `agent.stop` lets the agent stop). The kit's bundle checks (`bundle.go`) and `check_vectors.py` accept `.cedar` files only.
- **Vectors on both stacks.** The Go profile checks a request against the schema before it evaluates, with the schema library already in `go.mod`, and decodes numbers as `json.Number`; `check_vectors.py` answers `error.invalid_request` rather than raising, and a schema library there would be a new dependency to justify. The gate of both takes the environment: F-10 uses `non_production`, and new fail-closed vectors cover `validated` and `ready` with `production`. About ten combination vectors: times without milliseconds and with an offset; a float argument; n = 2^63-1 under a forbid on n > 1000 (`policy.forbid`) and n = 2^63 (`error.invalid_request`); an unknown member; `on_behalf_of` set to a name and to an empty string; an erroring permit beside a satisfied permit, and beside a satisfied forbid (`error.evaluation`, naming the erroring permit); and two permits out of ascending order. `vectors_test.go` checks that every refused request fails the schema or a named rule.
- **A fix of the core, outside the RFC.** The inventory's validation of label keys, and the `Labels` pattern of the OpenAPI document, take the request schema's pattern; no migration is needed before a release.

P1-07.2 adds to the kit what the scenarios need:

| Addition | Scenarios |
| --- | --- |
| The fake core returns each environment at registration for S-02, as it does for S-05 and S-06; S-05 and S-06 use an `active` agent, since a `validated` or `ready` one stays closed in production | S-02, S-05, S-06 |
| The driver's `POST /v1/decide` gains an optional `agent_id`, and the kit runs the halt, lease and bundle scenarios with two agents in scope for an enforcement point that serves several | S-04, S-05, S-09 |

### 2026-10-23: corrections, part 4: manifests, bundles and versions

The fourth part follows the maintainer's decisions on points 9, 13, 14, 16, 20, 21 and 39 of the review, the answer on `action.executed` included:

| Point | Change | Where |
| --- | --- | --- |
| 9 | Section 10 tells open documents (protobuf messages, the extension attributes of CloudEvents), whose readers ignore what they do not know, from closed ones (event data and types, the module manifest, the bundle manifest, the decision documents), which change in a stated order: the core first, so a module's release is never newer than its core's, and the bundle manifest only through a new format. An additive change only fails closed. EP-10 is scoped to protobuf; section 4.6 gains `UNIMPLEMENTED`, `CANCELED` and a default; section 4.5 states the order of versions and the bootstrap; EP-7 states what keeping the last valid bundle costs | Sections 4.5, 4.6, 4.8 and 10, EP-7, EP-10; S-13, S-16; RFC-0001's reading of ADR-0005, decision 4, and of NFR-01 |
| 13 | A module has a set of approved manifests: an instance registers with any of them, a new one is approved on its own, and an operator retires the old ones | Section 3.2, MAN-2, MAN-3 |
| 14 | Canonical JSON applies to I-JSON, and a manifest that is not I-JSON is refused. A YAML manifest is read under YAML 1.2 Core, without ambiguous scalars, anchors, aliases, merge keys or tags, and JSON is recommended. An instance takes its manifest's hash from its release | Sections 1, 3.1, 3.2 and 8.2, MAN-2 |
| 16 | The bundle versions the core sends never go back, also after a restore or a failover, after which the core re-issues every bundle at a higher version (CORE-18). A rejected version may be retried once the bundle keys change | Sections 5.9, 7.6 and 11 |
| 20 | Two verifiers agree: V4 checks in a stated order, V5 builds each path from its entry, and V7 accepts static Cedar policies only and never rejects a bundle for the core's validation. `cedar_schema` is required, the JWS header has exactly its three members in any order, `EdDSA` stays under RFC 9864's exception, and bundle keys come as a JWK Set | Sections 6.7 and 7.1 to 7.4 |
| 21 | Capabilities bind what a module needs and emits: runtime control needs `events.publish`; the obligations name the events they emit, `whitetower.action.executed.v1` included (EP-8, AUD-02, the maintainer's decision); the catalog's emitters bind (MAN-6); and the core records layer reports only for declared layers (CORE-19) | Sections 2, 3.1, 3.3 and 8.5, EP-3, EP-4, EP-7, EP-8; S-10 |
| 39 | The manifest's version follows the expression of semver.org, with at most 64 characters | `module-manifest.schema.json` only |

The documents follow: RFC-0001 and RFC-0002 (what keeping the last valid bundle means), P1-06 (versions that survive a restore), P1-07 (the set of manifests, the checks of MAN-1 and MAN-6, the reference tool for hashes, the order of versions, layer reports, and the mock module's manifest), P1-08 (a regression also re-issues the bundles, in section 10 of its design note), P1-09 (its manifest's hash from its release, the validation of policies for diagnostics only, and bundle keys as a JWK Set), P1-10.5 (the instances of each manifest) and P1-12 (the order of upgrades, and the re-issue of bundles after a restore). The threat model changes T-30, and records the cost of keeping the last valid bundle as accepted risk R-16.

Three follow-ups are recorded: a revision field, with the first additive change after the tag; a new contract version, or a method added within one, served only once every replica serves it (P1-07 step 4); and a check of the compatibility of JSON schemas in CI, which the maintainer adds, since workflows are protected. Appendix A shows ep-python's real manifest hash in the pull request that accepts RFC-0001, once the examples are final.

What follows is for the coding agents ([AGENTS.md](../../../AGENTS.md), work queue), in two parts:

- **The manifest.** In `module-manifest.schema.json`, `contractVersions` accepts any well-formed version; runtime control needs `governance.watch`, `governance.acknowledge` and `events.publish`, and a non-empty `emits` needs `events.publish`; an enforcement point must emit `decision.made`, `action.executed`, `instance.halted`, `bundle.activated`, `bundle.rejected` and `lease.expired`, and runtime control `lease.expired`, with the quarantine events when it declares the `network_quarantined` layer; `identity: agent` goes only with `enforcement-point`; each capability appears once; and the version takes the numbered-group form of semver.org's expression, written with `[0-9]`, with at most 64 characters. An invalid manifest covers each rule, `1.0.0-01`, `1.0.0-a..b` and a version of 65 characters among them. The catalog's `lease.expired` requires its subject, and the mock module's example declares `action.executed` and its runtime-control role. Manifest vectors give the three examples with their canonical JSON and SHA-256, and invalid YAML manifests (an enumeration `[on, off]`, a date, an integer beyond 2^53), checked in Go and in Python. Comments say, in `registry.proto`, that `manifest_sha256` is the hash of one of the module's approved manifests, taken from the release, and in `governance.proto`, that unspecified outcomes and layers never count as done; then `task gen`.
- **Bundles and both verifiers.** `bundle-manifest.schema.json` requires `cedar_schema`, takes the UUID form in its path pattern, and loses or recomputes `maxItems`. About twenty generated vectors: a template; a policy that fails validation, which is activated; no schema; unknown members at the top level and in a policy entry, and missing members; malformed, duplicate and mismatched paths; a misplaced schema; unsupported values; and header cases (`alg` `none`, `HS256` keyed with the public key, the algorithm name `Ed25519`, another `typ`, an extra `b64` with `crit`, no `kid`). Both verifiers, `bundle.go` and `check_vectors.py`, follow V4's order, build paths from entries, refuse unknown members, and parse static policies only. The driver protocol passes the trusted bundle keys as a JWK Set file.

The counts of vectors in the specification and in RFC-0001 follow the new vectors in the pull request that accepts RFC-0001.

### 2026-10-23: corrections, part 5: events and halt reports

The fifth part follows the maintainer's decisions on points 3, 7, 10, 12, 22, 27, 28, 35 and 36 of the review:

| Point | Change | Where |
| --- | --- | --- |
| 3 | A source names a module by its slug, and an evidence buffer by a random stream ID of at least 64 bits, never a host, pod, cluster or instance name. A source has one writer, and a `wtseq` that repeats under a new event ID is a finding | Sections 4.3, 8.2 and 8.4 |
| 7 | `terminate` ends the process only if work still runs at the end of the grace period, and a release during it cancels the end. A process that starts while its agent is halted stays up and closed, and never ends itself for that halt. The process that ends reports `process_terminated` `done` just before, as its last report, and `after_receipt` runs from the receipt by that process | Section 5.5, EP-4; S-05, S-07 |
| 10 | The fields of `decision.made` depend on its reason: an environment only when policies were evaluated, since none exists before a registration (I-7), and `bundle_version` by reason, in the response too. A resource ID has 1 to 512 characters; `instance.halted` may leave out a scope it does not know; a quarantine applied at lease expiry is reported by `lease.expired`; and a denial with `gate.evidence_full` is the one decision not recorded | Sections 3.2 (MAN-5), 4.9 (I-7), 5.5, 5.8 (RC-3), 6.3, 6.6, 8.3, 8.5 and 10, EP-8; S-03, S-10 |
| 12 | At most one `Publish` call per source is in flight, and after a failure the same events go first (I-12). The core records a gap at once, and recognizes an event for at least 28 days | Sections 4.7 and 8.4; S-10 |
| 22 | The hashed mode of arguments is a defined HMAC, with its key's ID. Values copied from a framework follow the first rule of section 8.3, a run or thread ID is recorded only when declared opaque, and `detail` fields carry fixed text or codes. CORE-9 says what the core can promise | Sections 5.9, 8.2 and 8.3; the domain model's section 7 |
| 27 | An instance delivers its buffer before it deregisters or ends itself (SHOULD), and its health reports an old backlog | Sections 4.9 and 8.4; S-10, S-11 |
| 28 | Health says whether the instance can do what the state asks, and `lease.expired` says why the lease ran out and what the halt mode did | Sections 4.9 and 5.3 |
| 35 | `Publish` holds 500 events within the message limit, and an event's size is that of its CloudEvent's JSON | Section 4.8; RFC-0002 |
| 36 | The envelope's rules that are narrower than CloudEvents are listed; `datacontenttype` becomes optional, and `traceparent` takes any version but `ff` | Section 8.2 |

Points 10, 27 and 28 each gave a health for a full evidence buffer. Section 4.9 settles it as `HEALTH_UNHEALTHY`, since an instance whose buffer is full cannot enforce what the state asks.

The documents follow: P1-02 (a fix of ingestion, before P1-07 serves `Publish`), P1-08 (in section 6 of its design note, how reports merge across a restart, and the receipt time that coverage C3 keeps), P1-09 (the `terminate` mode, the evidence buffer and the HMAC's key), P1-12 (where buffers live), RFC-0002 (the limit of definitions, and `bundle_version` with the catalog's reasons) and the domain model (the fields copied into evidence). The threat model changes T-35 and AT-6, and its assets gain the HMAC's key.

What follows is for the coding agents ([AGENTS.md](../../../AGENTS.md), work queue):

- **Schemas and references.** `decision.made` requires `environment` only with `policy.permit`, `policy.forbid`, `policy.no_permit`, `error.evaluation` and `error.timeout`, and `bundle_version` as section 6.6 says, as `decision-response.schema.json` does; it marks a resource ID or an argument name recorded as its SHA-256, and its `arguments` gain an optional `key_id`. `instance.halted` makes `scope` optional, and `lease.expired` gains the optional `cause` (`no_renewal` or `stale_renewals`), `halt_mode` and `layers`. `cloudevent.schema.json` makes `datacontenttype` optional, and accepts any `traceparent` version but `ff`. Comments change in `events.proto` (one call per source in flight, de-duplication for 28 days), in `governance.proto` (`HALT_LAYER_PROCESS_TERMINATED` and `LAYER_OUTCOME_DONE`) and in `registry.proto` (health); then `task gen`. Both references deny a resource ID over 512 characters with `error.invalid_request`, with a combination vector, and check `bundle_version` by reason. An HMAC vector (arguments, key, expected value) runs on both stacks, and the `ep-python` example gains the key's file and ID in its evidence settings.
- **Ingestion,** in a fix of P1-02 (its progress notes of 2026-10-23), with the pattern of sources in `cloudevent.schema.json` and every example's source.

P1-07.2 adds to the kit what the scenarios need:

| Addition | Scenarios |
| --- | --- |
| The fake core checks sources as the core does, holds a `Publish` response, and fails a call with `RESOURCE_EXHAUSTED` or `UNAVAILABLE` | S-10 |
| The driver protocol gains endpoints that replace the module's evidence buffer and that stop the module, and the driver survives the end of the module's process | S-05, S-07, S-10 |
| The kit makes the fake core unreachable while the module restarts | S-10 |

### 2026-10-23: corrections, part 6: conformance, runtime control, and the rest

The last part of the corrections follows the maintainer's decisions on points 33, 34 and 38 of the review, and applies its editorial corrections:

| Point | Change | Where |
| --- | --- | --- |
| 33 | `v1alpha1` specifies runtime control as the network quarantine of Kubernetes workloads, and other platforms and layers come through an RFC. A layer leaves the core reachable from the workloads it isolates (RC-7), and blocks DNS by default; an enforcement point reuses the core's last resolved addresses when resolution fails. The rule of DNS leaves section 12. The quarantine events name their mechanism with an open value, rather than a closed list of CNIs | Sections 2, 3.1, 5.7, 5.8 and 12; S-29 |
| 34 | One rule times every timed scenario: the kit's own clock, from when the fake core sends, with 1 second for transport and polling. S-04 and S-17 expect `gate.lease_expired` by the TTL plus 1 second; S-05 expects the gate's acknowledgement within 1 second, the maintainer's choice, and honest outcomes for the later layers; S-12 says what it checks of the backoff | Section 9.2, S-04, S-05, S-12 and S-17; RFC-0002's S-20 |
| 38 | RFC-0001 says that the specification changed after its approval, and where each change is listed; its main choices add the rule that a halt applies wherever the instance runs and the environment that registration returns; its related items add ADR-0010, KIL-01, KIL-02 and NFR-20; its implementation plan adds P1-05; and the question on tool arguments points to RFC-0002. The specification's related items add ADR-0010, and appendix B KIL-02. The entry of 2026-10-02 and 2026-10-09 above lists the changes these notes lacked. ADR-0004 is not edited: RFC-0001's section on compatibility says which of its clauses section 10 replaces | RFC-0001; the specification's header, section 12 and appendix B |

The editorial corrections: the contracts have seven parts, not six; RC-4 and S-15 count the workloads isolated, the word of section 5.5, and so do the domain model and P1-08; section 6.2 names `attributes.owner_id`; EP-2 cites the bounded evaluation time; CORE-3 lists the versions in its error for people, while instances learn them from `GetServerInfo`; `dataschema` and section 12 follow the decision of 2026-09-30 on question Q6, as `api/events/README.md` does; and section 7.2 states the JWS signing input. CORE-4 needed no correction of its own, since point 26 rewrote it.

What follows is for the coding agents ([AGENTS.md](../../../AGENTS.md), work queue), in one part:

- **Runtime control.** In the quarantine events, `cni` becomes `mechanism`, an open string with a pattern, whose four known values the schema documents; `cluster` stays required. Their examples change, and the golden file of indexed examples is regenerated.
- **The kit's skeleton** follows I-7, as P1-07.2 would have done: the fake core returns `ENVIRONMENT_PRODUCTION` at registration; the stub takes the environment from its registration, and treats an unspecified or unknown one as refused; `WT_CONFORMANCE_ENVIRONMENT` leaves the driver protocol; and `/v1/decide`, with the comments of `kit.DecideRequest` and `stubep.Decide`, says the subject comes from the state and the registration. The driver protocol gains `WT_CONFORMANCE_EVIDENCE_CAPACITY`, with which the harness gives the module a small buffer for S-11; a module that cannot take it reports S-11 as not run. The runs of S-25 with each environment stay with P1-07.2.
- **Examples and vectors.** The examples of `decision.made` and `action.executed` get different span IDs, since they record two different calls, and C-15's description says that the environment that registration returns decides.

Two corrections wait for the pull request that accepts RFC-0001, since the coding parts regenerate the vectors and change the examples first: appendix A's bundle references (the valid bundle's hash and size, 4344 bytes today rather than the 4241 of `tampered-policy`) and ep-python's manifest hash, and the counts of vectors in section 9.1 and in RFC-0001.

P1-07.2 adds to the kit what S-29 needs: the driver protocol's endpoints for runtime-control modules also say whether an isolated workload reaches the core's machine listener and token endpoint, as the platform shows it.

### 2026-10-23: RFC-0001 accepted provisionally

With the six parts of corrections merged, the maintainer accepted RFC-0001 provisionally on 2026-10-23 ([GOVERNANCE.md](../../../GOVERNANCE.md#rfc-process)), and decided two more things:

- **Accepted now** (decision 1, option A). The accepted text is the specification at commit `a284a2d`. The changes to `api/`, the vectors, the conformance kit and the core follow in their own pull requests, as GOVERNANCE.md's rule 6 says, and land before `contracts/v0.1.0` is tagged. RFC-0001's status had said it would wait for them.
- **Those parts first** (decision 2, option A). They depend on no feature plan, and the tag and step 12 wait for them, so they move up in AGENTS.md's work queue, to rows 2 to 11, right after the version mechanism of the halt path.

RFC-0001 now holds the record of its review: each point, its decision and the part that applied it, and that the maintainer alone reviewed it. Step 11 is done. What is left of the review is small: once the coding agents have regenerated the vectors, a pull request of the reviewer's updates appendix A (the valid bundle's hash and size, and ep-python's manifest hash) and the counts of vectors in section 9.1 and in RFC-0001.

RFC-0002's provisional review follows, the same way. The tag waits for step 12 and for the parts above.

### 2026-10-23: RFC-0002's provisional review, part 1

The reviewer read RFC-0002 against the specification as RFC-0001's review left it, plan P1-16, the design of the halt path and the threat model, and found 21 points, 8 of them major, and 3 editorial notes. The maintainer decided the eight major points on 2026-10-23, and this part applies them to RFC-0002 and to the documents that follow from it:

| Point | Decision | Where |
| --- | --- | --- |
| 1. A usage rule never applies to a provider-run tool whose calls the provider does not submit for approval | `tool.expose` gains `calls_decided`; the enforcement point asks for approvals for the tools that usage rules name; each rule compiles to a second statement, which forbids exposing the tool while its calls are not decided | RFC-0002, sections 7.3, 7.4, 7.6 and 8; CAT-07; T-79, ST-82; P1-06, P1-09, P1-16 step 6 |
| 2. The `path` transform is defined by a Go library | An algorithm in the text: control characters cannot be read, and a leading `//` is merged, as Go does and Python's `normpath` does not; path rules are safe as allow-lists | RFC-0002, sections 7.5 and 8; T-78, R-15, ST-79; P1-09 |
| 3. `url_host` and `email_domain` meet the differences between parsers | Rules that refuse what parsers read differently, narrowed after a check: of 42 legitimate URLs and 18 addresses, they refuse 2 and 4, and in 38 URL tricks and 15 address tricks no parser reaches another host than theirs | RFC-0002, section 7.5; T-78, R-15, ST-79; P1-09 |
| 4. Secrets in URL paths escape EP-14, and what a reference covers is unstated | The deployment's redaction rules, a setting carried in every catalog file and applied by the enforcement point and the core; an approval covers every configuration that shares a reference | RFC-0002, sections 3, 4.1, 4.2 and 5; CAT-10; T-76, T-83, DC-11, ST-77; P1-09, P1-16 steps 2 and 4, P1-17, the domain model |
| 5. A remote server's URL is normalized only in part | A full normalization, with the host that `url_host` reads | RFC-0002, section 3; P1-09 |
| 6. "The provider's public endpoint" is undefined | A model's reference always carries its endpoint; the core's keys still read `openai/gpt-4o` | RFC-0002, sections 3 and 7.2; P1-09, P1-16 step 2 |
| 7. Definition hashes over input that RFC 8785 does not cover | RFC 8785 with integers written exactly, `null` members left out, and the wire form of `tools/list` as the input | RFC-0002, sections 3 and 4.1; P1-09, P1-16 step 4, the domain model |
| 8. A catalog file can be larger than a bundle may be | The core keeps each bundle within step V1: enabled entries first, observed ones while they fit, and an enabling that would not fit refused | RFC-0002, section 5; P1-06, P1-16 step 5 |

The check of point 3 ran each URL through Python's `urllib.parse`, urllib3, requests, httpx and yarl, Node's WHATWG parser, Go's `net/url` and curl 8.12, and each address through Python's three address parsers. Python's own parsers disagree: `http://evil.com\@good.com/` is `good.com` for `urlsplit`, httpx and yarl, and `evil.com` for urllib3 and requests. The rules as first proposed refused 15 of the legitimate URLs and 9 of the addresses: spaces in a query, user information, other schemes, display names.

Step 12 carries these decisions into the specification, the schemas and the vectors. The vectors take the check's cases, which the reviewer hands over with the specification text (pull request 1). Two notes for them (pull request 3):

- Go's ready-made `idna.Lookup` profile refuses underscores. The Go stack converts hosts with `golang.org/x/net/idna` options close to WHATWG's (UTS #46 mapping, non-transitional, no STD3 rules, no hyphen checks, joiners and Bidi checked), which agreed with Node's `domainToASCII` on every valid host of the check. In Python, the `idna` package's `encode` applies IDNA 2008 and refuses underscores too, so the Python stack uses its `uts46_remap`, then Punycode.
- `gowebpki/jcs` cannot compute definition hashes as it is: it writes 18446744073709551615 as 18446744073709552000.

The 13 minor points and the editorial notes follow in later parts.
