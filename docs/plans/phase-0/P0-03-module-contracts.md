# P0-03: Module contracts v0.1

| | |
| --- | --- |
| **Phase** | 0 Foundations |
| **Status** | In progress: the corrections from the review of RFC-0001 and its acceptance, then, once RFC-0002 is accepted, step 12 remain (see [progress notes](#progress-notes)) |
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
| The fake token endpoint, which the [driver protocol](../../../test/conformance/driver-protocol.md) says P1-07 adds, issues tokens that expire within a minute. The fake core ends each stream with `UNAUTHENTICATED` when its token expires (CORE-1), and allows two streams per instance, ending a third with `ABORTED`, as the core does (P1-07 step 5) | S-26, S-27 |
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
| 2 and later. Corrections | The other points, the rest of point 38 included, and the editorial corrections, in small pull requests: the specification text first (the reviewer's), then `api/`, the vectors and the code that follow it, as parts for the coding agents | Not started |
| Last. Acceptance | The record of the review in RFC-0001, the commit of the accepted text, the roadmap's summary and risks of the reviews, and step 11 closed | Not started |

RFC-0002's review follows, the same way.

The governance part of point 38 comes with the rule: GOVERNANCE.md, CONTRIBUTING.md, the index of RFCs and section 10 name `api/policy` and what the vectors expect among the changes that need an RFC. The rest of point 38, in RFC-0001 and the specification, is a correction like the others. The RFC template gains a section for the record of the review, and gate G0 of the roadmap asks for both RFCs accepted, provisionally while the rule applies. The comment at the top of `.github/CODEOWNERS` still names three directories, and is the maintainer's to change.
