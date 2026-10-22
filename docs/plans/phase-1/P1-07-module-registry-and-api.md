# P1-07: Module registry and module API

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | XL, split into two subplans before it starts, by a pull request of its own: **P1-07.1** (steps 1 to 7, about 5 weeks: generated code, authentication and authorization, registration, sessions, the governance state service with the blocks record, acknowledgements, event ingestion) and **P1-07.2** (steps 8 to 10, about 3 weeks: the wiring of tooling reports of step 7, once P1-16's pull request 3 is merged, then the mock module, the conformance kit with S-01 to S-30, the load test), each with its tests (step 11). The first pull request of P1-07.1 is the version mechanism of the halt path ([design note](P1-08-kill-switch.md#progress-notes), section 14), which needs nothing from P1-05 and lands ahead of it |
| **Depends on** | P0-03, P1-01, P1-05 (can start with stub authentication); P0-03 step 12 (RFC-0002 in the contracts) for the parts of RFC-0002; P1-16 step 4 for the wiring of tooling reports (step 7) |
| **Unblocks** | P1-08, P1-09, P1-10.5; P1-04 pull request 4, through the first pull request of P1-07.1; P1-16 step 7, through the blocks record of step 5 and, for ST-80, the mock module of step 8 |
| **Requirements** | MOD-01 to MOD-05, MOD-07, KIL-07, AUD-02 (ingestion wiring); the transport of CAT-01 and CAT-04, and part of NFR-24's budget |
| **Decisions** | ADR-0004, ADR-0005, [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) |

## Goal

The core side of the module contracts: modules are registered and approved, their instances connect and are authorized, governance state reaches every enforcement point through watch streams with leases, acknowledgements come back, and events flow into the audit log. A reference module and the conformance kit prove the contract works. Once RFC-0002 is in the contracts, tooling reports also reach the catalog, and organization-wide blocks reach every enforcement point as fast as halts, without slowing them.

## Scope

**In:** the generated code, authentication and authorization on the machine listener, module registration, instance sessions, the governance state service and watch fan-out, acknowledgements, ingestion wiring, the mock reference module, the conformance kit, load tests. Once P0-03 step 12 has put RFC-0002 in the contracts: the generated code, the authorization and the wiring of `RegistryService.ReportTooling` and `RegistryService.ReportDefinitions`, the blocks record of the watch stream, the mock module's side of RFC-0002, the scenarios S-18 to S-24, and the load test with blocks.

**Out:** the kill switch domain (P1-08, which writes the governance state through the service built here); bundles (P1-06); the Python enforcement point (P1-09); the network quarantine module (P1-15); RFC-0002's contract text, protobuf, schemas and vectors (P0-03 step 12); the catalog domain: validating reports, storing observations and definitions, issuing and lifting blocks (P1-16, which writes blocks through the service built here).

## Deliverables

- `internal/modules`, `internal/govstate`, `internal/api/moduleapi`.
- `modules/mock`: a Go reference enforcement point.
- `test/conformance`: the conformance kit runner (`wt-conformance`) with every scenario of P0-03 and RFC-0002, S-01 to S-30.
- A load test report, with and without 500 active blocks.

## Steps

### 1. Generated code

Run `buf generate` for the Go server, the Go client (used by the mock module and the conformance kit) and the Python client (used by P1-09).

RFC-0002's contract text, protobuf, schemas and vectors land first, in P0-03 step 12, whose pull request also gives the kit's fake core the new methods. Once they have, the generated code covers `RegistryService.ReportTooling`, `RegistryService.ReportDefinitions` and `Block` in the three outputs, and the fake core gains what the scenarios of RFC-0002 need: it records every report and every definition, answers with the definition hashes it does not have, and scripts blocks in snapshots and changes.

**Done when:** the three outputs build and are part of the drift check, and the fake core serves what the scenarios of RFC-0002 need.

### 2. Authentication and authorization

- Verify White Tower access tokens (own JWKS, audience of the module API).
- Two kinds of caller:
  - **enforcement points embedded in an agent**, whose subject is the agent's SPIFFE ID, may only serve that agent;
  - **module instances**, whose subject is a module's SPIFFE ID, may only serve the agents bound to the module by an operator.
- The event types a caller may publish are those its manifest declares.
- Only instances of modules whose manifest declares the `enforcement-point` capability may call `RegistryService.ReportTooling` and `RegistryService.ReportDefinitions`, and only about agents in their scope (RFC-0002, section 4.1).

**Done when:** negative tests pass: watching another agent, publishing undeclared types, reporting tooling about another agent or from a module without `enforcement-point`, and using an expired token or one with the wrong audience are all rejected.

### 3. Module registration

REST operations for operators:

- upload a manifest, validated against the JSON Schema;
- approve or revoke a module;
- create the module's credentials through P1-05;
- bind a module to agents;
- list the modules.

Everything is audited.

**Done when:** a module goes from manifest upload to approved and connected, and revoking it disconnects its instances.

### 4. Instance sessions

- `RegisterInstance` records the instance ID, module, version, supported contract versions, agents served and host details, then negotiates the contract version.
- Instances have a status: connected, last seen, lease state.
- `/api/v1/agents/{id}/instances` and a module's instance list show them.
- `RegisterInstanceResponse` returns the environment recorded for the credential the instance registered with. `module_instances` keeps it, in a column that this plan adds, and the public API's instance lists show it: `environment` joins the OpenAPI document's `Instance` schema, an additive change made before the code that serves it. The core refuses to register an instance of a module whose manifest declares the `enforcement-point` capability when the instance's credential has no environment, since every decision needs one. A module that authenticates as itself takes its module credential's environment, which P1-05 step 7 requires of such modules. The environment serves decisions and the console's grouping of instances (P1-10), and never decides what a halt covers ([design note](P1-08-kill-switch.md#progress-notes), section 13, decision 7). The field is not this plan's to add: it comes with the change to the contracts and RFC-0001 that the note's section 14 lists for decision 7, and step 1 generates it.

- **What an instance is** (contracts, sections 4.3 and 4.9). An instance belongs to the principal whose token registered it, and its key is unique per module and principal: a migration replaces `UNIQUE (module_id, instance_key)` with a key on the module, the principal and the instance key, where `identity_agent_id` is NULL for module identities (so `NULLS NOT DISTINCT`, or two partial indexes). Every call that names an instance checks that the caller's principal registered it (CORE-2, ST-35). Every `RegisterInstanceResponse` and `HeartbeatResponse` sets the heartbeat interval (I-6).
- Rate limits answer `RESOURCE_EXHAUSTED` with a `google.rpc.RetryInfo` detail, and never refuse an `Acknowledge` that carries a halt acknowledgement (CORE-15). The machine listener accepts client HTTP/2 PINGs as often as every 10 seconds (CORE-14).

**Done when:** instances appear, update and disappear as they connect, heartbeat and drop, each with the environment of its credential, and an enforcement point whose credential has no environment cannot register.

### 5. Governance state service (subplan candidate)

- One state record per agent, as defined in P0-02, versioned from one version counter (`governance_head`, through `next_governance_version()`), rather than from one global sequence under an advisory lock. Writers (inventory, policy, kill switch) update it inside their own transactions.
- After commit, a notification goes out through `notify.Bus`, and each replica's hub reads the changes in one consistent snapshot and fans them out to its watch streams. A stream carries its instance's scope (contracts, section 4.3), not the agents the instance serves, which matter only to tracking: RC-1 needs every halted agent in scope, including those whose workloads start later.
- Bindings are versioned too: `module_agent_bindings` gains `state_version` and `removed_version`, stamped like the other records and checked by the version-check trigger, so a resumed stream learns which agents entered or left its scope ([design note](P1-08-kill-switch.md#progress-notes), sections 2 and 12).
- A new or lagging stream gets a snapshot; otherwise it resumes from the last version it saw. Lease renewals are sent every third of the shortest TTL in the stream's scope, at most 30 seconds apart (contracts, section 4.8), and only while the replica is current: a replica whose last successful read is 3 seconds old or more sends none, so leases run out rather than trust a replica that may have missed a halt.
- The hub reads after each notification, every second, and whenever a stream asks for a version above what it has read, so a lost notification delays a change by one second at most. Once its last successful read is 10 seconds old, a replica ends its streams with `UNAVAILABLE` and reports not ready, so enforcement points move to a healthy replica ([design note](P1-08-kill-switch.md#progress-notes), sections 3 and 5).
- Each stream holds one pending change, into which new changes merge, so a slow consumer never slows the hub or another stream. Each send has a deadline of 5 seconds: a stream that misses it is ended (CORE-7), and its enforcement point resumes elsewhere or receives a snapshot. State is never dropped silently.
- A stream ends with the code of its cause: `UNAUTHENTICATED` at token expiry (CORE-1), `PERMISSION_DENIED` at revocation (MAN-4), `UNAVAILABLE` for a slow client, a stale replica or a drain, and `ABORTED` for the oldest stream of an instance that opens a third on the replica, since two are allowed for the token rollover of I-2, and a dead stream the replica has not noticed must never refuse a live reconnection (CORE-16).
- `Watch` refuses HTTP/1.x (contracts, section 4.1): the cut-off of slow clients (CORE-7) and the check of dead peers rely on HTTP/2.
- `module_instances.lease_ttl_seconds` keeps the shortest TTL in the instance's scope, and nothing when the scope has no agent, so a migration drops its `NOT NULL`. The instance's row also keeps the heartbeat interval the core last set for it, and `last_heartbeat_at`, the time of its last heartbeat, apart from `last_seen_at`, which only a replica that streams the instance refreshes. P1-08's tracker finds lost instances from them, by the two rules of CORE-4.
- **Blocks** (RFC-0002, section 6) are a third record, beside the agents' and the fleet's, and never enter the fleet record. P1-16 writes them through this service (its step 7), each issue or lift in a transaction of its own that stamps only its `catalog_blocks` row. They take their versions from the same version counter, so a lease renewal still means "your state is current" (CORE-6), and they are committed without waiting for any bundle (CORE-12). A lifted block keeps the version that lifted it, so catching up on every change after a version never misses a removal.
- Snapshots carry every active block, and changes carry the blocks added and the IDs of those removed. A block carries its ID, its kind, the SHA-256 of the string form of what it covers and its issue time; references and reasons stay in the core. At most 500 are active, about 40 KB of a snapshot.
- Blocks go to every stream of an enforcement point, whatever agents it serves, and to no other stream. The hub keeps one shared, immutable copy of the active blocks, so memory does not grow with streams times blocks. A stream's pending change keeps the blocks added and removed since its last send, net of each other, as it keeps only the latest state of each agent, so a halt that follows a burst of blocks arrives in the same message, never behind them.
- Writers lock their rows first, then take the version with `StateVersions.Next`, then stamp the agent's state, the fleet record or the blocks record, so the version counter is held only from `Next` to the commit.
- Blocks are on the halt path. The design of this step and of step 6 is part of the halt path's [design note](P1-08-kill-switch.md#progress-notes), accepted on 2026-10-20 (DC-9).
- Metrics: open streams, lag, send latency.

**Done when:** tests prove ordering, resumption, snapshots after a gap, and slow-consumer handling; with blocks, a snapshot after a gap carries every active block, a resumed stream ends with the right set of active blocks, and after a burst of blocks a fleet halt is still delivered within the fan-out budget.

### 6. Acknowledgements

`Acknowledge` receives halt acknowledgements (with each layer reported separately), bundle activations and observed states. It is idempotent on the instance, subject and version. It feeds drift detection (P1-06) and halt propagation tracking (P1-08). As the halt path's [design note](P1-08-kill-switch.md#progress-notes) says (section 6):

- **Validation** follows CORE-2. A failure of the call refuses the whole request, such as an instance that the caller's principal did not register. An item about an agent outside the caller's scope, or an acknowledgement of a halt that is unknown or does not cover the agent, is counted, not recorded, and does not fail the request, so a valid acknowledgement beside it is never lost (ST-40). One of a released halt is recorded only for an expected pair of instance and agent, so that a drill's later layers are still measured; it changes nothing else.
- **Halt acknowledgements** go to the replica's halt writer, which collects them for 10 ms, or up to 100, and writes them in one transaction on the halt path's own connections. The response goes out once its items are committed.
- **Layer reports** are kept per halt, instance, agent and layer. A report replaces an earlier one only when its `after_receipt` is larger, so retries and duplicates change nothing, and a layer moves from `not_done` to `done` as the instance reports it.
- **State and bundle acknowledgements** are coalesced per instance and agent, keeping the highest version, and flushed every 250 ms on the main pool; their requests return after the flush. They never share a batch with halt acknowledgements.
- No rate limit refuses a halt acknowledgement.

A state acknowledgement at or after the version that carries a block means the instance applied the block (EP-15). P1-16 shows the block's spread from `instance_agents.observed_state_version`, through the tracking of P1-08, counting enforcement points only. Since state acknowledgements never share a batch with halt acknowledgements, the burst of acknowledgements that a block causes never delays a halt's, where NFR-03 is measured.

**Done when:** duplicates are harmless, acknowledgements about an agent outside the caller's scope are counted and never recorded while the valid items beside them are, and halt acknowledgements never wait for state acknowledgements.

### 7. Event ingestion and tooling reports

Wire `EventService.Publish` to the ingestion logic of P1-02 (step 5), with per-instance rate limits and counters used as health signals.

Once P1-16 step 4 is merged, wire `RegistryService.ReportTooling` and `RegistryService.ReportDefinitions` to its logic the same way:

- the handler authenticates the caller, checks its scope and its capability (step 2) and the message limits (contracts, section 4.8), then passes the instance's identity, its agents and the request to P1-16, which validates it, applies the limits of reports and their rate limit, and stores it;
- a report sent twice changes nothing;
- logs carry counts, never reported text.

**Done when:** events from the mock module appear in the audit log, sealed, and its tooling reports and definitions reach the catalog as observations; reports outside the scope, over the limits or too frequent are refused.

### 8. Mock reference module (MOD-07)

`modules/mock` is a faithful enforcement point in Go:

- it registers, watches and keeps its lease;
- it verifies bundles (signature, hashes, monotonic version) and evaluates Cedar policies with `cedar-go`, using the White Tower combination semantics;
- it simulates actions at a configurable rate and publishes events through a durable file buffer;
- it halts and acknowledges each layer;
- it also plays a runtime-control module, which acknowledges the `network_quarantined` layer for the agents it reports as served (I-6), for the tests of P1-08 step 4;
- it can also authenticate as the agent it serves, as an enforcement point inside an agent does, so that P1-08 step 3 can halt one agent's instances on a production and a non-production credential;
- once RFC-0002 is in the contracts, its manifest declares `tool.expose`, and it plays the enforcement point's side of RFC-0002: it reports scripted, configurable tooling (servers, tools and models, with canary secrets it redacts, definitions that change on demand, and hostile reported text: markup, script, bidirectional and invisible characters, 16 KiB descriptions) through `ReportTooling` and `ReportDefinitions`; applies blocks by the SHA-256 of the string forms of what they cover, and denies every tool and model call while a block of a kind it does not know is active; checks the catalog before policies; fills per-tool arguments with their transforms; evaluates `tool.expose` on scripted model requests; and narrows provider-run tools;
- flags inject faults: drop acknowledgements, delay them, crash, lie; and, for RFC-0002, report secrets unredacted, ignore blocks, skip the catalog check, expose a denied or changed tool, acknowledge blocks late.

It serves tests, demos and load tests. It is also the reference implementation module authors can read.

**Done when:** the mock module passes every conformance scenario.

### 9. Conformance kit (MOD-05, subplan candidate)

Implement every P0-03 scenario in `test/conformance`. The `wt-conformance` runner plays the core against a module under test and produces JUnit XML plus a readable report. It runs in CI against the mock module and is documented for third-party authors. Its documentation shows a minimal client in plain HTTP, as P0-03 promised: the unary calls, the Connect framing of a `Watch` stream and its end-of-stream message (contracts, appendix A), and the token requests of section 4.2.

The kit's fake core returns, in `RegisterInstanceResponse`, the environment of the credential the instance registered with, as the core does (step 4), so the driver protocol's `WT_CONFORMANCE_ENVIRONMENT` and the environment in the configuration of the stub enforcement point (`test/conformance/stubep`) give way to it, and the driver protocol's `POST /v1/decide` has the module build the subject from its state and its registration, not its credential ([design note](P1-08-kill-switch.md#progress-notes), section 13, decision 7).

The kit additions that the scenarios need are listed in [P0-03's progress notes](../phase-0/P0-03-module-contracts.md#progress-notes): those of S-26 to S-29 in the notes of 2026-10-21, and those of S-12, S-27 and S-30 in the notes of 2026-10-22 (corrections, part 1).

Once P0-03 step 12 has added RFC-0002's vectors, also implement the RFC's scenarios S-18 to S-24, which run those vectors through the module under test. The kit checks the module's side only: the core's side is tested in P1-16 (ST-75 for CORE-10, ST-80 for the spread of blocks). The [driver protocol](../../../test/conformance/driver-protocol.md) gains three endpoints for these scenarios, in its table "Planned for P1-07":

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/tooling` | Sets the tooling the agent is configured with: MCP servers (URL or command, arguments, environment, headers), their tools with definitions, models, and provider-run tools. The module reports it (S-18, S-24) and resolves calls against it |
| `POST /v1/call` | A tool or model call as the agent makes it (server, tool name, current definition, arguments; provider, endpoint, model, runtime digest), through the normal path: gate, catalog, policies, evidence. S-03, S-19, S-20, S-21 and S-23 use it; `/v1/decide` stays for the other actions |
| `POST /v1/model-request` | A model request that offers tools, run by the agent or by the provider, removable or not. It answers with the tools that reached the model, or with the denial (S-21, S-22) |

**Done when:** the kit fails on each fault the mock module can inject, and passes without faults.

### 10. Load test

Using the P0-05 S2 setup at production shape:

- 500 or more concurrent streams across two replicas;
- fan-out timing of a state change;
- a rolling restart of one replica while streams are open;
- memory per stream;
- the same runs with 500 active blocks: the size and time of a snapshot, the fan-out time of a block, a fleet halt right after 100 block changes, and a rolling restart.

Publish the results.

Build the load test to take new scenarios, as the halt path's [design note](P1-08-kill-switch.md#progress-notes) says (section 14): P1-08's harness (its step 10) extends it with halt scenarios and per-instance timings, and P1-16 runs that harness again with blocks (ST-80).

**Done when:** the report is in `docs/performance/` and the acceptance numbers below are met.

### 11. Tests

- Permission negatives.
- Version negotiation.
- Correctness of resumption.
- Slow consumers.
- Instance lifecycle.
- `ReportTooling` and `ReportDefinitions`: scope, capability and limits.
- Blocks in snapshots and changes, resumption across additions and removals, and merged block changes in a slow stream.
- Halt acknowledgements that never wait for state acknowledgements.

**Done when:** all run in CI.

## Acceptance criteria

- The mock module passes the full conformance suite in CI.
- With 500 concurrent streams on two replicas, state changes are delivered with p95 ≤ 1 second (part of NFR-03's budget).
- During a rolling restart of one replica, every enforcement point reconnects within a third of the shortest lease TTL it holds (I-4) without losing a change, and no lease expires with the default TTL.
- Instances and their state are visible through the API.
- The mock module passes scenarios S-18 to S-24, and the kit fails on each fault of RFC-0002 that the mock module can inject.
- With 500 concurrent streams on two replicas and 500 active blocks, state changes and blocks are delivered with p95 ≤ 1 second (part of the budgets of NFR-03 and NFR-24).
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-07-module-registry-and-api) pass: ST-34 to ST-39, with ST-35 and ST-38 covering `ReportTooling`, `ReportDefinitions` and the message limits of reports and definitions.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Load balancers cut long-lived HTTP/2 streams, or buffer them | Keepalives, a documented idle timeout, and resumption from the last version on reconnect. A proxy that buffers makes every renewal stale, so the operations guide gives each supported one's settings to pass messages as they arrive (P1-12 step 9) |
| Fan-out storms when a global policy changes every agent's state | Coalescing in the hub (only the latest version per agent is sent), and a chunked bundle rebuild in P1-06 |
| The mock module drifts from the specification | It is the reference: every contract change updates it and the kit in the same pull request |
| Blocks slow the halt path (T-80, DC-9) | A record of their own, at most 500 active and hashed (about 40 KB in a snapshot); block changes merged per stream; the version counter held only until commit; halt acknowledgements in batches of their own; the halt path's design reviewed before code; measured in step 10, and by P1-16 with the harness of P1-08 (ST-80) |
| A module floods the catalog with reports (T-74) | Only enforcement points report, about agents in their scope; P1-16 applies the limits, the rate limit and the bound on each agent's entries waiting for review (DC-10); reports never authorize |

## Notes for implementers

- `connect-go` server streams map to plain `http.Handler`s, so TLS and middleware stay shared with the rest of the machine listener.
- Send the snapshot and later changes through the stream's one pending change and its one writer, to avoid races between them ([design note](P1-08-kill-switch.md#progress-notes), section 4).
- Enforcement points start closed. The contract (and the kit) makes the "no action before state" rule testable (KIL-07).
- An instance that does not know blocks ignores them (EP-10). That is safe because every bundle now carries a catalog file, which such an instance rejects at step V4 (`invalid_manifest`): it keeps its last valid bundle or, with none, stays closed, and never activates a bundle built after RFC-0002 (contracts, section 7.6).
- From spike S2, which ran this design with 1,000 enforcement points ([report](../../spikes/S2-watch-streams.md)):
  - serialize every governance state change, so versions commit in order, as the version counter does (the spike used a transaction-level advisory lock); otherwise a replica reading "every change after V" can skip one that commits late;
  - register a stream before reading its snapshot, then skip changes the snapshot already holds;
  - catch up on every notification and also every second, as the hub does (the spike caught up every five seconds), so a lost notification delays a change by one second at most;
  - send renewals only once a stream's pending change is sent (CORE-6), and only while the replica is current, which the spike did not check ([design note](P1-08-kill-switch.md#progress-notes), section 5), and drop streams that cannot keep up (CORE-7);
  - streams stay where they reconnected after a replica returns; ending them at token expiry (CORE-1) rebalances them over time.
