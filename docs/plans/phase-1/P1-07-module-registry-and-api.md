# P1-07: Module registry and module API

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L |
| **Depends on** | P0-03, P1-01, P1-05 (can start with stub authentication) |
| **Unblocks** | P1-08, P1-09, P1-10.5 |
| **Requirements** | MOD-01 to MOD-05, MOD-07, KIL-07, AUD-02 (ingestion wiring) |
| **Decisions** | ADR-0004, ADR-0005 |

## Goal

The core side of the module contracts: modules are registered and approved, their instances connect and are authorized, governance state reaches every enforcement point through watch streams with leases, acknowledgements come back, and events flow into the audit log. A reference module and the conformance kit prove the contract works.

## Scope

**In:** the generated code, authentication and authorization on the machine listener, module registration, instance sessions, the governance state service and watch fan-out, acknowledgements, ingestion wiring, the mock reference module, the conformance kit, load tests.

**Out:** the kill switch domain (P1-08, which writes the governance state through the service built here); bundles (P1-06); the Python enforcement point (P1-09); the network quarantine module (P1-15).

## Deliverables

- `internal/modules`, `internal/govstate`, `internal/api/moduleapi`.
- `modules/mock`: a Go reference enforcement point.
- `test/conformance`: the conformance kit runner (`wt-conformance`) with every P0-03 scenario.
- A load test report.

## Steps

### 1. Generated code

Run `buf generate` for the Go server, the Go client (used by the mock module and the conformance kit) and the Python client (used by P1-09).

**Done when:** the three outputs build and are part of the drift check.

### 2. Authentication and authorization

- Verify White Tower access tokens (own JWKS, audience of the module API).
- Two kinds of caller:
  - **enforcement points embedded in an agent**, whose subject is the agent's SPIFFE ID, may only serve that agent;
  - **module instances**, whose subject is a module's SPIFFE ID, may only serve the agents bound to the module by an operator.
- The event types a caller may publish are those its manifest declares.

**Done when:** negative tests pass: watching another agent, publishing undeclared types, and using an expired token or one with the wrong audience are all rejected.

### 3. Module registration

REST operations for operators:

- upload a manifest, validated against the JSON Schema;
- approve or revoke a module;
- create the module's credentials through P1-05;
- bind a module to agents;
- list the module catalog.

Everything is audited.

**Done when:** a module goes from manifest upload to approved and connected, and revoking it disconnects its instances.

### 4. Instance sessions

- `RegisterInstance` records the instance ID, module, version, supported contract versions, agents served and host details, then negotiates the contract version.
- Instances have a status: connected, last seen, lease state.
- `/api/v1/agents/{id}/instances` and a module's instance list show them.

**Done when:** instances appear, update and disappear as they connect, heartbeat and drop.

### 5. Governance state service (subplan candidate)

- One state record per agent, as defined in P0-02, versioned from one global sequence. Writers (inventory, policy, kill switch) update it inside their own transactions.
- After commit, a notification goes out through `notify.Bus`, and each replica's hub fans the change out to its watch streams, filtered by the agents each stream serves.
- A new or lagging stream gets a snapshot; otherwise it resumes from the last version it saw. Lease renewals are sent every third of the TTL.
- A slow consumer has a bounded buffer. When it overflows, the stream is closed with a "resynchronize" code; the enforcement point reconnects and receives a snapshot. State is never dropped silently.
- Metrics: open streams, lag, send latency.

**Done when:** tests prove ordering, resumption, snapshots after a gap, and slow-consumer handling.

### 6. Acknowledgements

`Acknowledge` receives halt acknowledgements (with each layer reported separately), bundle activations and observed states. It is idempotent on the instance, subject and version. It feeds drift detection (P1-06) and halt propagation tracking (P1-08).

**Done when:** duplicates are harmless, and acknowledgements from an instance that does not serve the agent are rejected.

### 7. Event ingestion

Wire `EventService.Publish` to the ingestion logic of P1-02 (step 5), with per-instance rate limits and counters used as health signals.

**Done when:** events from the mock module appear in the audit log, sealed.

### 8. Mock reference module (MOD-07)

`modules/mock` is a faithful enforcement point in Go:

- it registers, watches and keeps its lease;
- it verifies bundles (signature, hashes, monotonic version) and evaluates Cedar policies with `cedar-go`, using the White Tower combination semantics;
- it simulates actions at a configurable rate and publishes events through a durable file buffer;
- it halts and acknowledges each layer;
- flags inject faults: drop acknowledgements, delay them, crash, lie.

It serves tests, demos and load tests. It is also the reference implementation module authors can read.

**Done when:** the mock module passes every conformance scenario.

### 9. Conformance kit (MOD-05, subplan candidate)

Implement every P0-03 scenario in `test/conformance`. The `wt-conformance` runner plays the core against a module under test and produces JUnit XML plus a readable report. It runs in CI against the mock module and is documented for third-party authors.

**Done when:** the kit fails on each fault the mock module can inject, and passes without faults.

### 10. Load test

Using the P0-05 S2 setup at production shape:

- 500 or more concurrent streams across two replicas;
- fan-out timing of a state change;
- a rolling restart of one replica while streams are open;
- memory per stream.

Publish the results.

**Done when:** the report is in `docs/performance/` and the acceptance numbers below are met.

### 11. Tests

- Permission negatives.
- Version negotiation.
- Correctness of resumption.
- Slow consumers.
- Instance lifecycle.

**Done when:** all run in CI.

## Acceptance criteria

- The mock module passes the full conformance suite in CI.
- With 500 concurrent streams on two replicas, state changes are delivered with p95 ≤ 1 second (part of NFR-03's budget).
- During a rolling restart of one replica, every enforcement point reconnects within 30 seconds without losing a change, and no lease expires with the default TTL.
- Instances and their state are visible through the API.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Load balancers cut long-lived HTTP/2 streams | Keepalives, a documented idle timeout, and resumption from the last version on reconnect |
| Fan-out storms when a global policy changes every agent's state | Coalescing in the hub (only the latest version per agent is sent), and a chunked bundle rebuild in P1-06 |
| The mock module drifts from the specification | It is the reference: every contract change updates it and the kit in the same pull request |

## Notes for implementers

- `connect-go` server streams map to plain `http.Handler`s, so TLS and middleware stay shared with the rest of the machine listener.
- Send the snapshot and later changes through one ordered channel per stream, to avoid races between them.
- Enforcement points start closed. The contract (and the kit) makes the "no action before state" rule testable (KIL-07).
- From spike S2, which ran this design with 1,000 enforcement points ([report](../../spikes/S2-watch-streams.md)):
  - serialize every governance state change with a transaction-level advisory lock, so versions commit in order; otherwise a replica reading "every change after V" can skip one that commits late;
  - register a stream before reading its snapshot, then skip changes the snapshot already holds;
  - catch up on every notification and also every few seconds, so a lost notification delays a change but never loses it;
  - send renewals only once a stream's queue is drained (CORE-6), and drop streams that cannot keep up (CORE-7);
  - streams stay where they reconnected after a replica returns; ending them at token expiry (CORE-1) rebalances them over time.
