# P1-07: Module registry and module API

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | In progress (1 of 13 pull requests); the rest after P1-05 |
| **Size** | XL, split into two subplans: **[P1-07.1](P1-07-module-registry-and-api/P1-07.1-module-api-and-governance-state.md)** (steps 1 to 7, about 5 weeks: generated code, authentication and authorization, registration, sessions, the governance state service with the blocks record, acknowledgements, event ingestion) and **[P1-07.2](P1-07-module-registry-and-api/P1-07.2-mock-module-kit-and-load-test.md)** (the tooling reports of step 7, once P1-16's pull request 3 is merged, then steps 8 to 10, about 3 weeks: the mock module, the conformance kit with S-01 to S-32, the load test). The first pull request of P1-07.1 is the version mechanism of the halt path ([design note](P1-08-kill-switch.md#progress-notes), section 14), which needs nothing from P1-05 and lands ahead of it |
| **Depends on** | P0-03, P1-01, P1-05 (can start with stub authentication); P0-03 step 12 (RFC-0002 in the contracts) for the parts of RFC-0002; P1-16 step 4 for the wiring of tooling reports (step 7) |
| **Unblocks** | P1-08, P1-09, P1-10.5; P1-04 pull request 4, through the first pull request of P1-07.1; P1-16 step 7, through the blocks record of step 5 and, for ST-80, the mock module of step 8 |
| **Requirements** | MOD-01 to MOD-05, MOD-07, KIL-07, AUD-02 (ingestion wiring); the transport of CAT-01 and CAT-04, and part of NFR-24's budget |
| **Decisions** | ADR-0004, ADR-0005, [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) |

## Goal

The core side of the module contracts: modules are registered and approved, their instances connect and are authorized, governance state reaches every enforcement point through watch streams with leases, acknowledgements come back, and events flow into the audit log. A reference module and the conformance kit prove the contract works. Once RFC-0002 is in the contracts, tooling reports also reach the catalog, and organization-wide blocks reach every enforcement point as fast as halts, without slowing them.

## Scope

**In:** the generated code, authentication and authorization on the machine listener, module registration, instance sessions, the governance state service and watch fan-out, acknowledgements, ingestion wiring, the mock reference module, the conformance kit, load tests. Once P0-03 step 12 has put RFC-0002 in the contracts: the generated code, the authorization and the wiring of `RegistryService.ReportTooling` and `RegistryService.ReportDefinitions`, the blocks record of the watch stream, the mock module's side of RFC-0002, the scenarios S-18 to S-24 and S-32 with the kit's model provider, and the load test with blocks.

**Out:** the kill switch domain (P1-08, which writes the governance state through the service built here); bundles (P1-06); the Python enforcement point (P1-09); the network quarantine module (P1-15); RFC-0002's contract text, protobuf, schemas and vectors (P0-03 step 12); the catalog domain: validating reports, storing observations and definitions, issuing and lifting blocks (P1-16, which writes blocks through the service built here).

## Deliverables

- `internal/modules`, `internal/govstate`, `internal/api/moduleapi`.
- `modules/mock`: a Go reference enforcement point.
- `test/conformance`: the conformance kit runner (`wt-conformance`) with every scenario of P0-03 and RFC-0002, S-01 to S-32.
- A load test report, with and without 500 active blocks.

## Subplans

| Subplan | Steps | Size | What it builds |
| --- | --- | --- | --- |
| [P1-07.1: Module API and governance state](P1-07-module-registry-and-api/P1-07.1-module-api-and-governance-state.md) | 1 to 7 | L, about 5 weeks | Generated code, authentication and authorization, module registration, instance sessions, the governance state service with the blocks record, acknowledgements and event ingestion. Its first pull request is the version mechanism of the halt path, which needs nothing from P1-05 and lands before P1-04 pull request 4 |
| [P1-07.2: Mock module, conformance kit and load test](P1-07-module-registry-and-api/P1-07.2-mock-module-kit-and-load-test.md) | The tooling reports of 7, and 8 to 10 | M, about 3 weeks | The wiring of tooling reports, once P1-16's pull request 3 is merged; the mock reference module; the conformance kit with S-01 to S-32; the load test |

Each subplan holds its steps, under the plan's step numbers, and its table of pull requests. Each pull request brings the tests of its steps.

## Acceptance criteria (both subplans)

- The mock module passes the full conformance suite in CI.
- With 500 concurrent streams on two replicas, state changes are delivered with p95 ≤ 1 second (part of NFR-03's budget).
- During a rolling restart of one replica, every enforcement point reconnects within a third of the shortest lease TTL it holds (I-4) without losing a change, and no lease expires with the default TTL.
- Instances and their state are visible through the API.
- The mock module passes scenarios S-18 to S-24 and S-32, and the kit fails on each fault of RFC-0002 that the mock module can inject.
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
- An instance that does not know blocks ignores them (EP-10). That is safe because every bundle now carries a catalog file, which such an instance rejects at step V4 (`invalid_manifest`): it keeps deciding with its last valid bundle, under policies the core has since replaced, or, with none, stays closed, and never activates a bundle built after RFC-0002 (contracts, section 7.6). It reports `HEALTH_DEGRADED`, and the core flags the drift (EP-7).
- From spike S2, which ran this design with 1,000 enforcement points ([report](../../spikes/S2-watch-streams.md)):
  - serialize every governance state change, so versions commit in order, as the version counter does (the spike used a transaction-level advisory lock); otherwise a replica reading "every change after V" can skip one that commits late;
  - register a stream before reading its snapshot, then skip changes the snapshot already holds;
  - catch up on every notification and also every second, as the hub does (the spike caught up every five seconds), so a lost notification delays a change by one second at most;
  - send renewals only once a stream's pending change is sent (CORE-6), and only while the replica is current, which the spike did not check ([design note](P1-08-kill-switch.md#progress-notes), section 5), and drop streams that cannot keep up (CORE-7);
  - streams stay where they reconnected after a replica returns; ending them at token expiry (CORE-1) rebalances them over time.

## Progress notes

### 2026-10-26: split into two subplans

As the plans' splitting rule asks of an XL plan, the steps moved into two subplans before work starts, under their numbers and with their text unchanged, but for their links and three lines that the split needed:

- step 7's tooling reports went to P1-07.2, which starts once P1-16's pull request 3 is merged, and step 7's check in P1-07.1 no longer waits for the mock module;
- the tests of the former step 11 went to the subplan of the steps they test;
- the steps lost their marks of subplan candidate.

Each subplan has its table of pull requests. The first pull request of P1-07.1 is the version mechanism of the halt path, row 1 of the work queue in [AGENTS.md](../../../AGENTS.md).
