# P0-05: Technical spikes and NFR targets

| | |
| --- | --- |
| **Phase** | 0 Foundations |
| **Status** | In progress (see [progress notes](#progress-notes)) |
| **Size** | M (five spikes, time-boxed, can run in parallel) |
| **Depends on** | none; spike code lives in `hack/spikes/` |
| **Unblocks** | P0-03 (AGT facts), the Phase 0 gate (NFR targets), P1-02, P1-07, P1-08, P1-09 |
| **Requirements** | NFR-02 to NFR-09, MOD-06; open questions Q4 and Q5 |
| **Decisions** | ADR-0005, ADR-0006; may amend them |

## Goal

Remove the largest technical unknowns with time-boxed experiments. Set the numeric targets the charter leaves to Phase 0 (decision latency and kill switch propagation), backed by measurements. Decide whether Microsoft AGT can be the first enforcement point.

## Scope

**In:** five spikes, each answering one question with throwaway code, a short report and a recommendation.

**Out:** production code. Spike code is not promoted to production without a normal review and rewrite.

## Deliverables

- `docs/spikes/S1-agt.md` to `docs/spikes/S5-interruption.md`: question, method, results, recommendation.
- Requirements section 6 updated with measured targets; ADRs amended where needed.
- A go/no-go decision on AGT as the first enforcement point.

## Steps

### 1. S1: Microsoft AGT integration (time-box 2 weeks; decides go or no-go)

**Question:** can an external control plane (a) deliver policies to AGT, (b) halt a running agent governed by AGT, and (c) receive AGT's decisions and actions, with the guarantees the contracts need?

Known facts from the research of September 2026, to be confirmed hands-on:

- AGT is an **in-process library** with no remote control API. Its optional HTTP services run an older engine and do not authenticate callers, so they must not be relied on.
- **Only the Python SDK covers every component.** The Go SDK has no policy runtime, and its Rego and Cedar modes are mocks.
- **The kill switch is cooperative and differs per language.** In Python, `kill()` rolls back or hands off in-flight steps and runs a registered callback with a 5-second timeout. Without a callback, it reports that the agent was not terminated.
- **Policies:** YAML rules, Rego and Cedar. The newer policy runtime (ACS) attaches policies to eight intervention points, is alpha, and is changing its set of verdicts.
- **Audit:** CloudEvents 1.0 (`ai.agentmesh.*`) through a pluggable event sink with OTLP and stdout sinks.
- **Maturity:** Public Preview with frequent breaking changes; the Agentic AI Foundation declined to host it in June 2026.

**Method.**

1. Pin the latest released AGT Python package.
2. Build two sample agents, for example LangGraph and Microsoft Agent Framework (the latter has native AGT support).
3. Prototype the four adapter hooks of the architecture document (section 6.1): gate, policy source loaded from memory, halt through `kill()` with framework termination callbacks, event sink.
4. Check whether AGT evaluates **Cedar** and **Rego** in-process in Python, without an external OPA server or CLI (open question Q5).
5. Measure evaluation latency with 1, 10 and 100 policies, the time from a halt signal to the gate closing, and the time to interrupt an in-flight tool call and an in-flight streaming model call.
6. Compare the older engine (Agent OS) with ACS on stability and on the extension points available.

**Output.**

- The adapter design: which AGT engine, which hooks, the version pinning strategy.
- The measurements.
- The gaps and their workarounds.
- **Go or no-go.** If no-go, the fallback: a minimal White Tower enforcement point in Python (a gate, Cedar evaluation, framework hooks and the module API client, without AGT). P1-09 then targets it, and AGT moves to Phase 2.

### 2. S2: Watch streams, leases and halt propagation (time-box 1 week)

**Question:** can two core replicas push a halt to 1,000 connected enforcement points within the NFR-03 target, and do leases expire accurately?

**Method.** A ConnectRPC server in Go with two replicas behind a load balancer, PostgreSQL with `LISTEN/NOTIFY`, and 1,000 simulated EPs. Measure:

- halt propagation (p50, p95, p99), with the halt issued on either replica;
- how accurately leases expire when a network partition is simulated;
- the reconnection storm after a replica restart, with and without jittered backoff;
- memory and CPU per stream.

**Output.** Confirmed or amended NFR-03, NFR-05 and NFR-07; a default lease TTL per risk tier; implementation notes for P1-07 and P1-08.

### 3. S3: Audit log throughput (time-box 1 week)

**Question:** can PostgreSQL with Merkle tree sealing sustain the audit load of NFR-07 within the sealing delay of NFR-09?

**Method.** Ingest 200 events per second sustained and 2,000 per second in bursts; seal with `golang.org/x/mod/sumdb/tlog`; sign checkpoints every 60 seconds. Measure:

- the sealing delay;
- the time to verify 10 million events;
- dropping a monthly partition while keeping the tree hashes;
- inclusion and consistency proofs.

Compare with a plain hash chain.

**Output.** Confirmed or amended NFR-07 and NFR-09; the Merkle tree or hash chain decision for ADR-0006; batching parameters for P1-02.

### 4. S4: Policy evaluation latency (time-box 3 days)

**Question:** what does a policy decision cost?

**Method.** Measure evaluation latency with representative policies and inputs:

- in-process engines: cedar-go and OPA embedded in Go, plus AGT in Python (taken from S1);
- a remote decision point through an AuthZEN evaluation over HTTP, on localhost and across nodes of a cluster.

**Output.** NFR-02 set with numbers; input for the Phase 2 choice of a second policy engine.

### 5. S5: Interrupting agents in real frameworks (time-box 3 days, can merge into S1)

**Question:** what does "interrupt the action in flight" mean in practice for the frameworks the pilot will use?

**Method.** For LangGraph, the OpenAI Agents SDK and Microsoft Agent Framework: cancel a running tool call, a streaming model call and a multi-step plan. Record what can be cancelled cleanly, what needs process termination, and how long each takes.

**Output.** NFR-04 confirmed or amended; halt modes for agents (`block`, `interrupt`, `terminate`) with a default per framework; input for the adapter's termination callbacks.

### 6. Consolidate and present at the gate

Update section 6 of the requirements (targets set), amend ADR-0005 or ADR-0006 if needed, record the AGT decision, close open questions Q4 and Q5, and present the results at the Phase 0 gate.

**Done when:** each NFR marked "set in Phase 0" has a number backed by a measurement.

## Acceptance criteria

- Five spike reports, each with its method, raw numbers and recommendation.
- NFR-02 to NFR-05, NFR-07 and NFR-09 have measured targets in the requirements.
- A recorded go or no-go decision on AGT, with the fallback plan if no-go.
- Open questions Q4 and Q5 closed.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| AGT changes during the spike (frequent breaking changes) | Pin one version; record it in the report; the adapter's CI later tests against the latest release weekly |
| Spike code leaks into production | It lives in `hack/spikes/` and CI never builds it into artifacts |
| Laptop measurements are not representative | Run S2 and S3 on a small cluster similar to the pilot's (kind is acceptable for S2; S3 needs a real disk) |

## Notes for implementers

- Time boxes are hard limits: when one expires, write down what is known and what is not, then stop.
- Report distributions (p50, p95, p99, max), never averages alone.
- S1 is the riskiest spike and on the critical path to the contracts: start it on the first day of Phase 0.

## Progress notes

### 2026-09-29: S1 and S5 done

| Spike | Status | Result |
| --- | --- | --- |
| S1 AGT integration | Done | **No-go on AGT as the foundation of the MVP enforcement point: White Tower builds its own enforcement point in Python, and AGT becomes a Phase 2 interoperability adapter.** Accepted by the maintainer on 2026-09-29 in [ADR-0011](../../adr/0011-own-python-enforcement-point.md); AGT is re-tested live in the pilot (P1-14). Report: [S1-agt.md](../../spikes/S1-agt.md) |
| S5 Interrupting agents | Done (in the S1 report) | Asynchronous tools and streaming calls stop within milliseconds; blocking tools cannot be interrupted in-process, so the `terminate` halt mode and honest layered acknowledgements are needed |
| S2 Watch streams and halt propagation | Not started | |
| S3 Audit log throughput | Not started | |
| S4 Policy evaluation latency | Partly done | Python side measured in S1 (Cedar p99 ≤ 1.1 ms with 100 policies parsed once); Go side (cedar-go, embedded OPA) pending |

**Open question Q5 is closed:** Cedar is the primary language, and Rego is not evaluated in-process in Python.

