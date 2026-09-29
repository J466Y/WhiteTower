# Spike S4: policy evaluation latency

| | |
| --- | --- |
| **Plan** | [P0-05](../plans/phase-0/P0-05-spikes-and-nfr-targets.md), spike S4 |
| **Status** | Done |
| **Date** | 2026-09-29 |
| **Tested** | `cedar-go` 1.8.0 and OPA 1.21.0 with Go 1.27.1, on Windows 11 and a laptop CPU (Intel Core i5-1235U). The Python numbers come from [spike S1](S1-agt.md): `cedarpy` 4.12.1 |
| **Code** | [`hack/spikes/s4/`](../../hack/spikes/s4/README.md) |

## The question

What does one policy decision cost, in process and through a remote decision point? The answer sets NFR-02 ("the core is never in the synchronous path; policy evaluation at the enforcement point adds bounded latency") and informs the Phase 2 choice of a second policy engine.

## Summary

**Decisions cost microseconds in process, and well under a millisecond through a decision point on the same host. NFR-02 holds with a wide margin, and stays as proposed:** p99 ≤ 5 ms in process, p99 ≤ 20 ms for a decision point in the same cluster.

| Engine, 100 policies | p50 | p99 |
| --- | --- | --- |
| `cedar-go`, in process (Go) | 0.007 to 0.011 ms | 0.06 to 0.12 ms |
| `cedarpy`, in process (Python, S1) | 0.42 ms | 1.02 ms |
| OPA embedded, with the contract's Rego wrapper (Go) | 0.12 to 0.18 ms | 0.6 to 1.2 ms |
| AuthZEN decision point over HTTP on localhost, `cedar-go` behind it | 0.09 to 0.10 ms | 0.44 to 0.51 ms |

## Method

The program in [`hack/spikes/s4`](../../hack/spikes/s4/main.go) uses the policy shapes of spike S1: one global `forbid` and agent-specific `permit` rules, 1, 10 and 100 policies in total, and a request that the policies permit. It measures:

1. **`cedar-go` in process**, with the policy set parsed once per bundle. Each decision includes mapping the AuthZEN request to a Cedar request and entities, as an enforcement point does, and applies rule 4 of the combining algorithm (any error denies).
2. **OPA embedded**, with the same policies as Rego packages and the contract's wrapper ([`decision.rego`](../../api/policy/rego/decision.rego)), prepared once per bundle.
3. **A remote decision point**: an AuthZEN evaluation endpoint (`POST /access/v1/evaluation`) in front of `cedar-go`, called over HTTP/1.1 with keep-alive on localhost. Each decision includes JSON encoding on both sides.

Each measurement runs 10,000 decisions after 1,000 of warm-up, three times. Go's monotonic clock on Windows ticks about every half millisecond, too coarse for single decisions, so the spike reads `QueryPerformanceCounter`, as Python's `perf_counter` does in S1.

## Results

**Latency per decision, in milliseconds** (p50 / p99 / max; last run, the other two within the ranges of the summary):

| Policies | `cedar-go` in process | OPA embedded | AuthZEN over HTTP, localhost |
| --- | --- | --- | --- |
| 1 | 0.003 / 0.038 / 11.6 | 0.045 / 0.47 / 10.9 | 0.109 / 0.53 / 1.4 |
| 10 | 0.003 / 0.055 / 0.4 | 0.052 / 0.47 / 9.7 | 0.102 / 0.44 / 5.7 |
| 100 | 0.007 / 0.060 / 0.2 | 0.121 / 0.60 / 1.3 | 0.089 / 0.44 / 1.2 |

**Activating a bundle, in milliseconds** (parsing or preparing its policies once):

| Policies | `cedar-go` parse | OPA prepare |
| --- | --- | --- |
| 1 | 0.06 | 1.7 |
| 10 | 0.06 | 2.6 |
| 100 | 1.2 | 9.4 |

## Findings

1. **Cedar in Go decides in microseconds.** With 100 policies, a decision, request mapping included, takes 7 to 11 µs at p50 and at most 0.12 ms at p99 over three runs: about forty times under the in-process target. Python with `cedarpy` (S1) is several times slower and still five times under it.
2. **OPA with the wrapper grows with the number of policies**: the wrapper visits every policy package on each decision. At 100 policies it is still near 1 ms at p99. An engine with thousands of policies would need the packages indexed, for example by resource type: a note for the Phase 2 engine.
3. **A decision point on the same host adds about 0.1 ms at p50 and 0.5 ms at p99**, JSON on both sides included, provided connections are reused. Between nodes, the network round trip adds to it; spike S2's cluster measures that.
4. **Activating a bundle is cheap**: at most 1.2 ms to parse 100 Cedar policies, and 9.4 ms for OPA to prepare them. Bundles change on the scale of minutes, so this never matters.
5. **Occasional outliers of 5 to 30 ms** (the max column) come from garbage collection and the scheduler of a busy laptop. p99 is the right target; an enforcement point with strict needs can tune its runtime's memory settings.

## Recommendation for NFR-02

Keep the proposed targets, now backed by measurements:

- **p99 ≤ 5 ms in process.** Measured: ≤ 0.12 ms in Go and ≤ 1.02 ms in Python, with 100 policies. The margin covers slower hosts, larger policy sets and the gate.
- **p99 ≤ 20 ms for a decision point in the same cluster.** Measured: ≤ 0.53 ms on localhost; the network between nodes is to be confirmed in S2's cluster.

**Not covered:** the durable write of each decision before the action proceeds (obligation EP-8 of the module contracts) adds disk latency to every decision. The target covers it, and plan P1-09 measures it with the real enforcement point.

## Input for the Phase 2 engine choice

- **OPA embedded** fits the latency target at MVP scale with the standard wrapper; indexing is needed for very large policy sets.
- **A decision point through AuthZEN** costs a fraction of a millisecond on the same host, so the Phase 2 gateways can call one without threatening NFR-02.
- **Cedar** remains the fastest option in both languages tested.

## Limitations

- One laptop with Windows 11; server CPUs are typically steadier.
- Synthetic policies: equality conditions only. Policies with many conditions, sets or tags cost more, though the Cedar vectors of the contracts show no case close to a millisecond.
- No measurement across cluster nodes (left to S2), and no concurrent load: decisions ran one at a time.
