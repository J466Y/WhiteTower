# Spike S2: watch streams, leases and halt propagation

| | |
| --- | --- |
| **Plan** | [P0-05](../plans/phase-0/P0-05-spikes-and-nfr-targets.md), spike S2 |
| **Status** | Done |
| **Date** | 2026-09-29 |
| **Tested** | Two core replicas and 1,000 simulated enforcement points on one laptop (Windows 11, Intel Core i5-1235U), Go 1.27.1, PostgreSQL 17.11 in Docker, TLS 1.3 and HTTP/2, the module API `v1alpha1` |
| **Code** | [`hack/spikes/s2/`](../../hack/spikes/s2/README.md); raw numbers in [`results-1000.json`](../../hack/spikes/s2/results-1000.json) |

## The question

Can two core replicas push a halt to 1,000 connected enforcement points within the NFR-03 target, and do leases expire accurately? And what does a lost replica, or a lost core, do to the fleet?

## Summary

**Yes, with a wide margin.** A fleet halt reaches and is acknowledged by 1,000 enforcement points with p95 at 0.63 s and a maximum of 0.74 s; an agent halt takes about 10 ms. Leases expire within 10 ms of their TTL. A crashed replica's 500 enforcement points move to the other replica in 0.6 s, with no lease expiry.

**One change is needed, in the module contracts:** reconnection backoff must be bounded by the lease. With a classic 30-second cap, a five-second outage of the whole core left 6 to 8% of the fleet failed closed and took 27 s to recover. With the cap at a third of the lease TTL, and the backoff reset once a session receives a renewal, the same outage caused no expiry and recovery took 5 s.

| Target | Result with 1,000 enforcement points | Verdict |
| --- | --- | --- |
| NFR-03: halt propagation p95 ≤ 2 s, max ≤ 5 s | Fleet halts: p95 0.63 s, max 0.74 s. Agent halts: max 19 ms | Confirmed |
| NFR-05: lease backstop, default TTL 60 s, 10 to 300 s per risk tier | Expiry 15.005 to 15.010 s after the last renewal, with a 15 s TTL | Confirmed; defaults kept |
| NFR-06: rolling upgrades do not stop agents | A crashed replica's streams recover in 0.6 s | Confirmed |
| NFR-07: 500 concurrent enforcement point connections | 1,000 streams on two replicas: about 50 KiB of live heap and 3 goroutines per stream, 3 to 4% of one core per replica while idle | Confirmed, with headroom |

## Method

The program in [`hack/spikes/s2`](../../hack/spikes/s2/README.md) starts, as separate processes:

- **two core replicas** serving the real module API (`Watch`, `Acknowledge`) over TLS and HTTP/2. They follow governance changes through PostgreSQL `LISTEN/NOTIFY`, and issue halts and releases through the real schema with the runtime role, including the two-person release its triggers enforce;
- **a layer 4 load balancer**, round robin, as a Kubernetes Service would be;
- **1,000 simulated enforcement points**, each an agent's embedded enforcement point with its own TLS connection. Each keeps its lease on the monotonic clock, acknowledges the gate layer as soon as it sees a halt, detects dead connections with HTTP/2 pings (after 5 s of silence, 3 s to answer) and reconnects with backoff.

The critical risk tier's lease TTL, 15 s with renewals every 5 s, was used throughout, since it is the tightest. The scenarios were:

1. 20 agent halts and 5 fleet halts, issued alternately on each replica and released through the other. Latency runs from the halt's commit to each acknowledgement's commit, both on the database clock.
2. A network partition of 50 enforcement points for 20 s, simulated on their sockets (what arrives is lost, what they send never leaves, and they cannot reconnect), then healed.
3. Reconnection storms: one replica killed, then the whole core killed for 5 s. Each ran with two backoff policies, with and without jitter:
   - **classic**: a 30 s cap, reset after 30 s of healthy session;
   - **lease**: a cap of a third of the lease TTL, reset as soon as a session receives a renewal.

## Results

**Halt propagation**, in milliseconds (n / p50 / p95 / p99 / max):

| Halt | From issue to acknowledgement recorded | From issue to receipt by the enforcement point |
| --- | --- | --- |
| 20 agent halts, both replicas | 20 / 9 / 13 / 19 / 19 | |
| Fleet halt 1 | 1,000 / 215 / 327 / 335 / 341 | 1,000 / 38 / 92 / 123 / 124 |
| Fleet halt 2 | 1,000 / 189 / 314 / 325 / 327 | 1,000 / 51 / 85 / 89 / 89 |
| Fleet halt 3 | 1,000 / 292 / 426 / 437 / 447 | 1,000 / 113 / 150 / 155 / 156 |
| Fleet halt 4 | 1,000 / 214 / 428 / 440 / 447 | 1,000 / 58 / 99 / 110 / 110 |
| Fleet halt 5 | 1,000 / 535 / 700 / 726 / 736 | 1,000 / 189 / 300 / 310 / 312 |
| All fleet acknowledgements | 5,000 / 243 / 632 / 700 / 736 | |

No acknowledgement was missing, and the replica that issued a halt made no difference.

**Leases and partitions** (50 enforcement points cut off for 20 s), in seconds:

| Measure | p50 | p95 | max |
| --- | --- | --- | --- |
| Last renewal to fail-closed | 15.005 | 15.010 | 15.010 |
| Partition start to fail-closed | 13.9 | 14.8 | 14.9 |
| Heal to recovered, lease backoff | 2.4 | 4.8 | 5.7 |
| Heal to recovered, classic backoff | 3.0 | 14.8 | 21.8 |

**Reconnection storms**, recovery measured from the kill (one replica) or from the restart (whole core):

| Storm | Backoff | Jitter | Reconnecting | Recovery | Attempts | Peak per 100 ms | Lease expiries | CPU |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Replica A crashes | lease | yes | 500 | 0.65 s | 500 | 105 | 0 | 178% of a core on the survivor |
| Replica A crashes | lease | no | 500 | 0.58 s | 500 | 110 | 0 | 154% |
| Replica A crashes | classic | yes | 500 | 0.56 s | 500 | 109 | 0 | 133% |
| Replica A crashes | classic | no | 500 | 0.55 s | 500 | 119 | 0 | 161% |
| Whole core down for 5 s | lease | yes | 1,000 | 4.95 s | 5,111 | 233 | **0** | 31% per restarted replica |
| Whole core down for 5 s | lease | no | 1,000 | 5.02 s | 5,029 | 258 | **0** | 28% |
| Whole core down for 5 s | classic | yes | 1,000 | 26.5 s | 4,969 | 260 | **78** | 7% |
| Whole core down for 5 s | classic | no | 1,000 | 26.8 s | 4,943 | 249 | **62** | 7% |

**Resources**, per replica with 500 streams: live heap from about 0 to 25 MiB, total memory from 10 to 78 MiB, 1,525 goroutines, 3 to 4% of one core while only renewals flow. The simulator used 233 MiB and 3,023 goroutines for its 1,000 enforcement points.

## Findings

1. **Halts are fast because nothing waits.** A halt is one transaction and one `NOTIFY`; each replica reads the change and pushes it to its streams at once. Delivery to the enforcement point takes 90 to 310 ms at p99 for the whole fleet. The rest of the acknowledgement time is 1,000 acknowledgements written in a burst, through 20 connections per replica.
2. **Leases behave exactly as specified.** An enforcement point fails closed one TTL after its last renewal, to the tens of milliseconds, on its own monotonic clock. With renewals every third of the TTL, a partition fails it closed between two thirds of the TTL and the full TTL after the partition starts.
3. **Losing a replica is invisible to agents.** Its enforcement points reconnect through the load balancer to the other replica within one backoff step. Rolling upgrades therefore do not stop agents (NFR-06). Streams stay on the surviving replica until they reconnect; the rule that a stream ends when its token expires (CORE-1, at most 15 minutes) rebalances them over time.
4. **Reconnection backoff must be bounded by the lease.** Against a core that is down, reconnection attempts fail within milliseconds, so exponential backoff grows fast: in five seconds it reaches 8 to 16 s. Once the core returns, some enforcement points wait longer than their remaining lease, and fail closed although the core is back. Bounding the backoff by a third of the TTL removes the problem. After a whole-core outage, every enforcement point then reconnects within one renewal interval, at the cost of more attempts during the outage: about 2,500 per second for 1,000 enforcement points, which a load balancer rejects cheaply.
5. **Jitter made little difference here,** because failures are detected at slightly different moments and the storms spread by themselves. It stays required: it is cheap, and larger fleets or synchronized failures need it.
6. **Version order must equal commit order.** Versions come from a sequence, which hands them out when transactions call it, not when they commit. A replica that reads "every change after version V" can skip a change that commits late with a lower version. The spike holds a transaction-level advisory lock for every governance state change, so versions commit in order. Governance changes are rare, so the serialization costs nothing measurable.

## Changes this spike asks for

- **Module contracts, obligation I-4:** the reconnection backoff's cap MUST NOT exceed a third of the shortest lease TTL the instance holds, and the backoff MUST return to its first step once a session has received a lease renewal. Scenario S-12 checks both.
- **Plans P1-07 and P1-08**, implementation notes:
  - serialize governance state changes with a transaction-level advisory lock;
  - register a stream before reading its snapshot, then skip changes the snapshot already holds;
  - catch up on every notification and also every few seconds, so a lost notification delays a change but never loses it;
  - send renewals only once a stream's queue is drained, and drop streams that cannot keep up;
  - write acknowledgements in batches.
- **Plan P1-09:** the enforcement point uses the bounded backoff, and HTTP/2 pings to detect dead connections before its lease expires.
- **Requirements:** NFR-03, NFR-05, NFR-06 and NFR-07 are confirmed by measurement. The default lease TTLs stay as they are: 60, 60, 30 and 15 s for the low, medium, high and critical risk tiers. With 15 s, an outage of the whole core longer than about 5 s can fail critical agents closed, which is the intended trade-off for them.

## Limitations

- **One machine.** Everything ran on one laptop, over loopback: the replicas, the load balancer, 1,000 enforcement points and PostgreSQL. Network latency between hosts adds to every number, and a dedicated server would be faster than this shared laptop.
- **Not fully production-shaped.** The replicas did not authenticate callers or validate tokens, and served only `Watch` and `Acknowledge`; the real core does more on every connection.
- **Simulated partitions.** The partitions were simulated on the enforcement points' sockets, not in the network. A real partition also stalls the core's writes, which the ping timeouts and CORE-7 handle.
- **Largely deterministic scenarios.** Real fleets fail in messier ways, and P1-08 and the pilot keep measuring.
