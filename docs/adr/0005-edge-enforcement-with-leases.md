# ADR-0005: Decisions at the edge, governance state pushed with fail-closed leases

- **Status:** Proposed
- **Date:** 2026-09-28
- **Related:** NFR-01 to NFR-05, KIL-01 to KIL-07, MOD-04, POL-05; ADR-0003, ADR-0004. Answers open question Q1 of the requirements.

## Context

The charter sets requirements that pull against each other:

- **Fail-closed:** "If the policy plane does not respond, the action is not executed"; "if the core does not respond, the action is denied".
- **Latency:** "The policy decision must not become the bottleneck of the agent's action."
- **Kill switch:** it "must stop a running agent, not just revoke its next token", within a propagation time set in Phase 0.
- **Modularity:** the policy engine is an interchangeable module, not part of the core.

Calling the core synchronously for every agent action would satisfy fail-closed trivially, but it would make the core a latency bottleneck and a single point of failure for every agent. Relying only on short-lived tokens would not stop a running agent.

## Decision

1. **Decisions happen at the edge.** Enforcement points (EPs) evaluate policies locally, with an in-process engine or a decision point deployed next to them. The core is never called synchronously for each agent action.
2. **The core pushes governance state.** For each agent it publishes: lifecycle state, run state (running or halted), the reference of its effective policy bundle (version, hash and signature) and the fleet state. EPs subscribe through the module API `Watch` stream: they receive a full snapshot on connection, then changes, each with a monotonic version.
3. **Every EP holds a lease.** The core renews it over the stream. Its TTL is set by the core for each agent (60 s by default, shorter for higher risk tiers). **If the lease expires, the EP must fail closed: deny every action and halt the agent.** This is the operational meaning of "if the core does not respond, the action is denied".
4. **Bundles are signed by the core.** EPs verify the signature and refuse missing, unsigned or unverifiable bundles, denying every action until they get a valid one.
5. **The kill switch is a state change.** Halting sets the run state to halted and pushes it through the same stream. EPs interrupt the current action, block new ones and acknowledge. Token issuance stops at the same time, except for the enforcement point's own channel to the core (ADR-0010). For an EP cut off from the core, lease expiry bounds the worst case.
6. **Connecting EPs start closed.** An EP allows nothing until it has received the current state of its agents, so a halted agent cannot slip an action through while reconnecting (KIL-07).
7. **Evidence flows back asynchronously.** EPs send decisions and actions as audit events, buffered durably on local storage. If the local buffer cannot accept events, the EP fails closed.
8. **Strict mode is a later option.** For agents whose risk demands it, Phase 2 may add a synchronous check with the decision point on every action. Not part of the MVP.

## Consequences

**Easier**
- Per-action latency does not depend on the core or on the network to the core.
- Core outages shorter than the lease TTL, such as rolling upgrades, do not stop agents.
- The worst-case time to stop an agent that is cut off from the core is bounded by the TTL.
- One mechanism (watch stream and leases) carries policies, state and halts. It is the pattern of Kubernetes watches and Envoy's xDS, well understood by operators.

**Harder, and accepted**
- A core outage longer than the TTL stops every governed agent. This is fail-closed by design; operators must run the core highly available, and the TTL is a conscious trade-off between availability and worst-case halt time.
- An attacker able to cut EPs off from the core can stop agents (a denial of service turned against availability, never against safety). Covered in the threat model (P0-04).
- Policy updates reach EPs within seconds, not instantly; for emergencies, the tool is a halt, which is pushed and acknowledged.
- EP implementations must get lease handling right. The conformance kit tests it (MOD-05).

## Alternatives considered

- **Synchronous check against the core for every action.** Simple, but it makes the core a latency and availability bottleneck for the whole fleet. Rejected as the default; kept as the future strict mode, pointed at a decision point rather than the core.
- **Revocation through token expiry only.** Explicitly rejected by the charter, because a running agent keeps going.
- **A message broker for distribution** (NATS, Kafka). Adds a stateful component (ADR-0003). The watch contract hides the transport, so a broker can come later.
- **Polling instead of streaming.** Simpler for module authors, but propagation time would equal the polling interval. The Connect protocol already lets a plain HTTP client consume the stream.
