# ADR-0011: White Tower's own enforcement point for Python agents, instead of Microsoft AGT

- **Status:** Accepted
- **Date:** 2026-09-29
- **Related:** MOD-06, KIL-01, KIL-10, POL-03, NFR-02, NFR-04, NFR-08, ASM-01; [spike S1](../spikes/S1-agt.md); plans P0-05, P1-09, P1-14; ADR-0005

## Context

The charter describes Phase 1 as "inventory and identity, audit and basic UI, kill switch via AGT", and the MVP requirements made Microsoft's Agent Governance Toolkit (AGT) the first enforcement point, loaded inside the agent's process. The same requirements recorded AGT as a risk (ASM-01): Public Preview, frequent breaking changes, and no foundation after the Agentic AI Foundation declined to host it in June 2026. Plan P0-05 therefore made spike S1 a go or no-go decision, with a fallback already described: a minimal White Tower enforcement point in Python.

Spike S1 tested AGT 5.0.0 with Cedar and LangGraph. Its findings:

- **The contribution is thin.** AGT's kill switch is a callback registry with a 5-second timeout; it does not stop new actions. Its policy evaluator applies its own rules first and asks only the first external backend. White Tower has to build the gate, the lease timer, the Cedar evaluation, the layered halt, the durable evidence buffer and the module API client either way.
- **The guarantees are missing.** `kill()` reports `terminated=True` while a blocking tool keeps running, and the event pipeline dropped 75% of a burst by design (drop-oldest queue), where White Tower requires that no governed action happens without evidence.
- **The hooks do not reach the tool call.** The published framework adapters check AGT's own allow and block lists; the new policy runtime that evaluates external policies at intervention points is an alpha with native wheels for Linux x86-64 only.
- **It lags the frameworks.** Its LangGraph integration requires `langgraph<1.0`, while LangGraph is at 1.2.
- **Everything needed works without it.** `cedarpy` evaluates Cedar in-process with exactly the combination semantics of POL-03, at p99 ≤ 1.1 ms with 100 policies.

The maintainers also decided on 2026-09-29 that a halt blocks and denies everything the agent tries afterwards rather than killing it (KIL-01), and that AGT should be checked again live once real agents exist.

## Decision

- **The MVP enforcement point is White Tower's own Python package**, `whitetower-ep`, in `modules/ep-python/` (plan P1-09). It depends on `cedarpy` and the generated module API client, not on AGT. It provides the gate, the lease timer, bundle verification, Cedar evaluation with the policy set parsed once per bundle, the layered halt with honest acknowledgements, a durable evidence buffer written at decision time, and hooks for LangGraph 1.x first, then the frameworks the pilot needs.
- **Microsoft AGT becomes an interoperability adapter, a Phase 2 candidate**, for organizations that already run it: White Tower as an external backend of AGT's policy evaluator, AGT's events forwarded as supplementary evidence, and White Tower halts relayed to AGT's kill switch callbacks.
- **AGT is re-tested live during the pilot** (P1-14), with a real agent and AGT's latest release. The result feeds the Phase 2 priorities; it does not reopen this decision for the MVP.
- **The contracts stay engine-neutral.** Nothing in them depends on AGT or on White Tower's own enforcement point; P0-03 still maps them onto AGT, OPA, Cedar and an AuthZEN engine.

This departs from the charter's Phase 1 description. The charter's intent, a kill switch that works across agents, is unchanged; only the component that provides it inside the agent changes.

## Consequences

**Easier**
- One dependency fewer in the agent's process, and none in Public Preview. The enforcement point follows the frameworks' current releases instead of waiting for AGT to catch up.
- The guarantees the contracts need are designed in, not worked around: a gate before every governed call, no decision without evidence, and acknowledgements that never overstate what stopped.
- The same effort as an AGT-based adapter (spike S1, section 6), so the roadmap does not change.

**Harder**
- White Tower owns security-critical code that runs inside other people's agents. Mitigations: a deliberately small scope, `cedarpy` for evaluation, the conformance kit, weekly CI against the frameworks' latest releases, and network quarantine on Kubernetes (KIL-10) as an independent layer that does not trust the agent's process.
- Hooks must be written and maintained per framework. The MVP starts with LangGraph 1.x and adds only what the pilot needs.
- Organizations that standardized on AGT wait for the Phase 2 adapter.

## Alternatives considered

- **AGT as the foundation, as the charter says (option B of spike S1).** Pin 5.0.0, build the gate, backend, halt and buffer on top anyway, stay on LangGraph below 1.0, and wait for its new policy runtime to mature. More dependencies, the same work and weaker guarantees.
- **Wait for AGT to mature before deciding.** Its roadmap and governance are outside the project's control, and the Phase 1 critical path cannot wait for them.
- **No in-process enforcement point; gateways only.** LLM and MCP gateways do not depend on the agent's code, but they are Phase 2 modules and cannot stop an agent's own logic. They will complement the in-process gate, not replace it.
