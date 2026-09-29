# Spike S1: Microsoft AGT integration (with S5: interrupting agents)

| | |
| --- | --- |
| **Plan** | [P0-05](../plans/phase-0/P0-05-spikes-and-nfr-targets.md), spikes S1 and S5 |
| **Status** | Done. Option A was accepted on 2026-09-29 ([ADR-0011](../adr/0011-own-python-enforcement-point.md)); AGT is re-tested live in the pilot |
| **Date** | 2026-09-29 |
| **Tested** | `agent-governance-toolkit-core` and `-integrations` 5.0.0 (published 2026-08-03), `cedarpy` 4.12.1, LangGraph 0.6.11, Python 3.13 on Windows 11 |
| **Code** | [`hack/spikes/agt/`](../../hack/spikes/agt/README.md): three probes, reproducible |

## The question

Can an external control plane use Microsoft AGT to deliver policies to an agent, halt the running agent, and receive its decisions and actions, with the guarantees the White Tower contracts need (ADR-0005)? And what does "interrupt the action in flight" mean in practice?

## Summary

**Recommendation: no-go on AGT as the foundation of the MVP's enforcement point. Build the fallback that plans P0-05 and P1-09 already describe, a minimal White Tower enforcement point in Python, and keep AGT as an interoperability adapter in Phase 2.**

The reasons, each backed by a finding below:

1. **What AGT would contribute is thin.** Its kill switch is a callback registry with a timeout. Its policy evaluator consults only the first external backend. Its event pipeline drops events under load. White Tower has to build its own gate, halt, Cedar evaluation and durable evidence buffer either way.
2. **It does not give the guarantees we need.** Its `kill()` reports `terminated=True` while a blocking tool keeps running, and its event queue dropped 75% of a burst in our test.
3. **Its extension points do not reach the tool call.** In the published 5.0.0, the framework adapters check tools against AGT's own simple allow and block lists. The new policy runtime (ACS) that would evaluate external policies at intervention points is an alpha, with native wheels for Linux x86-64 only.
4. **It lags behind the frameworks and is still moving.** Its LangGraph integration requires `langgraph<1.0`, while LangGraph is at 1.2. Its packages are mid-consolidation: the meta package is 4.1.0 and the subpackages 5.0.0, and imports emit deprecation warnings. Add Public Preview status, and the Agentic AI Foundation declining to host it.
5. **The fallback costs about the same, and removes a fragile dependency.** Everything White Tower needs works with `cedarpy` alone: Cedar in-process with our exact semantics, sub-millisecond decisions and schema validation.

This departs from the charter, which says Phase 1 runs its kill switch through AGT. **The maintainers accepted it on 2026-09-29** ([ADR-0011](../adr/0011-own-python-enforcement-point.md)), and asked for AGT to be re-tested live once real agents exist (P1-14).

## What was tested

Three probes, all in [`hack/spikes/agt/`](../../hack/spikes/agt/README.md):

| Probe | What it does |
| --- | --- |
| `probe_cedar.py` | Evaluates White Tower-shaped requests with Cedar in-process, checks the combination semantics, measures latency, validates policies against a schema, and plugs a White Tower backend into AGT's `PolicyEvaluator` |
| `probe_halt.py` | Runs a LangGraph graph, halts it through a White Tower gate and AGT's `KillSwitch` while an asynchronous tool, a blocking tool or a streaming model call is in flight, and measures what stopped |
| `probe_events.py` | Converts an AGT event to CloudEvents and floods AGT's event processor to see what happens under load |

No real LLM was used: streaming was simulated with timed tokens, which is enough to test interruption.

## Findings

### 1. Packaging and maturity

- **Package versions disagree.** The meta package `agent-governance-toolkit` is at 4.1.0 (June 2026) and pins its subpackages below 5.0, while `agent-governance-toolkit-core` and `-integrations` are at 5.0.0 (August 2026). Installing "AGT 5" means installing the subpackages directly.
- **Imports are deprecated.** Importing `agent_os` from `agent-governance-toolkit-core` 5.0.0 warns that "agent-os-kernel is deprecated and will be removed in a future release".
- **The LangGraph extra is behind.** It requires `langgraph<1.0,>=0.2.0`; installing it next to LangGraph 1.2 fails with a dependency conflict.
- **The new policy runtime is not usable yet.** ACS is published as `agent-control-spec` 0.4.0a4 (2026-09-26), depends on `agent-hooks-sdk` 0.1.0a5, and ships a native wheel for Linux x86-64 only: none for Windows, macOS or ARM. AGT 5.0's `_v5_runtime_bridge` needs it; the `agt` module is not importable without it.
- **The code base is large and duplicated.** The core package alone has about 540 Python files. Two parallel policy stacks coexist (`agent_os.policies` and `agentmesh.governance`), as the foundation's reviewers noted.

### 2. Policies

**Cedar runs in-process, with White Tower's semantics.** One Cedar policy set holding the global and the agent-specific policies gives exactly the combination semantics of requirement POL-03, because Cedar itself applies "forbid overrides permit" and denies by default:

| Case | Decision |
| --- | --- |
| Agent-specific permit | allow |
| Agent-specific permit, internal email | allow |
| Global forbid against an agent-specific permit | deny |
| No applicable permit | deny |
| Unknown agent | deny |

Three more properties matter for us:

- **A policy set that does not parse denies everything** (fail-closed).
- **`cedarpy.validate_policies` checks policies against a schema** and names the error, for example `unrecognized action WhiteTower::Action::"tool.invok"`. This is what P1-06 needs before approval.
- **Rego does not run in-process.** AGT's `OPABackend` either calls the `opa` binary as a subprocess on every decision or queries a remote OPA server; its "builtin" mode is a mock. This confirms Cedar as the primary language (open question Q5).

**AGT's evaluator adds constraints and little value.**

- **Rule order.** `PolicyEvaluator` applies its own YAML rules first, by priority, first match wins; that is not our semantics.
- **Backend order.** It then asks only the first registered external backend. Global and agent-specific policies therefore cannot be separate backends: they must be one Cedar set.
- **Fail-closed.** It fails closed on backend errors, which is good.
- **Request shape.** Its `CedarBackend` hard-codes the entity types `Agent` and `Resource` and derives actions from tool names, which does not match our AuthZEN-aligned request profile. A White Tower backend is about 25 lines on top of `cedarpy`.

**Latency per decision, in milliseconds** (p50 / p99, 2,000 decisions, Windows workstation):

| Policies | Text parsed on every call | Policy set parsed once |
| --- | --- | --- |
| 1 | 0.14 / 0.55 | 0.07 / 0.30 |
| 10 | 0.31 / 0.96 | 0.09 / 0.38 |
| 100 | 3.20 / 6.66 | 0.42 / 1.02 |
| 10, through AGT's `PolicyEvaluator` | | 0.21 / 0.53 |

Parsing once, when a bundle is activated, is essential at 100 policies. Even in Python, a decision stays well under NFR-02's proposed 5 ms (p99).

### 3. Halting (S1 and S5)

**AGT's kill switch is a thin callback registry.**

- **What `kill()` does:** it runs the callback registered for the agent in a daemon thread, waits at most 5 seconds, and reports `terminated=True` if the callback returned without error. Nothing more: it does not stop new actions, emits no event, and unregisters the agent afterwards, so a second kill needs a new registration.
- **What `terminated` means:** only that the callback returned.

**Measured halts in LangGraph.** A White Tower gate was closed first, then AGT's `kill()` was called with a callback that cancels the graph's task and waits for it to finish.

| Work in flight | Gate closed | `kill()` returned | Graph task stopped | Work actually stopped |
| --- | --- | --- | --- | --- |
| Asynchronous tool (such as an HTTP call) | 0.004 ms | 1.1 ms, `terminated=True` | Yes | Yes |
| Streaming model call | 0.012 ms | 3.1 ms, `terminated=True` | Yes | Yes |
| **Blocking tool in a worker thread** | 0.011 ms | 1.4 ms, `terminated=True` | Yes | **No: the thread keeps running** |

In every case, the next governed action after the halt was denied. The gate costs 59 ns per check.

**The third row is the key result.** Cancelling the graph cannot stop a blocking call running in a worker thread, because Python cannot stop threads from outside. AGT still reports `terminated=True`. Three consequences:

- The acknowledgement must report each layer honestly: gate closed, interruption confirmed or not, process terminated (as the contract in P0-03 step 4 already requires).
- The `terminate` halt mode, which exits the process, is the only guarantee when an agent uses blocking tools. The adapter should detect blocking work still running and escalate to it after the grace period.
- A halt path outside the agent process (the harness module, Phase 2) remains the real backstop.

### 4. Evidence

**The format maps cleanly.** An AGT event converts to a CloudEvent such as:

```json
{
  "specversion": "1.0",
  "type": "ai.agentos.tool.blocked",
  "source": "/agent-os/agent/invoice-triage",
  "data": { "action": "send_email", "decision": "deny", "reason": "global-no-external-email", "policy_name": "whitetower-bundle-42" }
}
```

It maps to the White Tower catalog (`action.blocked`, `decision.made`) by adding the White Tower agent ID, `wtseq` and the trace context, and keeping the original type in an extension attribute.

**Delivery is lossy by design.** AGT's `GovernanceEventProcessor` uses a bounded queue (1,024 by default) with a **drop-oldest** policy. In a burst of 5,000 decisions towards a sink that needs 20 ms per batch, it delivered 1,224 events and **dropped 3,776 (75%)**, only counting them. White Tower requires that no governed action happens without evidence (NFR-08, ADR-0005). The enforcement point must therefore write each decision synchronously to a durable local buffer at decision time, and fail closed when that buffer is full, instead of relying on AGT's queue.

### 5. Framework integrations

- **`langgraph_trust`**, the LangGraph extra, does not use AGT's policy engine, Cedar or the kill switch. It is a separate set of graph nodes: trust-score gates and a checkpoint with its own simple policy of tool lists, patterns and limits. It writes a verdict into the graph state; blocking depends on how the developer wires the edges. It requires LangGraph below 1.0.
- **`LangChainKernel` and the other "Kernel" adapters** wrap tool methods, but the check they apply to each tool uses AGT's own allow and block lists (`GovernancePolicy`), not an external evaluator. Their v5 intervention points go through the ACS bridge (finding 1).

### 6. What AGT would contribute, against what White Tower builds anyway

| Need (contracts, ADR-0005) | With AGT | Without AGT |
| --- | --- | --- |
| Gate before every governed action | Build it (AGT has none) | Build it |
| Lease timer and fail-closed on expiry | Build it | Build it |
| Verified bundle, Cedar evaluation with our request profile | Own backend on `cedarpy`, behind AGT's evaluator | Own evaluation on `cedarpy` |
| Layered halt with honest acknowledgement | Build it; AGT's `KillSwitch` adds a timeout wrapper | Build it |
| Durable evidence buffer, no loss | Build it; AGT's queue drops events | Build it |
| Module API client | Build it | Build it |
| Framework interception at tool and model calls | AGT adapters check their own lists; v5 hooks need ACS | Build hooks per framework |

## Recommendation and the decision needed

**Option A, recommended: a White Tower enforcement point in Python** (`whitetower-ep`, under `modules/`), which depends on `cedarpy` and the generated module API client. It provides:

- the gate;
- the lease timer;
- bundle verification;
- Cedar evaluation, with the policy set parsed once per bundle;
- the layered halt with honest acknowledgements;
- the durable evidence buffer;
- hooks for LangGraph 1.x first, then other frameworks.

AGT becomes a Phase 2 interoperability adapter for organizations that already run it, in three ways:

- White Tower plugs into AGT's `PolicyEvaluator` as an external backend;
- a `GovernanceEventSink` forwards AGT's events to White Tower as supplementary evidence;
- White Tower halts are relayed to AGT's `KillSwitch` callbacks.

**Option B: AGT as the foundation, as the charter says.** Pin 5.0.0, build the White Tower gate, backend, halt and buffer on top anyway, stay on LangGraph below 1.0, and wait for ACS to mature. More dependencies, the same amount of work, and weaker guarantees.

**Documents updated when Option A was accepted:**

| Document | Change |
| --- | --- |
| P1-09 | Targets the fallback; renamed to "White Tower enforcement point (Python)" |
| Requirement MOD-06 and assumption ASM-01 | Reworded |
| Architecture section 6.1 | Describes the White Tower enforcement point, with AGT as an optional integration |
| Roadmap | Unchanged: the effort is similar |
| Charter | The Phase 1 description ("kill switch via AGT") changes by maintainer decision, recorded in an ADR |

## Inputs to the NFR targets

- **NFR-02 (decision latency).** In-process Cedar in Python measures p99 ≤ 1.1 ms with up to 100 policies parsed once. The proposed target (p99 ≤ 5 ms in-process) holds with margin. The Go side (cedar-go, embedded OPA) is still to be measured in S4.
- **NFR-03 and NFR-04 (halt).**
  - Inside the enforcement point, the gate closes in microseconds and asynchronous work stops in milliseconds, so the budget is dominated by delivery from the core (spike S2).
  - Blocking tools cannot be interrupted in-process. The proposal keeps NFR-04 (p95 ≤ 10 s) with the `terminate` halt mode as the default for agents that use blocking tools, and `interrupt` for fully asynchronous agents.

## Limitations of this spike

- **Environment:** a single Windows workstation, Python 3.13, no real LLM.
- **LangGraph 1.x** was not tested with AGT, because AGT does not support it. The White Tower hooks for LangGraph 1.x are part of P1-09.
- **Microsoft Agent Framework** was not exercised. Its AGT adapter exists (`maf_adapter`) and should be checked if an organization needs it.
- **ACS** could not be tested (no Windows wheel). It could be tried on Linux if the maintainers want Option B evaluated further.
- **Spikes S2, S3 and S4** (watch streams, audit throughput, Go-side policy latency) are separate and still pending.
