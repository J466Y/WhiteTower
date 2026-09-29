# Module contracts v0.1 mapped onto real engines

| | |
| --- | --- |
| **Status** | Draft for review in [RFC-0001](../rfcs/0001-module-contracts-v0.1.md) |
| **Date** | 2026-09-29 |
| **Plan** | [P0-03](../plans/phase-0/P0-03-module-contracts.md), step 9 |
| **Contract** | [module-contract-v0.1.md](module-contract-v0.1.md) |

The contracts must not be shaped like one product, and certainly not like White Tower's own enforcement point, which implements them first ([ADR-0011](../adr/0011-own-python-enforcement-point.md)). This document maps them onto four kinds of engines. For each, it records what fits, the gaps, and how each gap is resolved.

**Result: no blocking gap.** The module API, the governance state and the event catalog fit every engine unchanged. One additive change is foreseen for Phase 2: new bundle languages for engines that neither run Cedar nor Rego.

## 1. Microsoft AGT

What was verified in [spike S1](../spikes/S1-agt.md), with `agent-governance-toolkit-core` 5.0.0. AGT becomes a Phase 2 interoperability adapter (ADR-0011).

| Contract element | AGT | Gap and resolution |
| --- | --- | --- |
| Role | An in-process library: an enforcement point with an embedded engine | None |
| Gate (section 5.4) | Has none | The adapter provides it, exactly as White Tower's own enforcement point does |
| Watch, leases, halts | No control-plane protocol | The adapter runs the watch client and the lease timer |
| Decision request (6.1 to 6.4) | `PolicyEvaluator` receives a context with the agent ID and the tool name; its `CedarBackend` hard-codes its entity types | The adapter registers a White Tower backend that builds the profile's request on `cedarpy`, about 25 lines in S1 |
| Actions (6.3) | The intervention points of its new policy runtime (ACS) map one to one to the profile's actions | ACS is an alpha with native wheels for Linux x86-64 only; until it stabilizes, the adapter hooks the frameworks' own integrations |
| Combining algorithm (6.5) | Its own YAML rules come first, first match wins; then it consults only the first external backend | Configure no AGT rules, and one White Tower backend holding the global and agent-specific policies as one Cedar policy set. Rule 4 (errors deny) is implemented in the backend |
| Bundles (7) | Loads policies from local files or pinned URLs | The adapter fetches through `GetBundle`, verifies (section 7.4), and gives the backend the policy set |
| Halt layers (5.5) | `KillSwitch.kill()` runs a registered callback with a 5-second timeout, and reports `terminated=True` even when a blocking thread keeps running | The adapter closes its gate first and reports each layer itself; AGT's kill is one way to interrupt, never the proof |
| Evidence (8) | CloudEvents 1.0 (`ai.agentmesh.*`, `ai.agentos.*`) through a bounded queue that drops the oldest events under load | The adapter maps them to catalog types, keeping the original in `wtorigtype`, and records decisions in its own durable buffer at decision time instead of relying on AGT's queue |

## 2. Open Policy Agent (OPA)

OPA 1.x, a graduated project of the Cloud Native Computing Foundation. It can be embedded through its Go SDK, or run as a sidecar or server.

| Contract element | OPA | Gap and resolution |
| --- | --- | --- |
| Role | A `policy-engine`, embedded in an enforcement point or as a decision point | None |
| Language (6.7) | Rego | The standard wrapper [`decision.rego`](../../api/policy/rego/decision.rego) implements the combining algorithm; checked with OPA 1.21 on the three rules |
| Decision request (6.1) | Any JSON input document | The AuthZEN request is the input as is |
| Decision API (6.8) | Its REST Data API (`POST /v1/data/whitetower/decision/response`); no native AuthZEN, which OPA declined to add (ADR-0004) | A thin adapter exposes the AuthZEN evaluation endpoint and calls OPA |
| Errors (6.5, rule 4) | Evaluation errors, such as conflicting rule values, return an error or an undefined result | The caller treats both as a denial (`error.evaluation`) |
| Bundles (7) | Its own bundle format and signatures (`.signatures.json`) | The enforcement point verifies the White Tower bundle, then loads its Rego files into OPA; OPA's own bundle signing is not used |
| Evidence (8) | Decision logs, and a status API for bundle activation | The adapter emits `decision.made` and `bundle.activated` from its own decision path, which has the reason codes |
| Halts, leases | None | The calling enforcement point's gate |

## 3. Cedar

The Cedar language in two implementations, both checked against every vector: `cedar-go` 1.8.0 (Go) and `cedarpy` 4.12.1 (Python, on the Rust implementation).

| Contract element | Cedar | Gap and resolution |
| --- | --- | --- |
| Role | A `policy-engine`, embedded | None |
| Combining algorithm (6.5) | "Forbid overrides permit" and default deny are rules 1 to 3, natively | **Rule 4 differs:** Cedar skips a policy that fails and decides with the others. The enforcement point turns any evaluation error into a denial; vector C-14 checks it |
| Profile features | Entity tags, `datetime` and `duration` are supported by both implementations | None. `cedar-go` has no policy templates, which the profile does not use |
| Validation (POL-07) | `cedarpy` validates against a schema; `cedar-go` has an experimental validator (`x/exp/schema/validate`) | Both gave identical results on the vectors, including the failures. The core pins its `cedar-go` version, and P1-06 re-checks validation results against `cedarpy` in CI |
| Bundles (7) | Policy files are Cedar text; the schema ships in the bundle | None |
| Policy IDs (6.6) | Statements are numbered (`policy0`, `policy1` and so on) | The enforcement point maps each statement back to its White Tower policy ID |

## 4. Engines with native AuthZEN: Cerbos and Topaz

Decision points that implement the AuthZEN Authorization API themselves. They are candidates for the Phase 2 demonstration that a module can be replaced without changing the core (MOD-08). What follows is a mapping on paper, to be verified with the combination vectors in Phase 2.

| Contract element | Cerbos, Topaz | Gap and resolution |
| --- | --- | --- |
| Role | `policy-engine` decision points (`embedded: false`), called by an enforcement point or a gateway | None |
| Decision request and response (6.1) | AuthZEN evaluation natively | Each maps AuthZEN's subject and resource types to its own model: `agent`, `tool` and `model` become its principal and resource kinds. Checked with the vectors |
| Languages (6.7) | Topaz evaluates Rego; Cerbos has its own YAML policies | Topaz can use the Rego wrapper. Cerbos needs a new bundle language: an additive change of `language` in a later contract version |
| Combining algorithm (6.5) | Each engine has its own rule precedence and scoping | The global and agent-specific levels must be expressed so that an agent-level policy can never override a global denial, and the vectors translated to the engine's language must pass. A mapping that cannot meet rule 1 is not conformant |
| Bundles (7) | Their own policy stores | The adapter verifies the White Tower bundle and writes its policies to the engine's store |
| Halts, leases, evidence | None: they are decision points | The calling enforcement point or gateway |

## 5. Summary

| Engine | Module API and governance state | Decision profile | Bundles | Events |
| --- | --- | --- | --- | --- |
| AGT | Unchanged, run by the adapter | Unchanged; a White Tower backend inside AGT | Unchanged | Unchanged; `wtorigtype` keeps AGT's types |
| OPA | Unchanged | Unchanged, through the Rego wrapper | Unchanged, `rego` language | Unchanged |
| Cedar | Unchanged | Unchanged; rule 4 added by the enforcement point | Unchanged | Unchanged |
| Cerbos, Topaz | Unchanged | Unchanged, through AuthZEN | Additive: new languages when needed | Unchanged |

**Not mapped:** Galileo Agent Control, named in the charter, was acquired by Cisco in 2026 (architecture, section 13). For the Phase 2 replacement demonstration, prefer engines hosted by a foundation or clearly independent, such as OPA.
