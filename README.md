# White Tower

**An open source, modular, self-hosted control plane for centralized AI agent governance.**

> **Status:** pre-alpha. Nothing here is production-ready yet. Phase 0 (foundations) is closing: the module contracts v0.1 are accepted provisionally, and their last parts are being brought into the code before they are tagged. Phase 1, the core MVP, is under way: see [where the project stands](#where-the-project-stands). Feedback and contributors are welcome.

---

## Why this project exists

Organizations are deploying more and more AI agents, both in-house and third-party. Those agents need the same governance as human identities: registry, identity, permissions, security, activity analytics, compliance and lifecycle.

Commercial agent governance platforms solve much of this, but they come with high costs, per-user licensing and ties to a single ecosystem. They usually govern agents on their own platform well and agents outside their perimeter poorly.

The open source community already has solid standalone pieces: policy engines, runtime governance toolkits and MCP gateways. It lacks the **coordinating layer** that brings them together under one inventory, one governance model and one UI. This project builds that layer.

## What it does

White Tower does **not** try to reimplement every capability. It provides a small, stable **governance core** and integrates specialized tools as **interchangeable modules** through standard contracts. Any module can be open source, commercial or custom, and can be swapped without touching the core.

**Planned capabilities**, and the phase that brings each:

| Capability | Phase |
| --- | --- |
| **Registry and inventory** of in-house and third-party agents, each with an accountable owner and a validated use case | 1, the MVP |
| **Discovery of agents nobody registered** (shadow AI) | 3 |
| **People's identity and access:** sign-in through the organization's identity provider (OIDC, or SAML through a broker), roles from its groups, separation of duties, break-glass, and the erasure of a person on request | 1, the MVP |
| **Agent identity** with short-lived credentials | 1, the MVP |
| Per-task credentials, delegated on behalf of a user | 2 |
| **Two-level policies:** organization-wide and agent-specific | 1, the MVP |
| **Lifecycle, monitoring and a kill switch**, per agent and fleet-wide | 1, the MVP |
| **Control of agents' tooling:** a catalog of the MCP servers, tools and models each agent may use, approved or blocked for the whole organization and enabled agent by agent, with usage rules in policies | 1, the MVP |
| **Audit and evidence:** a tamper-evident log of every decision and governance change, exported to the organization's SIEM; evidence bundles that an auditor verifies offline; and a [mapping](docs/security/framework-mapping.md) of what the MVP provides to the EU AI Act, ISO/IEC 42001, the GDPR and the OWASP Top 10 for Agentic Applications | 1, the MVP |
| **Resource control:** token quotas, cost, GPU and local inference | 2 |
| **Per-agent execution harness** (sandbox) | 2 |
| A compliance module and GRC export | 3 |
| **Unified UI and public API** | 1, the MVP |
| A public SDK for building modules | 3 |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Unified UI  ·  Public API                   │
└──────────────────────────────┬───────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────┐
│                        Governance core                       │
│  Inventory · Identity & owner · Policies · Audit · Kill switch│
└──────────────────────────────┬───────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────┐
│       Module contracts: versioned API, events, manifest      │
└──────────────────────────────┬───────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────┐
│   Interchangeable modules (open source, commercial, custom)  │
│  Policy engine · MCP gateway · LLM gateway                   │
│  Harness/sandbox · Observability · Compliance · Discovery    │
└──────────────────────────────┬───────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────┐
│  Existing systems: IdP · SIEM · EDR · agent frameworks ·     │
│  model servers                                               │
└──────────────────────────────────────────────────────────────┘
```

The core holds only the shared truth: which agents exist, who is accountable for each, which policies apply, what they have done and how to stop them. Everything else is a module.

Each **module** declares in a manifest which capability it covers, which events it emits and consumes, and which endpoints it exposes. A product joins through an **adapter** that translates its API into the common contract. Adapters are code that someone has to keep up as products and frameworks change. So the contract stays small and versioned, a conformance kit checks every module against it, and the MVP builds its own enforcement point instead of depending on young products ([ADR-0011](docs/adr/0011-own-python-enforcement-point.md)). The contract's model of agents, actions and decisions was checked against several policy engines ([engine mappings](docs/contracts/engine-mappings.md)), and the MVP tests it with two agent frameworks, chosen to differ. A gap found there goes to an RFC, rather than being worked around in an adapter.

**How an action is decided.** White Tower's enforcement point runs inside the agent's process. Before each tool call, model call, input or output, it checks a gate (the agent's state is known, its lease is valid, it is not halted), evaluates the agent's policies itself, from a bundle that the core signed, and records the decision as evidence. No call waits for the core. The enforcement point keeps a stream open to the core, through which a halt arrives within seconds. **If it loses the core for longer than the agent's lease, it denies everything** ([ADR-0005](docs/adr/0005-edge-enforcement-with-leases.md)).

## Design principles

- **Modular and vendor-agnostic.** Every capability sits behind a defined contract.
- **Small core.** Only inventory, agent identity, policy model, audit and kill switch live in the core.
- **Deny by default.** Every governed call is denied unless a policy permits it, and an enforcement point that has lost the core denies everything once the agent's lease runs out.
- **Self-hosted and air-gap capable.** No mandatory cloud and no outbound telemetry.
- **Every agent has an owner.** No agent runs in production without a human owner and a validated use case.
- **Standards over custom formats.** OpenTelemetry, CloudEvents, OpenID AuthZEN, Cedar (Rego in Phase 2), MCP, OAuth 2.0 and OIDC, SPIFFE later.
- **Verifiable evidence.** Every policy decision and governed action leaves evidence in a tamper-evident log. The log is sealed into a Merkle tree under checkpoints signed with a key kept outside the database, exported to the organization's SIEM, and verifiable by a third party without trusting White Tower ([ADR-0006](docs/adr/0006-tamper-evident-audit-log.md)).

## Limits of the MVP

The MVP is deliberately narrow. These are its main limits, and what lifts each:

- **The enforcement point trusts the agent's process.** It runs inside the agent because that is where every call can be seen: calls to local MCP servers and to the agent's own functions, and the tools a model's provider runs for it, none of which a network gateway sees. An agent or an owner who takes control of that process can bypass it (the [threat model](docs/security/threat-model.md)'s accepted risk R-01). Outside the process, the MVP isolates halted agents on Kubernetes at the network level. The MCP and LLM gateways and an enforced sandbox add controls outside the process in Phase 2.
- **A halt stops what comes next.** From the moment an enforcement point receives a halt, every further governed call is denied. Work already in flight is interrupted where the framework allows it, and the acknowledgement says whether it was. The agent's process ends only in the halt mode that its owner chooses for that.
- **Only registered agents are governed.** The inventory holds the agents someone registered, third-party agents without runtime integration included, whose tooling can be declared by hand. Agents nobody registered stay invisible until shadow AI discovery, in Phase 3.
- **Python agents first.** The enforcement point is a Python package, with hooks for LangGraph 1.x and for a second framework that the pilot needs. The hooks of each framework follow its releases, tested every week against the latest ones.
- **One organization per deployment.** Multi-tenancy is not planned.
- **Evidence, not compliance.** The MVP gives the evidence that frameworks ask for, and maps it to their controls. It does not make an agent or an organization compliant, and the compliance module comes in Phase 3.

## Candidate integrations

These are the first components we plan to integrate or build. None of them is final.

| Capability | Components |
| --- | --- |
| Policy engine | Cedar, evaluated inside White Tower's enforcement point (`cedarpy`), with policies validated by the core (`cedar-go`). OPA, and engines with native AuthZEN, in Phase 2 ([engine mappings](docs/contracts/engine-mappings.md)) |
| Runtime governance and kill switch | Built in this project: White Tower's enforcement point for Python agents, and network quarantine on Kubernetes ([ADR-0011](docs/adr/0011-own-python-enforcement-point.md)). [Microsoft Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) as an interoperability adapter in Phase 2 |
| Identity | Built in this project: an OAuth 2.0 token issuer for agents ([ADR-0010](docs/adr/0010-built-in-agent-token-issuer.md)). Any OIDC identity provider for people, and SAML through a broker such as Keycloak, which development uses. SPIFFE/SPIRE later |
| MCP servers, tools and models | Built in this project: a catalog in the core, applied by the enforcement point ([RFC-0002](docs/rfcs/0002-mcp-servers-tools-and-models.md)) |
| Audit | Built in this project: a tamper-evident log on PostgreSQL ([ADR-0006](docs/adr/0006-tamper-evident-audit-log.md)), exported over OpenTelemetry and JSON Lines |
| Sandbox / harness (Phase 2) | gVisor, Firecracker, containers with seccomp |
| LLM gateway, quotas, cost (Phase 2) | LiteLLM |
| MCP and tool gateway (Phase 2) | Obot, open MCP gateways |
| Observability | OpenTelemetry |

## Where the project stands

| | |
| --- | --- |
| **Works today** | The core's platform: TLS listeners, configuration, structured logs, metrics and traces, PostgreSQL with forward-only migrations and a runtime role that cannot change the schema, and background jobs |
| | The tamper-evident audit log: every change of the core recorded in the transaction that makes it, sealed into a Merkle tree under signed checkpoints, searchable through the API, exported over OpenTelemetry and JSON Lines, kept by a retention that leaves the rest verifiable, and checked by a verification library that third parties can use ([`pkg/auditverify`](pkg/auditverify/)) |
| | People's identity and access: sign-in through OIDC, whose tokens never reach the browser, sessions, roles from the identity provider's groups, a permission matrix with separation of duties, API tokens, SCIM deprovisioning, break-glass, and SAML through a broker |
| | The first part of the inventory: agents, use cases and their owners, through the API |
| | Container images, an evaluation stack with sample data, and a Helm chart |
| | The module contracts in machine-readable form, and their conformance kit: test vectors that two independent stacks, in Go and in Python, check alike |
| **Next** | The agents' lifecycle, identities and policies; the module API; the kill switch; the enforcement point for Python agents; the catalog of MCP servers, tools and models; network quarantine; the console and the CLI. Then hardening, release v0.1.0 and the pilot |

The [plans index](docs/plans/README.md) tracks the status of every plan, and the work queue of [AGENTS.md](AGENTS.md) what comes next.

## Roadmap

| Phase | Focus | Exit gate |
| --- | --- | --- |
| **0: Foundations** | Module contracts, data model, threat model | Contracts v0.1 reviewed |
| **1: Core MVP** | Inventory and identity, audit and evidence, basic UI, control of the MCP servers, tools and models of agents, kill switch through White Tower's enforcement point and network quarantine | Pilot with real agents |
| **2: Key modules** | LLM gateway and quotas, MCP gateway, per-agent harness | One use case in production |
| **3: Ecosystem** | Shadow AI discovery, compliance module, third-party module SDK, public release | First third-party module |

The pilot runs on Windows, macOS and Linux, and includes an external security review. Once a pilot passes, external security audits follow, each from its own angle.

Phases are not dated yet. The implementation roadmap to the MVP, with its milestones and an illustrative calendar, is in [docs/roadmap.md](docs/roadmap.md).

## Design documents

The design package lives in [`docs/`](docs/README.md):

- the [MVP requirements](docs/requirements/mvp-requirements.md), the [architecture decision records](docs/adr/README.md) and the [MVP architecture](docs/architecture/mvp-architecture.md);
- the [module contracts](docs/contracts/README.md), with their machine-readable parts in [`api/`](api/README.md) and their [conformance kit](test/conformance/README.md);
- the [security design](docs/security/README.md): the threat model, the security tests and the framework mapping;
- the [implementation plans](docs/plans/README.md) and the [roadmap](docs/roadmap.md).

All of them are open for review.

## Out of scope

- Building a new agent framework. LangChain, CrewAI, OpenClaw and others are integrated instead.
- Serving models. vLLM, llama.cpp, Foundry Local or external APIs are integrated instead.
- Replacing your IdP, SIEM or EDR. The project integrates with them.

## Contributing

The project is young, which is the best time to shape it. The most useful contributions right now are:

- Reviewing and challenging the module contract and data model proposals.
- Proposing adapters for tools you already run.
- Threat modeling the core.

Changes to module contracts go through an **RFC process**. See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md). Code lands in small parts that follow the implementation plans, each reviewed as [AGENTS.md](AGENTS.md) describes. To build and run the code, follow the [development guide](docs/development.md).

## Security

The [threat model](docs/security/threat-model.md) and the [security tests](docs/security/security-tests.md) that each plan must pass are public. An external security review runs in the pilot.

Please do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for coordinated disclosure.

## License

[Apache License 2.0](LICENSE). Contributions are accepted under the Developer Certificate of Origin ([ADR-0008](docs/adr/0008-license-apache-2.md)).
