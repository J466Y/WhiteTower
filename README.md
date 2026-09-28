# White Tower

**An open source, modular, self-hosted control plane for centralized AI agent governance.**

> **Status:** pre-alpha, Phase 0 (foundations). Nothing here is production-ready yet. Contracts, data model and threat model are being designed in the open. Feedback and contributors are welcome.

---

## Why this project exists

Organizations are deploying more and more AI agents, both in-house and third-party. Those agents need the same governance as human identities: registry, identity, permissions, security, activity analytics, compliance and lifecycle.

Commercial agent governance platforms solve much of this, but they come with high costs, per-user licensing and ties to a single ecosystem. They usually govern agents on their own platform well and agents outside their perimeter poorly.

The open source community already has solid standalone pieces: policy engines, runtime governance toolkits and MCP gateways. It lacks the **coordinating layer** that brings them together under one inventory, one governance model and one UI. This project builds that layer.

## What it does

White Tower does **not** try to reimplement every capability. It provides a small, stable **governance core** and integrates specialized tools as **interchangeable modules** through standard contracts. Any module can be open source, commercial or custom, and can be swapped without touching the core.

**Planned capabilities:**

- **Registry and inventory** of in-house and third-party agents, including discovery of unregistered agents (shadow AI).
- **Agent identity and permissions** with short-lived, per-task credentials.
- **Two-level policies:** organization-wide and agent-specific.
- **Deployment, monitoring and kill switch**, both per agent and fleet-wide.
- **Resource control:** token quotas, cost, GPU and local inference.
- **Skills repository:** centralized, versioned, reviewed and signed.
- **Per-agent execution harness** (sandbox).
- **Observability, immutable audit and compliance evidence.**
- **Unified UI, public API** and an SDK for building modules.

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
│  Policy engine · MCP gateway · LLM gateway · Skills repo     │
│  Harness/sandbox · Observability · Compliance · Discovery    │
└──────────────────────────────┬───────────────────────────────┘
┌──────────────────────────────▼───────────────────────────────┐
│  Existing systems: IdP · SIEM · EDR · agent frameworks ·     │
│  model servers                                               │
└──────────────────────────────────────────────────────────────┘
```

The core holds only the shared truth: which agents exist, who is accountable for each, which policies apply, what they have done and how to stop them. Everything else is a module.

Each **module** declares in a manifest which capability it covers, which events it emits and consumes, and which endpoints it exposes. An **adapter** translates a product's API into the common contract, so switching tools means switching adapters.

**Path of an agent action:** the agent requests an action → the relevant gateway asks the policy engine, passing the agent's identity and specific policy → the decision and the action are written to the audit log. **If the core does not respond, the action is denied.**

## Design principles

- **Modular and vendor-agnostic.** Every capability sits behind a defined contract.
- **Small core.** Only inventory, agent identity, policy model, audit and kill switch live in the core.
- **Deny by default.** If the policy plane is unreachable, nothing runs.
- **Self-hosted and air-gap capable.** No mandatory cloud and no outbound telemetry.
- **Every agent has an owner.** No agent runs in production without a human owner and a validated use case.
- **Standards over custom formats.** OpenTelemetry, OPA/Rego or Cedar, MCP, OIDC/SPIFFE.
- **Verifiable evidence.** Every policy decision and every agent action leaves an immutable, auditable trail.

## Candidate integrations

These are the first modules we plan to integrate. None of them is final.

| Capability | Candidate open source components |
| --- | --- |
| Policy engine and runtime governance | [Microsoft Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/), [Galileo Agent Control](https://galileo.ai/blog/announcing-agent-control), OPA |
| Identity | SPIFFE/SPIRE, Keycloak |
| Kill switch | Microsoft AGT (Agent Runtime) |
| Sandbox / harness | gVisor, Firecracker, containers with seccomp |
| LLM gateway, quotas, cost | LiteLLM |
| MCP and tool gateway | Obot, open MCP gateways |
| Skills repository | Built in this project (Git + signing) |
| Observability | OpenTelemetry |

## Roadmap

| Phase | Focus | Exit gate |
| --- | --- | --- |
| **0: Foundations** | Module contracts, data model, threat model | Contracts v0.1 reviewed |
| **1: Core MVP** | Inventory and identity, audit and basic UI, kill switch via AGT | Pilot with real agents |
| **2: Key modules** | LLM gateway and quotas, MCP gateway, skills repository, per-agent harness | One use case in production |
| **3: Ecosystem** | Shadow AI discovery, compliance, third-party module SDK, public release | First third-party module |

Phases are not dated yet. The implementation roadmap to the MVP, with its milestones and an illustrative calendar, is in [docs/roadmap.md](docs/roadmap.md).

## Design documents

The design package lives in [`docs/`](docs/README.md): the [MVP requirements](docs/requirements/mvp-requirements.md), the [architecture decision records](docs/adr/README.md), the [MVP architecture](docs/architecture/mvp-architecture.md) and the [implementation plans](docs/plans/README.md). All of them are drafts open for review.

## Out of scope

- Building a new agent framework. LangChain, CrewAI, OpenClaw and others are integrated instead.
- Serving models. vLLM, llama.cpp, Foundry Local or external APIs are integrated instead.
- Replacing your IdP, SIEM or EDR. The project integrates with them.

## Contributing

The project is in its design phase, which is the best time to shape it. The most useful contributions right now are:

- Reviewing and challenging the module contract and data model proposals.
- Proposing adapters for tools you already run.
- Threat modeling the core.

Changes to module contracts go through an **RFC process**. See `CONTRIBUTING.md` (coming soon).

## Security

Please do not open public issues for security vulnerabilities. See `SECURITY.md` (coming soon) for coordinated disclosure.

## License

To be decided before the first code release.
