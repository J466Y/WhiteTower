# P1-14: Pilot and Phase 1 gate

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | M of work, plus 3 to 4 weeks of pilot calendar |
| **Depends on** | P1-13; the pilot agreement (step 1) must start much earlier, before the Phase 0 gate |
| **Unblocks** | Phase 2 |
| **Requirements** | The charter's success criteria; the four MVP criteria of requirements section 1 |
| **Decisions** | All |

## Goal

Prove, with real agents, real people and a real SIEM, that White Tower does what the charter promises. Pass the Phase 1 gate, "Pilot with real agents", with evidence, and choose the priorities of Phase 2 from what the pilot teaches.

## Scope

**In:** the pilot agreement, plan and metrics, environment setup, onboarding through the full lifecycle, instrumentation of agents, operation, drills, evidence, the gate review and the retrospective.

**Out:** new features; pilot fixes ship as patch releases (v0.1.x) through the owning plans.

## Deliverables

- The pilot agreement and plan.
- A pilot environment running v0.1.x.
- Drill and measurement reports.
- The Phase 1 gate report, with evidence per criterion.
- A public write-up, with the partner's consent.

## Steps

### 1. Pilot agreement (start during Phase 0)

Agree with a partner organization (ASM-03) on:

- scope, schedule and a support channel;
- **two to five real agents**: at least one in-house Python agent instrumented with White Tower's enforcement point (aiming for coverage C3), and at least one third-party SaaS agent registered at C0;
- named owners and committee members;
- the IdP, the SIEM and the environment: Kubernetes, preferably with a CNI that enforces deny rules so network quarantine can be shown (ASM-05), or a Docker host;
- a data handling agreement and the success metrics.

**Done when:** signed before the Phase 0 gate. Without it, the Phase 1 gate is at risk (critical path).

### 2. Plan and metrics

Success criteria:

- 100% of pilot agents in the inventory with an owner, a use case and a policy;
- halt timings within the targets, for one agent and for the fleet;
- audit events and checkpoints received by the SIEM and verified;
- zero fail-open incidents.

Define how each is measured, which data is collected, and a weekly check-in.

**Done when:** the plan is approved by the pilot sponsor.

### 3. Environment

- Install from the release (Helm or Compose; air-gapped if the partner requires it).
- IdP integration with group mapping to roles.
- SIEM export through an OpenTelemetry collector.
- TLS certificates and backups.

**Done when:** the smoke test passes in the pilot environment, and the SIEM receives checkpoints.

### 4. Onboarding with real people

- Train each role in a short session.
- Take every pilot agent through the full lifecycle: proposal, use case validation by the advisory committee, global policies from the steering committee, agent-specific policies, activation.
- Register the third-party agents at C0.

**Done when:** every pilot agent is `active` or registered at C0, each with its owner, use case and policy.

### 5. Instrument agents

- Install `whitetower-ep` in the governed agents, with credentials created through the CLI or Kubernetes workload identity.
- On Kubernetes, label the agents' pods with their agent ID and install the network quarantine module (P1-15).
- Iterate policies in a non-production environment first.
- Verify coverage C2.

**Done when:** decisions from every governed agent reach the audit log.

### 6. Operate for two to four weeks

Watch the dashboards, reviews and drift; collect user experience feedback; fix blocking issues through v0.1.x patch releases.

**Done when:** the planned period is complete without unresolved blocking issues.

### 7. Drills

- A halt drill on each governed agent.
- A fleet halt drill in an agreed window.
- A partition drill (block traffic between the enforcement points and the core) to verify fail-closed behavior.
- On Kubernetes, check in each halt drill that the agent's pods were quarantined, and how long it took (NFR-23).

Measure each against the targets, and reach coverage C3.

**Done when:** the drill report shows the targets met, or explains the gaps.

### 8. Microsoft AGT, re-tested live

ADR-0011 replaced AGT with White Tower's own enforcement point for the MVP, and asked for AGT to be checked again with a real agent. If the partner runs AGT, or agrees to try it:

- run one pilot agent with AGT's latest release, next to or instead of White Tower's enforcement point, in a non-production environment;
- repeat the spike S1 probes live: White Tower as AGT's policy backend, halts relayed to AGT's kill switch, event delivery under load;
- record what changed since spike S1.

**Done when:** the result is in the gate report, as input to the Phase 2 priorities (the AGT interoperability adapter).

### 9. Evidence

- Auditors run `wtctl audit verify`, and a consistency check against a checkpoint stored in the SIEM.
- Export the evidence bundle for the pilot period (Could).

**Done when:** the evidence is attached to the gate report.

### 10. Gate review (G1)

Write a report with evidence for each charter success criterion and each Must requirement (demonstrated or not), the NFR measurements against their targets, incidents, feedback and known limitations. The maintainers and the pilot sponsor decide go or no-go for Phase 2, and set its priorities (for example, MCP gateway or LLM gateway first).

**Done when:** the gate decision is recorded, and the roadmap is updated for Phase 2.

### 11. Retrospective and publication

Hold a project retrospective. With the partner's consent, publish a write-up or case study, and update the README's status section.

**Done when:** published.

## Acceptance criteria

The gate report, approved by the maintainers and the pilot sponsor, shows the four MVP criteria of requirements section 1 met:

1. every pilot agent in the inventory with an active owner, a validated use case and an approved agent-specific policy;
2. governed agents authenticated by White Tower and governed at runtime by White Tower's enforcement point with White Tower policies;
3. evidence in the tamper-evident log, verified with the CLI and exported to the partner's SIEM;
4. halts of one agent and of the fleet confirmed and measured within the Phase 0 targets and, for agents on Kubernetes, their pods quarantined at the network level (in the pilot if its cluster supports it, otherwise on the reference cluster).

The gate report also records the exercise this plan owns in the [security test catalog](../../security/security-tests.md#p1-14-pilot-and-gate), ST-74.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| No pilot partner in time | Start step 1 during Phase 0; the maintainers' own organizations as a fallback |
| Real agents use frameworks the enforcement point does not support | Choose pilot agents with LangGraph 1.x where possible; add hooks in P1-09 if needed |
| The pilot's cluster cannot enforce deny rules, or the pilot runs on Docker | Show network quarantine on the reference cluster, and record the limit in the gate report |
| Committee members lack time | Short training, the personal inbox and reminders; realistic review intervals |

## Notes for implementers

- Measure from the first day; retrofitting measurements at the end of a pilot does not work.
- Keep a pilot log of every incident and every piece of feedback: it is the raw material of the gate report and of the Phase 2 priorities.
