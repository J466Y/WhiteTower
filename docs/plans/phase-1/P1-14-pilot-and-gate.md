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
- **two to five real agents**: at least one in-house Python agent instrumented with AGT (aiming for coverage C3), and at least one third-party SaaS agent registered at C0;
- named owners and committee members;
- the IdP, the SIEM and the environment (Kubernetes, or a Docker host);
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

- Install `whitetower-agt` in the governed agents, with credentials created through the CLI or Kubernetes workload identity.
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

Measure each against the targets, and reach coverage C3.

**Done when:** the drill report shows the targets met, or explains the gaps.

### 8. Evidence

- Auditors run `wtctl audit verify`, and a consistency check against a checkpoint stored in the SIEM.
- Export the evidence bundle for the pilot period (Could).

**Done when:** the evidence is attached to the gate report.

### 9. Gate review (G1)

Write a report with evidence for each charter success criterion and each Must requirement (demonstrated or not), the NFR measurements against their targets, incidents, feedback and known limitations. The maintainers and the pilot sponsor decide go or no-go for Phase 2, and set its priorities (for example, MCP gateway or LLM gateway first).

**Done when:** the gate decision is recorded, and the roadmap is updated for Phase 2.

### 10. Retrospective and publication

Hold a project retrospective. With the partner's consent, publish a write-up or case study, and update the README's status section.

**Done when:** published.

## Acceptance criteria

The gate report, approved by the maintainers and the pilot sponsor, shows the four MVP criteria of requirements section 1 met:

1. every pilot agent in the inventory with an active owner, a validated use case and an approved agent-specific policy;
2. governed agents authenticated by White Tower and governed at runtime through AGT with White Tower policies;
3. evidence in the tamper-evident log, verified with the CLI and exported to the partner's SIEM;
4. halts of one agent and of the fleet confirmed and measured within the Phase 0 targets.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| No pilot partner in time | Start step 1 during Phase 0; the maintainers' own organizations as a fallback |
| Real agents use frameworks the adapter does not support | Choose pilot agents together with the P0-05 S1 framework choice; add a helper in P1-09 if needed |
| Committee members lack time | Short training, the personal inbox and reminders; realistic review intervals |

## Notes for implementers

- Measure from the first day; retrofitting measurements at the end of a pilot does not work.
- Keep a pilot log of every incident and every piece of feedback: it is the raw material of the gate report and of the Phase 2 priorities.
