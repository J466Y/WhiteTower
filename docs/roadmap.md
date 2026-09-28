# White Tower: implementation roadmap to the MVP

| | |
| --- | --- |
| **Status** | Draft v0.1, open for review |
| **Date** | 2026-09-28 |
| **Related** | [Requirements](requirements/mvp-requirements.md), [Architecture](architecture/mvp-architecture.md), [ADRs](adr/README.md), [Implementation plans](plans/README.md) |

This roadmap puts the implementation plans in order: who does what, when, and which milestones prove progress, from an empty repository to the MVP (the Phase 1 gate). The charter leaves phases undated until the team is known. Durations are therefore given in weeks under a stated staffing assumption, and the calendar dates are illustrative.

---

## 1. At a glance

- **Two phases to the MVP.** Phase 0, Foundations: 8 weeks. Phase 1, Core MVP: 26 weeks, including 6 weeks of pilot.
- **Effort.** About 85 person-weeks for the individual plans, plus joint hardening and pilot work, roughly 110 person-weeks in total.
- **Calendar with four people: 34 weeks** from start to the Phase 1 gate, before holidays and contingency. Starting on Monday 2026-10-05, the illustrative dates are:
  - Phase 0 gate at the end of November 2026;
  - release v0.1.0 in mid-April 2027;
  - Phase 1 gate at the end of May 2027.

  With the year-end break and a 15 to 20% contingency, plan for **June to July 2027**.
- **Critical path.** Core skeleton → human identity → inventory → agent identity → kill switch → AGT adapter → hardening → pilot. Beyond four people, adding staff barely shortens it (section 7).
- **Two things to start now,** because they can delay everything: the Microsoft AGT spike (go or no-go in week 3) and signing the pilot partner (before the Phase 0 gate).

## 2. Assumptions

**Baseline team**

| Person | Workstream | Main plans |
| --- | --- | --- |
| A: backend lead (Go) | Core domain | P0-02, P0-03 (lead), P1-03, P1-04, P1-05, P1-08 |
| B: backend engineer (Go) | Platform and contracts | P0-01, P0-05 S2 and S3, P1-01, P1-02, P1-07, P1-11, P1-12.2 |
| C: frontend engineer (TypeScript) | Console | P1-10.0 to P1-10.6 |
| D: platform and security engineer (Go and Python) | Agent side, deployment and security | P0-05 S1 and S5, P0-04, P1-12.1, P1-06, P1-09, P1-13 (lead) |

Part-time roles:

- A maintainer acting as product lead: runs the RFC process, secures the pilot partner, and works with committee members.
- An independent security reviewer, for P0-04 and P1-13.

**Other assumptions**

- One week is five working days of one person. Durations sit within the plan sizes of the [plans index](plans/README.md).
- The pilot partner signs before the Phase 0 gate. If not, the Phase 1 gate slips week for week.
- The AGT spike decides "go". A "no-go" adds two to four weeks to track D, for the fallback enforcement point.
- Week W1 starts on Monday 2026-10-05 in the illustrative calendar. Holidays are not modeled.

## 3. Milestones and gates

Every milestone ends with a recorded demonstration, a video or a script anyone can rerun, so progress is visible to the community.

| Milestone | Week (illustrative date) | What can be demonstrated | Plans done |
| --- | --- | --- | --- |
| **G0: Contracts v0.1 reviewed** (end of Phase 0) | W8 (2026-11-27) | The design package: accepted contracts, data model, threat model, measured NFR targets, AGT decision, pilot partner signed | P0-01 to P0-05 |
| **M1: Walking skeleton** | W12 (2026-12-25) | The core deployed with Compose and Helm; login through Keycloak with each role; audit events sealed and verified; the console shell | P1-01, P1-03, P1-12.1, the audit writer and sealer of P1-02 |
| **M2: Governed agent** | W20 (2027-02-19) | An agent goes from proposal to active through the API and the console, gets tokens, and its approved policies reach a mock enforcement point as signed bundles; decisions land in the audit log | P1-02, P1-04, P1-05, P1-06, P1-07 |
| **M3: Stoppable agent** | W25 (2027-03-26) | Real agents on two frameworks governed through AGT; one agent and then the fleet halted from the console and confirmed live within targets; conformance kit green | P1-08, P1-09, P1-10.1 to P1-10.5 |
| **M4: Release v0.1.0** | W28 (2027-04-16) | A hardened, load-tested, signed release that installs air-gapped | P1-10, P1-11, P1-12, P1-13 |
| **G1: Pilot with real agents** (end of Phase 1: the MVP) | W34 (2027-05-28) | The four MVP criteria met in the pilot, with evidence | P1-14 |

## 4. Timeline

```mermaid
gantt
    title White Tower to the MVP (illustrative, team of 4, start 2026-10-05, no holidays)
    dateFormat YYYY-MM-DD
    axisFormat %d %b
    excludes weekends
    todayMarker off

    section Platform and contracts (B)
    P0-01 Engineering foundations        :p001, 2026-10-05, 10d
    P0-05 S2 and S3 spikes               :s23, after p001, 10d
    P1-01 Core platform skeleton         :p101, 2026-11-16, 15d
    P1-02 Audit log                      :p102, after p101, 20d
    P1-07 Module registry and API        :p107, after p102, 25d
    P1-11 CLI                            :p111, after p107, 10d
    P1-12.2 HA and air-gap and upgrades  :p1122, after p111, 20d

    section Core domain (A)
    P0-02 Domain and data model          :p002, 2026-10-05, 10d
    P0-05 S4 Policy latency              :s4, after p002, 3d
    P0-03 Module contracts (lead)        :p003, after p002, 20d
    RFC-0001 review                      :rfc, after p003, 10d
    P1-03 Human identity and access      :p103, after p101, 15d
    P1-04 Inventory and lifecycle        :p104, after p103, 20d
    P1-05 Agent identity and credentials :p105, after p104, 20d
    P1-08 Kill switch                    :p108, after p105 p107, 20d

    section Agent side and security (D)
    P0-05 S1 AGT and S5 interruption     :s1, 2026-10-05, 15d
    P0-04 Threat model                   :p004, after s1, 15d
    P1-12.1 Images and Compose and Helm  :p1121, after p101, 15d
    P1-06 Policy model and distribution  :p106, 2027-01-11, 20d
    P1-09 AGT adapter                    :p109, after p106 p107, 25d
    P1-09 Halt integration and measures  :p109b, after p108 p109, 5d

    section Console (C)
    P1-10.0 UX design                    :p1100, 2026-10-12, 15d
    P1-10.1 Foundations                  :p1101, 2026-11-30, 15d
    P1-10.2 Inventory and lifecycle      :p1102, after p1101, 20d
    P1-10.3 Policies                     :p1103, after p1102, 15d
    P1-10.4 Audit explorer               :p1104, after p1103, 10d
    P1-10.5 Kill switch and modules      :p1105, after p1104, 15d
    P1-10.6 Dashboard and inbox          :p1106, after p1105, 10d

    section Release and pilot (all)
    P1-13 Hardening and release          :p113, after p108 p109b p1106 p1122, 15d
    P1-14 Pilot setup and onboarding     :p114a, after p113, 10d
    P1-14 Pilot operation and drills     :p114b, after p114a, 15d
    P1-14 Gate review                    :p114c, after p114b, 5d

    section Gates
    G0 Contracts v0.1 reviewed           :milestone, g0, after rfc, 0d
    M1 Walking skeleton                  :milestone, m1, after p103 p1121, 0d
    M2 Governed agent                    :milestone, m2, after p105 p106 p107, 0d
    M3 Stoppable agent                   :milestone, m3, after p109b, 0d
    M4 Release v0.1.0                    :milestone, m4, after p113, 0d
    G1 Pilot with real agents            :milestone, g1, after p114c, 0d
```

The same schedule as a table:

| Weeks | A: core domain | B: platform and contracts | C: console | D: agent side, deployment, security |
| --- | --- | --- | --- | --- |
| W1–W2 | P0-02 data model | P0-01 foundations | Console skeleton (P0-01), then P1-10.0 UX design (W2–W4) | P0-05 S1 AGT spike |
| W3–W6 | P0-03 contracts (lead); S4 in W3 | S2 and S3 spikes (W3–W4); P0-03 protobuf and events (W5–W6) | UX design validated with prospective users | S1 and S5 (to W3); P0-04 threat model (W4–W6) |
| W7–W8 | RFC-0001 review; P1-03 preparation | P1-01 skeleton (W7–W9) | Design system on generated mocks | Conformance kit design; pilot environment preparation |
| W9–W12 | P1-03 human identity (W10–W12) | P1-01 (W9); P1-02 audit log (W10–W13) | P1-10.1 foundations (W9–W11); P1-10.2 begins (W12) | P1-12.1 images, Compose, Helm (W10–W12) |
| W13–W16 | P1-04 inventory and lifecycle | P1-02 (W13); P1-07 module API (W14–W18) | P1-10.2 inventory screens (to W15); P1-10.3 policies (W16–W18) | Security test automation (W13–W14); P1-06 policies (W15–W18) |
| W17–W20 | P1-05 agent identity | P1-07 (to W18); P1-11 CLI (W19–W20) | P1-10.3 (to W18); P1-10.4 audit explorer (W19–W20) | P1-06 (to W18); P1-09 AGT adapter (W19–W23) |
| W21–W25 | P1-08 kill switch (W21–W24) | P1-12.2 HA, air-gap, upgrades (W21–W24) | P1-10.5 kill switch and modules (W21–W23); P1-10.6 (W24–W25) | P1-09 (to W23); halt integration and measurements (W25) |
| W26–W28 | P1-13 hardening and release v0.1.0 (everyone, led by D) | | | |
| W29–W34 | P1-14 pilot: setup, onboarding, operation, drills, gate review (everyone) | | | |

The slack in track D (weeks 7 to 9 and 13 to 14) is deliberate: it absorbs the year-end break, or the extra work of a "no-go" on AGT.

## 5. How the phases unfold

**Phase 0 (W1–W8): decide before building.** The spikes, the data model and the foundations start on day one, in parallel. The contracts follow the data model; the threat model follows the first spike. The RFC review of the contracts runs in weeks 7 and 8, and the core skeleton starts at the same time, because it does not depend on the contracts. The console's UX design is validated with prospective users while nothing can be built yet.

**Phase 1, first half (W9–W20): a governed agent.** The core gains its audit log, logins and roles, then the inventory, agent credentials, policies and the module API. Every step is shown in the console as soon as its API exists: the console works against mocks generated from the OpenAPI document and never waits for the backend. **M2** proves the whole chain with the mock enforcement point.

**Phase 1, second half (W21–W28): a stoppable agent, then a release.** The kill switch and the AGT adapter meet in week 25 (**M3**), with real agents stopped from the console. Deployment gains high availability, air-gap and upgrades. Three weeks of joint hardening produce v0.1.0 (**M4**).

**Pilot (W29–W34): prove it with real people.** Installation at the partner, onboarding of real agents through their real committees, operation, drills, evidence in the partner's SIEM, and the gate review (**G1**).

## 6. Critical path and where time can be won

**The critical path** runs through track A:

> P0-01 and P0-02 → P1-01 → P1-03 → P1-04 → P1-05 → P1-08 → P1-09 (halt integration) → P1-13 → P1-14

The contracts branch (P0-03 → RFC-0001 → P1-07) has about two weeks of slack, and the console about one.

**Where time can be won**

1. **A fifth person (Go)** can take P1-05 in parallel with P1-04. Credential management and the token endpoint do not need the complete lifecycle, only its states. This saves about two weeks.
2. **Prepare the pilot during P1-13:** environment, IdP integration and SIEM export ready before the release.
3. **Keep the console on generated mocks,** so it never waits for the backend.
4. **Start the AGT spike on the first day:** a late "no-go" is the most expensive surprise.

**What must not be cut:** the drills in the pilot, the tamper and fail-closed tests, and the external review of the contracts. They are what makes White Tower trustworthy.

## 7. Scaling the team

| Team | Calendar to G1 (no holidays or contingency) | Comment |
| --- | --- | --- |
| 2 people (full stack: Go and TypeScript) | about 52 weeks (12 months) | Almost everything becomes sequential and the console is the bottleneck. Consider a thinner console for the pilot, relying on the CLI for operators. |
| 3 people (A, B and D; console shared) | about 40 weeks (9 months) | The console is built by B and D after their backend plans; UX design still happens early. |
| **4 people (baseline)** | **34 weeks (8 months)** | As scheduled above. |
| 6 people | about 31 weeks (7 months) | The critical path dominates. Extra people add more quality (tests, documentation, a second framework in the adapter) than speed. |

## 8. Schedule risks

| Risk | Effect | Response |
| --- | --- | --- |
| "No-go" on AGT in P0-05 | Track D gains 2 to 4 weeks for the fallback enforcement point | Decide by week 3; the fallback is already described in P0-05 and P1-09; choose the pilot's frameworks accordingly |
| Pilot partner not signed by G0 | G1 slips week for week | Start outreach now; fall back to the maintainers' own organizations |
| RFC-0001 needs a second round | P1-07 and P1-09 move by up to 2 weeks, partly absorbed by slack | Share drafts from week 4; invite external reviewers at the start |
| Year-end break (W12–W13 in the illustrative calendar) | About 2 weeks | Plan it; use track D's slack |
| The console (XL) slips | M3 and M4 slip | API first, generated mocks, early UX design; the Should items (UI-08, UI-09) can move to v0.1.x |
| One person on the critical path (A) | Illness or departure delays everything | Pair B or D on P1-05 and P1-08 reviews; keep designs written down |
| Spikes miss NFR targets | Architecture rework (for example the hash chain fallback for the audit log, or a broker) | Spikes in weeks 1 to 4, with fallbacks already named in the ADRs |

## 9. Gate checklists

### G0: "Contracts v0.1 reviewed" (end of Phase 0)

- [ ] ADR-0001 to ADR-0010 accepted or amended.
- [ ] Requirements v0.2: NFR targets set from measurements (P0-05); open questions Q1 to Q6 closed.
- [ ] Data model v0.1 and lifecycle specification approved (P0-02).
- [ ] RFC-0001 accepted with at least one external review; tag `contracts/v0.1.0` (P0-03).
- [ ] Threat model v0.1 reviewed by the security reviewer (P0-04).
- [ ] Go or no-go on AGT recorded, with the adapter design or the fallback (P0-05 S1).
- [ ] CI, release pipeline and development environment working on the three operating systems (P0-01).
- [ ] Pilot partner signed (P1-14 step 1), which also closes Q7.
- [ ] Phase 1 team confirmed. Only then do the dates of this roadmap become commitments.

### G1: "Pilot with real agents" (end of Phase 1, the MVP)

- [ ] Every pilot agent in the inventory with an active owner, a validated use case and an approved agent-specific policy.
- [ ] Governed agents authenticated by White Tower and governed at runtime through AGT with White Tower policies.
- [ ] Evidence in the tamper-evident log, verified with the CLI and exported to the partner's SIEM, including a consistency check against a checkpoint held by the SIEM.
- [ ] Halts of one agent and of the fleet confirmed and measured within the Phase 0 targets; the partition drill failed closed.
- [ ] Release v0.1.x signed and verifiable; no open critical or high finding.
- [ ] Gate report approved by the maintainers and the pilot sponsor, with Phase 2 priorities.

## 10. After the MVP

The charter's later phases, not scheduled yet. Their plans are written during the pilot (W29–W34), so work can start right after G1.

| Phase | Content | Gate |
| --- | --- | --- |
| **2: Key modules** | LLM gateway and quotas; MCP gateway; skills repository with review and signing; enforced per-agent harness (including a halt path outside the agent process). Also: a second policy engine to prove module replacement, per-task delegated tokens, strict mode for critical agents, a TypeScript enforcement point. | One use case in production |
| **3: Ecosystem** | Shadow AI discovery; compliance module and GRC export; public third-party module SDK; public release; hosting in a foundation. | First third-party module |

The order of the Phase 2 modules is decided at G1 from what the pilot shows, for example whether the MCP gateway or the LLM gateway matters more to the first adopters.

## 11. Keeping the roadmap current

- The [plans index](plans/README.md) is the source of truth for plan status; this roadmap is reviewed at every milestone.
- After each gate, re-baseline the dates and record the variance and its causes.
- Dates become commitments only once the team is confirmed at G0, as the charter says.
