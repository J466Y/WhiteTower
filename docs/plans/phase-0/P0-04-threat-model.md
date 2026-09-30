# P0-04: Threat model v0.1

| | |
| --- | --- |
| **Phase** | 0 Foundations |
| **Status** | In progress (review; see [progress notes](#progress-notes)) |
| **Size** | M |
| **Depends on** | P0-02 and P0-03 (drafts are enough to start) |
| **Unblocks** | P1-13; security requirements for every Phase 1 plan |
| **Requirements** | NFR-12, NFR-21, NFR-22 |
| **Decisions** | ADR-0005, ADR-0006, ADR-0009, ADR-0010 |

## Goal

A published threat model of the MVP architecture: what must be protected, who might attack it and how. Its results become requirements, design changes and security tests before Phase 1 code is written. The charter asks for a published threat model as part of the project's own security.

## Scope

**In:** assets, threat actors, data flows and trust boundaries, STRIDE analysis, attack trees for the top scenarios, mitigations, residual risks, mapping to the OWASP Top 10 for Agentic Applications and to the EU AI Act, a catalog of security tests for Phase 1.

**Out:** penetration testing and the release security review (P1-13); threats specific to Phase 2 modules (updated at each phase gate).

## Deliverables

- `docs/security/threat-model.md`: data flow diagram, trust boundaries, assets, actors, STRIDE tables, attack trees, mitigations with owners, residual risks.
- `docs/security/framework-mapping.md`: OWASP Top 10 for Agentic Applications 2026 and EU AI Act articles.
- A security test catalog, with each test assigned to a Phase 1 plan.
- Pull requests that add or change requirements and ADRs where the analysis demands it.

## Steps

### 1. Assets and security objectives

List the assets:

- the three signing keys (tokens, bundles, audit checkpoints);
- the audit log and its checkpoints;
- policies and bundles;
- governance state and the halt channel;
- agent and module credentials, human sessions, role mappings;
- configuration and backups.

State the objectives: integrity of governance decisions and evidence, availability of the halt path, confidentiality of credentials and keys.

**Done when:** each asset has an owner component and an objective.

### 2. Threat actors

- external attacker;
- agent under the influence of injected content (goal hijack);
- compromised module or enforcement point;
- malicious insiders: agent owner, operator, database administrator, cluster administrator;
- compromised IdP account;
- supply-chain attacker (dependencies, CI, images).

**Done when:** each actor has capabilities and motivations written down.

### 3. Data flows and trust boundaries

Draw the data flow diagram: browser and core, IdP and core, agent process (with its EP) and core, core and database, core and SIEM, operators and cluster, CI and published artifacts. Mark every trust boundary.

**Done when:** the diagram is reviewed against the architecture document.

### 4. STRIDE analysis

Apply STRIDE to each element and flow, rating likelihood and impact on a simple three-level scale.

**Done when:** every flow crossing a trust boundary has been analyzed.

### 5. Attack trees for the top scenarios

At least:

- suppress, delay or forge a halt, or forge its release;
- forge, tamper with or roll back a policy bundle;
- rewrite audit history without detection;
- activate an unapproved agent through self-approval or abuse of role mapping;
- steal or replay agent tokens; algorithm confusion; audience confusion;
- an enforcement point that lies (fake acknowledgements, fake decisions, events withheld);
- fail-closed abused as a fleet-wide denial of service;
- supply-chain compromise of Go or npm dependencies, CI or images;
- abuse of the break-glass credential.

**Done when:** each tree ends in mitigations or accepted risks.

### 6. Mitigations and residual risks

Map each threat to a control (an ADR, a requirement or a plan step) or to an explicitly accepted risk, with its rationale and an owner. Expected examples: signatures and version monotonicity for bundles; externally anchored checkpoints for audit; separation of duties in the domain layer; short token lifetime with audience binding; the halt also stopping token issuance, and the console flagging instances that keep sending events after a halt; high availability and tuned TTLs against denial of service; pinned and signed dependencies.

**Done when:** no high-rated threat is left without a mitigation or an accepted risk.

### 7. Framework mapping (NFR-22)

**OWASP Top 10 for Agentic Applications 2026.** For each entry, state what White Tower provides in the MVP, what comes in later phases, and what is out of scope:

| Entry | Name |
| --- | --- |
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution |
| ASI06 | Memory and Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

For example: ASI03 is covered by short-lived identities and issuance gated by lifecycle; ASI02 by per-agent policies at the EP; ASI10 by the kill switch and the audit log. ASI04 arrives with the signed skills repository in Phase 2, and ASI05 with the enforced harness in Phase 2.

**EU AI Act.** Map:

- Article 12 (automatic logging) to the audit log;
- Article 14(4)(e) (interrupting the system through a "stop" button or a similar procedure that brings it to a halt in a safe state) to the kill switch;
- Articles 19 and 26(6) (logs kept for at least six months) to NFR-10;
- Article 26 (deployers monitor the system and suspend its use when it presents a risk) to the lifecycle and halts.

Record the application dates as amended by the Digital Omnibus (Regulation (EU) 2026/1744): 2 December 2027 for Annex III high-risk systems and 2 August 2028 for Annex I. These dates come from secondary sources; verify them against the Official Journal before publishing.

**Done when:** both mappings are published, with every claim linked to a feature or requirement.

### 8. Security test catalog

Turn the abuse cases into tests and assign each one to a plan: for example, forged acknowledgement (P1-08), tampered audit rows (P1-02), algorithm confusion (P1-05), self-approval (P1-03 and P1-06), cross-site request forgery (P1-03), lease expiry under partition (P1-08 and P1-09).

**Done when:** each Phase 1 plan's acceptance criteria reference its tests.

### 9. Review and upkeep

Review with a security reviewer and the maintainers, then publish. Update the model at each phase gate, whenever a trust boundary changes, and in the security section that every contract RFC must have.

**Done when:** the review is recorded and the upkeep rules are in `GOVERNANCE.md`.

## Acceptance criteria

- Reviewed by a security reviewer who did not write it.
- Every high-rated threat has a mitigation linked to a plan step, or an accepted risk with its rationale.
- The OWASP and EU AI Act mappings are published.
- The security test catalog is referenced by the Phase 1 plans.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| No independent security reviewer available | Ask the community (OpenSSF, OWASP chapters); failing that, a reviewer from the pilot organization |
| The threat model goes stale | Update triggers in step 9; each gate checklist includes it |
| Regulatory dates change again | Keep them in one place (the mapping document) and cite the source |

## Notes for implementers

- Plain Markdown and Mermaid are enough; tools such as OWASP Threat Dragon are optional.
- Keep attack trees short and concrete; a threat that does not lead to a test or a decision is noise.

## Progress notes

### 2026-09-30: threat model v0.1 written

| Step | Status | Result |
| --- | --- | --- |
| 1 to 6 | Done | [Threat model](../../security/threat-model.md): 14 assets, 10 threat actors, 9 trust boundaries, 73 threats, 9 attack trees. Eight design changes: seven applied to the requirements, ADR-0010, the contracts, the architecture and the Phase 1 plans; DC-2 is scheduled in the contracts. 14 accepted risks, with their rationale |
| 7 | Done | [Framework mapping](../../security/framework-mapping.md). The dates of the Digital Omnibus on AI were checked against two law firms' summaries; the Official Journal still has to be checked on EUR-Lex |
| 8 | Done | [Security test catalog](../../security/security-tests.md): 74 tests, each owned by a Phase 1 plan whose acceptance criteria reference them |
| 9 | Waiting | Review by an independent security reviewer. The upkeep rules were already in `GOVERNANCE.md` |

**What remains:** the independent review (an acceptance criterion); DC-2 in the contracts, before the review of RFC-0001 opens (P0-03); a maintainer's check of the Omnibus dates on EUR-Lex before the Phase 0 gate.
