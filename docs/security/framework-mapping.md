# Framework mapping

| | |
| --- | --- |
| **Status** | Draft v0.1, with [threat model v0.1](threat-model.md) |
| **Date** | 2026-09-30 |
| **Plan** | [P0-04](../plans/phase-0/P0-04-threat-model.md), step 7; requirement NFR-22 |

How White Tower's MVP relates to two frameworks its users will be asked about: the OWASP Top 10 for Agentic Applications 2026, and the EU AI Act. Every claim names the requirement that delivers it, so it can be checked against the implementation. White Tower is a governance tool: it supports these frameworks' goals for the agents it governs, and does not by itself make an agent or an organization compliant.

## 1. OWASP Top 10 for Agentic Applications 2026

The list published by the [OWASP GenAI Security Project](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) in December 2025. For each risk: what the MVP provides, what later phases add, and what stays outside White Tower.

| ID | Risk | In the MVP | Later | Outside White Tower |
| --- | --- | --- | --- | --- |
| ASI01 | Agent Goal Hijack | Limits what a hijacked agent can do, rather than detecting the hijack: an agent runs only after its use case is validated and its policy approved (INV-03, POL-04); every tool and model call it makes is denied unless its policies allow it (POL-03, MOD-06); a halt stops it within seconds (KIL-01, NFR-03); every decision is evidence (AUD-02) | LLM and MCP gateways where guardrail modules can inspect prompts and tool results (Phase 2) | Detecting injected instructions |
| ASI02 | Tool Misuse and Exploitation | Every tool call is evaluated before it runs, and denied by default: the tool's kind and server, and the arguments a deployment exposes to policies (POL-06, [contracts section 6](../contracts/module-contract-v0.1.md#6-decision-profile)); global forbids override agent permits (POL-03); decisions recorded (AUD-02) | An MCP and tool gateway with a tool catalog; quotas (Phase 2) | The tools' own security |
| ASI03 | Identity and Privilege Abuse | One identity per agent (AID-01); asymmetric credentials White Tower never holds (AID-02); tokens that last 5 minutes, bound to an audience (AID-03); no token for halted, suspended or unapproved agents (AID-04); separation of duties for people (HUM-04); modules confined to their scope (MOD-02) | Per-task tokens carrying the user they act for (AID-08); SPIFFE SVIDs (AID-09) | The rights agents hold in other systems through their own accounts |
| ASI04 | Agentic Supply Chain Vulnerabilities | White Tower's own releases are signed, with SBOMs and provenance, and its dependencies pinned (NFR-13); policies reach agents only as signed bundles (POL-05); modules run only after an operator approves their manifest, pinned by its hash (MOD-02) | A signed skills repository with review (Phase 2) | The agents' own dependencies and models |
| ASI05 | Unexpected Code Execution (RCE) | Policies can deny code-execution tools (POL-03); a harness is declared per agent; on Kubernetes, a halted agent is isolated at the network level whatever its code does (KIL-10). The [threat model](threat-model.md) records that code execution inside the agent's process can bypass the in-process enforcement point (R-01) | An enforced harness (sandbox), and stopping workloads (Phase 2) | |
| ASI06 | Memory and Context Poisoning | Not covered directly: White Tower never sees an agent's memory, prompts or outputs ([contracts section 8.3](../contracts/module-contract-v0.1.md#83-personal-data)). Policies can govern `input.receive` and `model.result` where the framework exposes them, and a halt stops a poisoned agent | Content inspection in the gateways (Phase 2) | Memory stores |
| ASI07 | Insecure Inter-Agent Communication | Each agent has its own identity and audience-bound tokens (AID-01, AID-03), which another agent or service can verify with the published keys; calling another agent goes through `tool.invoke` and its policies | Per-task delegation carrying the user (AID-08); gateways (Phase 2) | The agent-to-agent protocols themselves |
| ASI08 | Cascading Failures | Fleet and selector halts (KIL-02); leases bound how long an agent cut off from the core keeps acting (KIL-04, NFR-05); per-agent policies bound what each agent can trigger; trace context in every event follows a cascade across agents; rate limits on ingestion | Quotas and budgets in the LLM gateway (Phase 2) | |
| ASI09 | Human-Agent Trust Exploitation | White Tower does not mediate what agents tell people; policies can govern `output.emit`. Its own high-stakes actions need two different people: no approval by the author, and releasing a halt by two people (HUM-04, KIL-05); every action is attributable (AUD-01) | | The agents' user interfaces |
| ASI10 | Rogue Agents | The inventory knows every declared agent and its owner (INV-01, INV-07); agents whose owner left or whose review is overdue are suspended (INV-05); a halt stops an agent within seconds and is confirmed (KIL-01, KIL-03, NFR-03); network quarantine isolates it outside its process (KIL-10); leases stop agents cut off from the core (KIL-04); the audit log keeps what it did (AUD-01 to AUD-04) | Discovery of agents nobody declared (Phase 3) | |

## 2. EU AI Act

Regulation (EU) 2024/1689 ([ELI](http://data.europa.eu/eli/reg/2024/1689/oj)), as amended by Regulation (EU) 2026/1744, the Digital Omnibus on AI ([ELI](http://data.europa.eu/eli/reg/2026/1744/oj)).

**How it applies.** Whether an agent is a high-risk AI system depends on its intended purpose (Article 6 and Annex III), so the obligations below apply to some governed agents and not to others. White Tower itself makes no decisions about people and is not a high-risk system. It gives the providers and deployers of agents capabilities that support their obligations; conformity depends on the whole system and its documentation.

| Article | What it requires | Who | What White Tower provides | Requirements |
| --- | --- | --- | --- | --- |
| 12(1) and (2) | High-risk systems allow the automatic recording of events (logs) over their lifetime, so that risk situations can be identified and the system's operation monitored | Providers, by design | The enforcement point records every decision and governed action automatically, and the core every governance change, in a tamper-evident log with trace context, exported to the organization's systems | AUD-01 to AUD-06, MOD-06 |
| 14(4)(e) | The people overseeing the system can intervene in its operation or interrupt it "through a 'stop' button or a similar procedure that allows the system to come to a halt in a safe state" | Providers, by design; deployers, in use | The kill switch: per agent, per selector or fleet-wide, from the console, the API or the CLI, without approval. On receipt, the gate closes and every further governed call is denied, which is White Tower's safe state; work in flight is interrupted where the framework allows, and the acknowledgement says what happened at each layer. Break-glass works when the IdP is down; on Kubernetes, the agent is also isolated at the network level | KIL-01 to KIL-10, UI-06, HUM-06 |
| 19(1) | Providers keep the logs their systems generate automatically, to the extent they control them, for at least six months, unless other Union or national law, in particular on personal data, provides otherwise | Providers | Retention of at least six months by default, configurable per event class; dropping older months keeps the rest verifiable | NFR-10, AUD-08 |
| 26(6) | Deployers keep the logs generated automatically, to the extent they control them, for at least six months, with the same proviso | Deployers | The same retention, and continuous export to the deployer's own SIEM | NFR-10, AUD-06, AUD-08 |
| 26(5) | Deployers monitor the system's operation; when its use may present a risk, they inform the provider or distributor and the market surveillance authority, and suspend its use; they report serious incidents | Deployers | Monitoring: the audit explorer, and the decisions, halts, instances and bundles of each agent. Suspending use: lifecycle suspension and halts. The evidence behind a report. Informing the authorities remains the organization's process | INV-04, INV-05, KIL-01, KIL-02, AUD-05, UI-02, UI-05 |
| 26(2) | Deployers assign human oversight to people with the necessary competence, training and authority | Deployers | Every agent has one accountable owner, an active person; committees and roles are explicit, and so is what each role may do | INV-02, HUM-02, HUM-03 |
| 26(1) | Deployers use the system in accordance with its instructions for use | Deployers | Approved policies, enforced at runtime, keep each agent within its validated use case | INV-03, POL-01 to POL-05 |

**Personal data.** The retention articles defer to data protection law. White Tower keeps personal data out of evidence where it can: people appear as pseudonymous IDs, argument values, prompts and outputs are never recorded, and human identifiers can be pseudonymized on export (NFR-20, [contracts section 8.3](../contracts/module-contract-v0.1.md#83-personal-data)).

**When the high-risk obligations apply.** Articles 12, 14, 19 and 26 are obligations for high-risk systems. The Digital Omnibus on AI deferred them:

| High-risk systems | Apply from | Before the Omnibus |
| --- | --- | --- |
| Listed in Annex III (stand-alone uses such as employment, credit or essential services) | 2 December 2027 | 2 August 2026 |
| Products, or safety components of products, under the Union legislation of Annex I | 2 August 2028 | 2 August 2027 |

Regulation (EU) 2026/1744 of 8 July 2026 was published in the Official Journal on 24 July 2026 (OJ L, 2026/1744), and entered into force three days later, on 27 July 2026 (its Article 4). Its Article 1, point (40), rewrites point (c) of Article 113, third paragraph, of the AI Act: Sections 1 to 3 of Chapter III, which hold Articles 12, 14, 19 and 26, apply from the dates in the table above. None of its amendments touches Articles 12, 14, 19 or 26.

High-risk systems placed on the market or put into service before those dates are covered only once their design changes significantly; those intended for public authorities must comply by 2 August 2030 (Article 111(2), as amended).

Checked on 2026-09-30 against the English text and the metadata of the Official Journal, retrieved from the Publications Office's Cellar repository. The dates are kept only in this document, so that a further change is corrected in one place.
