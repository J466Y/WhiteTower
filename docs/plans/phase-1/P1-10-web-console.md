# P1-10: Web console

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | XL, split into eight subplans (P1-10.0 to P1-10.7) |
| **Depends on** | Only the requirements for P1-10.0 (which can start during Phase 0); P1-03 for P1-10.1, which starts against mocks generated from the OpenAPI document and integrates the real login when P1-03 lands; then each subplan follows its backend plan (P1-16 for P1-10.7) |
| **Unblocks** | P1-13, P1-14 |
| **Requirements** | UI-01 to UI-10, NFR-12 (CSP), NFR-14, NFR-17 |
| **Decisions** | ADR-0002, ADR-0009, RFC-0002 |

## Goal

A console where each role finds its work: owners propose and review their agents, committees validate and approve, operators watch modules and halt agents, auditors verify evidence. It must be fast to use in an emergency, clear about what is happening, accessible, bilingual (English and Spanish), and must load nothing from outside the deployment.

## Scope

**In:** every screen of the MVP, split into the subplans below.

**Out:** backend logic (every screen uses only the public API, API-01); Phase 2 screens (quotas, gateways).

## UX principles

- **Safety-critical actions are obvious but guarded.** Before confirming, show the consequence ("This halts 37 agents running on 112 instances"). A fleet halt needs a reason and an explicit typed confirmation. A single agent halt stays one confirmation away, because speed matters. A block also shows first what it denies ("This blocks `github` and its 23 tools for 14 agents"), needs a reason, and stays one confirmation away, like a single agent halt.
- **Failures are never hidden.** Unconfirmed halts and blocks, drift, lost instances, failed checks and changed tool definitions stay visible until someone resolves them.
- **Disabled actions explain themselves.** For example: "You wrote this version, so you cannot approve it."
- **Status is never conveyed by color alone:** always an icon and text as well (WCAG 2.2 AA).
- **Comments are required wherever the API requires a reason.**

## Subplans

Each subplan gets its own file in `phase-1/P1-10-web-console/` when work starts. Until then, this section is its scope.

### P1-10.0: UX design (M, about 3 weeks; can start during Phase 0, depends only on the requirements)

- Information architecture and navigation for each role.
- Wireframes of the key flows: onboarding an agent (owner and advisory committee), approving a policy, halting one agent and the fleet, releasing a halt, verifying audit evidence, reviewing a discovered MCP server and its tools, enabling tooling for an agent, blocking a server, reviewing a changed tool definition.
- Visual language: design tokens, and a status vocabulary that always pairs an icon with text: lifecycle states, coverage levels, halt layers, the status of catalog entries (discovered or approved, shown as blocked while a block covers them), and an agent's tooling (observed, enabled or both).
- Directions from the maintainer, who gives them when the console's turn comes (decision of 2026-10-29), and validation with prospective users from the pilot organization when they are available: a committee member, an operator and an auditor.

**Done when:** the wireframes of the key flows are validated and linked from each console subplan.

### P1-10.1: Foundations (M; depends on P1-03)

- The app shell and layout; navigation built from the permissions returned by `/api/v1/me`.
- Routing with TanStack Router; the generated API client; TanStack Query conventions (query keys, error handling that renders RFC 9457 problems).
- The authentication flow: redirects to the backend-for-frontend, session expiry, the CSRF header.
- i18n with react-i18next (English and Spanish), with a check that fails CI on missing keys.
- Light and dark themes; design tokens; shadcn/ui set up.
- An accessibility baseline (axe in Playwright); error boundaries.
- A CSP-compatible build (no inline code) and Monaco loaded from local assets (its default loader uses a CDN).
- Playwright end-to-end tests against the Compose stack, including a check that no request leaves the deployment.

**Done when:** a user of each role logs in, sees the right navigation, and every page passes the automated accessibility check.

### P1-10.2: Inventory and lifecycle (L; depends on P1-04)

- **Agent list:** filters, saved views, CSV and JSON export.
- **Agent detail,** with tabs: overview, owner and delegates, use case, lifecycle history, effective policies, credentials, instances, coverage, "MCP and Tools" (P1-10.7), recent audit events.
- **The proposal wizard,** including registration of third-party agents at C0.
- **Use case validation screens** for the advisory committee.
- **Lifecycle actions** with confirmation and comments.
- **Reviews:** the owner's attestation form and advisory sign-off.

**Done when:** the full onboarding path, from proposal to active, can be done in the console by the right roles.

### P1-10.3: Policies (M; depends on P1-06)

- A policy list with filters (scope, language, status).
- Policy detail with its versions, and a diff view with the Monaco diff editor.
- An editor with syntax highlighting for Cedar and Rego; Cedar may need a small tokenizer.
- Validation results and policy tests.
- Submit, approve and reject, with separation of duties made clear in the interface.
- The effective policy per agent; bundle and drift status.
- Usage rules are edited and reviewed as forms in P1-10.7.

**Done when:** a global and an agent-specific policy can be written, validated, approved and seen in effect for an agent, entirely in the console.

### P1-10.4: Audit explorer (M; depends on P1-02)

- Search with filters and a time range; a virtualized results table.
- Event detail: formatted JSON, related events through the trace ID.
- Verification status: last checkpoint, sealing lag, and the inclusion proof of the event shown as verified.
- A permission-gated export of JSON Lines for a time range.

**Done when:** an auditor can find, inspect and export the evidence of a pilot scenario.

### P1-10.5: Kill switch, modules and instances (M; depends on P1-07 and P1-08)

- **Halting:** from the agent detail and from a kill switch page, for one agent, the agents that a selector of risk tiers and labels matches (if implemented), or the fleet. Before confirming, the dialog shows what the halt stops, from P1-08's preview for a selector or the fleet, and always says that the halt stops these agents in every environment. The console offers no environment control ([design note](P1-08-kill-switch.md#progress-notes), section 13, decision 2).
- **Live propagation:** per-instance status and layers, refreshed every second while a halt is active. A lost enforcement point shows as "failed closed (lost contact)", and a lost runtime-control module as "lost contact: layer not applied" ([design note](P1-08-kill-switch.md#progress-notes), section 7). It is built as a component that P1-10.7 reuses for blocks.
- **Release:** the request and approval flows.
- **A minimal break-glass page,** for halting only: a break-glass session cannot block (HUM-06).
- **Modules:** manifest view, approval, credentials.
- **Instances:** health, versions, lease, active bundle, drift, the manifest each instance registered with, so that an operator knows when a manifest can be retired (contracts, MAN-3), and the environment that the core recorded at registration, by which the console groups them ([design note](P1-08-kill-switch.md#progress-notes), section 13, decision 7).

**Done when:** an operator halts an agent and the fleet, follows the confirmations live, and a second person releases them, all in the console.

### P1-10.6: Dashboard, inbox and settings (M; depends on P1-04, P1-08, P1-16 and P1-17)

- **Home dashboard:** agents by state, overdue reviews, coverage distribution, active halts and blocks, tooling waiting for review, module health, sealing lag.
- **Personal inbox:** pending approvals, including requests to enable tooling or to unblock, the entries and definitions waiting for review, and reviews due.
- **Administration settings:** the runtime settings, through P1-17's API, each with its bounds (review intervals, lease TTL per risk tier, the quorum of policy approvals per scope of P1-06 step 4); view of role mappings, API tokens, notification settings.

**Done when:** each role's home page shows what needs their attention.

### P1-10.7: MCP servers, models and the "MCP and Tools" tabs (M, about 3 weeks; depends on P1-16, and builds on P1-10.2, P1-10.3 and P1-10.5)

The console of [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) (UI-10). It needs P1-16 in stages: step 1 (the API) to start on mocks, steps 2 to 4 for the catalog pages and the agent tab, step 6 for the rule forms, and step 7 for blocks. It runs before P1-10.6: UI-10 is a Must, while P1-10.6's UI-08 and UI-09 are Should.

- **MCP servers:** the catalog's servers, with their status (discovered or approved, shown as blocked while a block covers them), transport, tools, the agents that use them, and when they were first and last seen. Lists are paginated and virtualized: one report can hold 4,096 tools.
- **A server's page:**
  - its tools, each with its definition in full, the diff of a reported definition against the pinned one (the Monaco diff editor of P1-10.3), its classification (`read_only`, `destructive`, `open_world`) and its history;
  - the flag on a local server launched from a package without an exact version (T-77);
  - the actions to approve an entry or a new definition, with its classification and the arguments policies may see, or to decline it, with a reason; to block it, with a reason; and to request and approve unblocking. Approving a server can approve its tools at once, and each definition is still shown in full. A declined entry leaves the queue of what waits for review and stays denied; reviewers can also decline at once everything that waits from one agent.
- **Models:** the same for models, with their endpoints, the pinned digest and a new digest waiting for review. A model's "MCP and Tools" tab lists the provider-run tools seen with it, and the agents that use them.
- **"MCP and Tools" on each agent** (a tab of P1-10.2's agent detail):
  - its servers, tools and models, each marked observed, enabled or both;
  - switches that request enabling, or disable, with a reason. A switch shows off, requested (waiting for a second person) or on, and whether the agent's instances already run the bundle that carries the change. An agent is enabled to use tools and models: a server shows as enabled when one of its tools is, and its switch acts on its approved tools at once;
  - the usage rules that apply to each tool, the enabled tooling the agent no longer has, and the tools waiting for review;
  - for agents below coverage C2, a form that declares their tooling, marked as not enforced (CAT-08).
- **Blocks:** the active blocks, with their reasons. Issuing one first shows what it denies, and its spread across enforcement points uses the live propagation view of P1-10.5. Lifting one takes a request and the approval of someone else.
- **Usage rules as forms,** in P1-10.3's policy editor and diff view: tools, conditions on arguments, operators, transforms and `if_absent`. The catalog's API compiles each rule into its statements (P1-16, step 1), so the console never compiles a rule or writes `@rule` text itself.
- **Reviews and audit:** P1-10.2's review form lists the enabled tooling the agent has not used recently, as candidates to disable (CAT-09). In the audit explorer, decision events link each usage rule that decided to its policy.
- **Reported text** (names, titles, descriptions, schemas, and the display forms of URLs and command lines) is plain text, never rendered as Markdown or HTML, marked as reported by the agent, and collapsed beyond a length. Invisible and bidirectional characters are made visible (Monaco's Unicode highlighting stays on). Reported URLs are never fetched (NFR-14) and never turned into links. Keys assigned by the core are the main label (T-75, T-76).

**Done when:** in the console, the advisory committee approves a discovered server and its tools; an owner requests enabling one of them for their agent, and the advisory committee approves the request as a second person; a usage rule made with the form restricts the tool; an operator blocks the server, follows the block's spread, and requests lifting it, which someone else approves; and ST-78 passes. The block screens work against the API's mocks until P1-16 step 7 lands, and are tested end to end from then on.

## Acceptance criteria (all subplans)

- Every Must requirement of the UI area is demonstrated by a Playwright test against the Compose stack. For UI-10, the mock module (P1-07) reports tooling into the stack, including a changed definition and the hostile strings of ST-78.
- The axe checks report no serious or critical violation.
- The English and Spanish translations are complete.
- No request leaves the deployment (asserted in Playwright).
- The console works at 1280 pixels wide and is usable at 768.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-10-web-console) pass: ST-54 to ST-56, and ST-78.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| The console becomes the bottleneck of Phase 1 | Subplans start as soon as their backend API is agreed (API first in each backend plan), working against generated mocks |
| Cedar syntax highlighting for Monaco does not exist | A small tokenizer is enough; the Cedar project's grammars can be adapted |
| Live halt status via polling costs too much at scale | One-second polling only while a halt is active or a block is spreading; Server-Sent Events are a later option |
| Reported text attacks reviewers, or hides instructions from them (T-75, T-76) | Plain text only, invisible and bidirectional characters made visible, marked as reported (P1-10.7); the Content Security Policy (ST-54); ST-78 |
| The rule forms and the core's compiler disagree, and the check at submission refuses what the form produced | The console never compiles rules: the catalog's API does (P1-16, step 1) |
| Large catalogs make pages slow: 4,096 tools in one report, schemas of 64 KiB | Paginated API (API-03), virtualized tables as in P1-10.4, and definitions loaded only when opened |

## Notes for implementers

- Generate API mocks from the OpenAPI document (for example with MSW), so screens can be built before their backend exists.
- Keep all visible text in translation files from the first commit; retrofitting i18n is expensive.
- Prefer server state in TanStack Query over client state; the console holds almost no state of its own.
- P1-10.7's mocks include hostile reported text: markup, script, bidirectional and invisible characters, descriptions of 16 KiB and schemas of 64 KiB.
