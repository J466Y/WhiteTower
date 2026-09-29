# P1-10: Web console

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | XL, split into seven subplans (P1-10.0 to P1-10.6) |
| **Depends on** | Only the requirements for P1-10.0 (which can start during Phase 0); P1-03 for P1-10.1, which starts against mocks generated from the OpenAPI document and integrates the real login when P1-03 lands; then each subplan follows its backend plan |
| **Unblocks** | P1-13, P1-14 |
| **Requirements** | UI-01 to UI-09, NFR-12 (CSP), NFR-14, NFR-17 |
| **Decisions** | ADR-0002, ADR-0009 |

## Goal

A console where each role finds its work: owners propose and review their agents, committees validate and approve, operators watch modules and halt agents, auditors verify evidence. It must be fast to use in an emergency, clear about what is happening, accessible, bilingual (English and Spanish), and must load nothing from outside the deployment.

## Scope

**In:** every screen of the MVP, split into the six subplans below.

**Out:** backend logic (every screen uses only the public API, API-01); Phase 2 screens (quotas, skills, gateways).

## UX principles

- **Safety-critical actions are obvious but guarded.** Before confirming, show the consequence ("This halts 37 agents running on 112 instances"). A fleet halt needs a reason and an explicit typed confirmation. A single agent halt stays one confirmation away, because speed matters.
- **Failures are never hidden.** Unconfirmed halts, drift, lost instances and failed checks stay visible until someone resolves them.
- **Disabled actions explain themselves.** For example: "You wrote this version, so you cannot approve it."
- **Status is never conveyed by color alone:** always an icon and text as well (WCAG 2.2 AA).
- **Comments are required wherever the API requires a reason.**

## Subplans

Each subplan gets its own file in `phase-1/P1-10-web-console/` when work starts. Until then, this section is its scope.

### P1-10.0: UX design (M, about 3 weeks; can start during Phase 0, depends only on the requirements)

- Information architecture and navigation for each role.
- Wireframes of the key flows: onboarding an agent (owner and advisory committee), approving a policy, halting one agent and the fleet, releasing a halt, verifying audit evidence.
- Visual language: design tokens, and a status vocabulary (lifecycle states, coverage levels, halt layers) that always pairs an icon with text.
- Validation with two or three prospective users from the pilot organization: a committee member, an operator and an auditor.

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
- **Agent detail,** with tabs: overview, owner and delegates, use case, lifecycle history, effective policies, credentials, instances, coverage, recent audit events.
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

**Done when:** a global and an agent-specific policy can be written, validated, approved and seen in effect for an agent, entirely in the console.

### P1-10.4: Audit explorer (M; depends on P1-02)

- Search with filters and a time range; a virtualized results table.
- Event detail: formatted JSON, related events through the trace ID.
- Verification status: last checkpoint, sealing lag, and the inclusion proof of the event shown as verified.
- A permission-gated export of JSON Lines for a time range.

**Done when:** an auditor can find, inspect and export the evidence of a pilot scenario.

### P1-10.5: Kill switch, modules and instances (M; depends on P1-07 and P1-08)

- **Halting:** from the agent detail and from a kill switch page, for one agent or the fleet (with selector, if implemented).
- **Live propagation:** per-instance status and layers, refreshed every second while a halt is active.
- **Release:** the request and approval flows.
- **A minimal break-glass page.**
- **The module catalog:** manifest view, approval, credentials.
- **Instances:** health, versions, lease, active bundle, drift.

**Done when:** an operator halts an agent and the fleet, follows the confirmations live, and a second person releases them, all in the console.

### P1-10.6: Dashboard, inbox and settings (M; depends on P1-04, P1-08)

- **Home dashboard:** agents by state, overdue reviews, coverage distribution, active halts, module health, sealing lag.
- **Personal inbox:** pending approvals and reviews due.
- **Administration settings:** review intervals, lease TTL per risk tier, view of role mappings, API tokens, notification settings.

**Done when:** each role's home page shows what needs their attention.

## Acceptance criteria (all subplans)

- Every Must requirement of the UI area is demonstrated by a Playwright test against the Compose stack.
- The axe checks report no serious or critical violation.
- The English and Spanish translations are complete.
- No request leaves the deployment (asserted in Playwright).
- The console works at 1280 pixels wide and is usable at 768.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| The console becomes the bottleneck of Phase 1 | Subplans start as soon as their backend API is agreed (API first in each backend plan), working against generated mocks |
| Cedar syntax highlighting for Monaco does not exist | A small tokenizer is enough; the Cedar project's grammars can be adapted |
| Live halt status via polling costs too much at scale | One-second polling only while a halt is active; Server-Sent Events are a later option |

## Notes for implementers

- Generate API mocks from the OpenAPI document (for example with MSW), so screens can be built before their backend exists.
- Keep all visible text in translation files from the first commit; retrofitting i18n is expensive.
- Prefer server state in TanStack Query over client state; the console holds almost no state of its own.
