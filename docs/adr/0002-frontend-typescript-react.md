# ADR-0002: TypeScript and React single-page app for the frontend

- **Status:** Accepted, by the maintainer on 2026-09-30
- **Date:** 2026-09-28
- **Related:** CON-06, UI-01 to UI-09, NFR-12, NFR-14, NFR-17; ADR-0004, ADR-0009

## Context

The web console is an authenticated administration interface. It is data-heavy (inventory tables, audit search), has safety-critical interactions (halting agents and the fleet, following propagation live), needs a code editor for policies, and must be accessible (WCAG 2.2 AA) and translatable. It has no SEO needs. It must work air-gapped, with no CDN or external font, and it must respect a strict Content Security Policy. The frontend's dependency tree is part of the product's attack surface.

## Decision

The console is a **TypeScript (strict mode) single-page app built with React and Vite**. Its static build is **embedded in the Go binary** and served by the core, so no Node.js runs in production.

| Concern | Choice |
| --- | --- |
| Routing and server state | TanStack Router, TanStack Query |
| Tables | TanStack Table |
| Components and styling | shadcn/ui (component code copied into the repository) on Radix primitives, Tailwind CSS |
| Forms and validation | React Hook Form with Zod |
| Policy editor | Monaco Editor, bundled locally (its default loader fetches from a CDN and must be reconfigured) |
| API client | `openapi-typescript` and `openapi-fetch`, generated from the OpenAPI document |
| Localization | i18next with react-i18next; English and Spanish at MVP |
| Tests | Vitest and Testing Library; Playwright end-to-end with axe accessibility checks |
| Lint and format | Biome |
| Package manager | pnpm, with a lockfile, a minimum release age for new versions and dependency build scripts blocked unless allow-listed |

The console talks only to the public REST API (API-01) and never sees OIDC tokens (ADR-0009).

## Consequences

**Easier**
- The largest ecosystem for data-heavy consoles, accessible primitives and editor integration, and the largest pool of frontend contributors.
- A static SPA ships inside the core binary: one artifact to sign and deploy, air-gap friendly, and a strict CSP (`default-src 'self'`, no inline scripts).
- End-to-end typing from the OpenAPI document to the UI.

**Harder**
- npm supply-chain risk. Mitigations: pnpm settings above, a small dependency budget reviewed in pull requests, Renovate with grouped and delayed updates, and frontend dependencies included in the SBOM.
- Two toolchains (Go and Node.js) for contributors. The `Taskfile` hides it for common tasks.

## Alternatives considered

- **Next.js or Remix.** Server-side rendering brings nothing to an authenticated console and would put Node.js in production. Rejected.
- **Angular.** Solid for enterprise apps, but heavier and with a smaller open-source contributor pool today. Rejected.
- **Vue or Svelte.** Technically fine; a smaller ecosystem of enterprise tables and accessible primitives. Rejected by a small margin.
- **HTMX with Go templates.** The fewest dependencies. Rejected because the policy editor, live halt status and complex tables would push the project back to substantial JavaScript anyway, without the React ecosystem.
