# Architecture decision records

An ADR records one significant decision: its context, what was decided, and what it costs. ADRs let a newcomer see why the system is the way it is, and they let the project change its mind explicitly instead of drifting.

## Process

1. Copy the template below into `NNNN-short-title.md` with the next free number.
2. Open a pull request with status **Proposed**. Discussion happens in the pull request.
3. A maintainer merges it as **Accepted**, or closes it as **Rejected** with the reason recorded.
4. An accepted ADR is not edited in substance. To change a decision, write a new ADR and mark the old one **Superseded by ADR-NNNN**.

Decisions that change the **module contracts** also need an RFC (see `CONTRIBUTING.md`, created in plan P0-01).

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-backend-language-go.md) | Go for the backend | Proposed |
| [0002](0002-frontend-typescript-react.md) | TypeScript and React single-page app for the frontend | Proposed |
| [0003](0003-postgresql-only-stateful-dependency.md) | PostgreSQL as the only stateful dependency of the MVP | Proposed |
| [0004](0004-api-and-contract-formats.md) | API and contract formats | Proposed |
| [0005](0005-edge-enforcement-with-leases.md) | Decisions at the edge, governance state pushed with fail-closed leases | Proposed |
| [0006](0006-tamper-evident-audit-log.md) | Tamper-evident audit log with a Merkle tree and signed checkpoints | Proposed |
| [0007](0007-monorepo-layout.md) | Monorepo layout | Proposed |
| [0008](0008-license-apache-2.md) | Apache-2.0 license and DCO for contributions | Proposed |
| [0009](0009-human-auth-bff-sessions.md) | Human authentication through a backend-for-frontend with server-side sessions | Proposed |
| [0010](0010-built-in-agent-token-issuer.md) | Built-in token issuer for agent and module credentials | Proposed |

All ten are expected to be accepted, amended or rejected at the Phase 0 gate at the latest.

## Template

```markdown
# ADR-NNNN: <decision in a few words>

- **Status:** Proposed | Accepted | Rejected | Superseded by ADR-NNNN
- **Date:** YYYY-MM-DD
- **Related:** <requirement IDs, plans, other ADRs>

## Context
What forces are at play: requirements, constraints, facts.

## Decision
What we will do, stated plainly.

## Consequences
What becomes easier and what becomes harder, including the risks we accept.

## Alternatives considered
Each serious alternative and why it was not chosen.
```
