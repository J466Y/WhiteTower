# White Tower design documents

The design of White Tower, from the charter to the implementation plans. All documents are drafts open for review; changes go through pull requests, and changes to the module contracts go through RFCs.

## Reading order

1. **[Project charter](../Project%20Declaration.pdf)**: why the project exists, its scope, principles and phases.
2. **[MVP requirements](requirements/mvp-requirements.md)**: what the MVP must do and how well, with requirement IDs, the permission matrix, the lifecycle, and the open questions.
3. **[Architecture decision records](adr/README.md)**: the founding decisions, including Go for the backend, TypeScript and React for the console, PostgreSQL as the only stateful dependency, and White Tower's own enforcement point for Python agents.
4. **[MVP architecture](architecture/mvp-architecture.md)**: components, interfaces, key flows (governed action, halt, policy change, audit evidence) and deployment.
5. **[Module contracts](contracts/README.md)**: what a module must implement to plug into White Tower, and what the core guarantees in return.
6. **[Implementation plans](plans/README.md)**: twenty plans from an empty repository to the MVP, with dependencies and the definition of done.
7. **[Roadmap](roadmap.md)**: sequencing, milestones, staffing, calendar and gate checklists.
8. **[Security design](security/README.md)**: the threat model, the security tests each plan must pass, and the mapping to the OWASP Top 10 for Agentic Applications and the EU AI Act.

## Where things will go

| Folder | Content | Created by |
| --- | --- | --- |
| `requirements/` | Requirements | This design package |
| `adr/` | Architecture decision records | This design package, then ongoing |
| `architecture/` | Architecture, domain model, lifecycle specification | This design package; P0-02 |
| `plans/` | Implementation plans and subplans | This design package, then ongoing |
| `contracts/` | Normative module contract specification | P0-03 |
| `security/` | Threat model and framework mapping | P0-04 |
| `spikes/` | Spike reports | P0-05 |
| `rfcs/` | Requests for comments on contract changes | P0-01 (template), P0-03 (RFC-0001) |
| `performance/` | Load and measurement reports | P1-07, P1-08, P1-09, P1-13, P1-15 |
| `reference/` | Generated configuration and CLI reference | P1-01, P1-11 |
