# P1-16: MCP servers, tools and models

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L, in six pull requests, about five weeks (see [progress notes](#progress-notes)) |
| **Depends on** | P1-04 for steps 1 to 4; RFC-0002 in the contracts ([P0-03](../phase-0/P0-03-module-contracts.md), step 12) and P1-06 for steps 5 and 6; the blocks record and the mock module of P1-07 (steps 5 and 8), the harness of P1-08 (step 10) and the reviewed design of the halt path for step 7 |
| **Unblocks** | The catalog steps of P1-09, P1-10.7, the catalog commands of P1-11, P1-13, P1-14 |
| **Requirements** | CAT-01 to CAT-10, NFR-24; backend of UI-10; the catalog part of API-04 |
| **Decisions** | [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md), ADR-0005, ADR-0011 |

## Goal

The core knows which MCP servers, tools and models each governed agent has, including the tools its model provider runs for it. People review them in a catalog, approve or block them for the whole organization, and enable them agent by agent. Enforcement points then let an agent use only what is enabled for it, in the ways its policies allow: the MCP servers, tools and models say what an agent can do, and usage rules in policies say how (decision of the maintainer, 2026-10-13).

## Scope

**In:** the core's side of RFC-0002:

- the catalog of MCP servers, tools and models, with review, classification and pinned definitions and digests;
- per-agent enablement, with requests and approvals, and immediate disables;
- the tooling that owners and operators declare for agents without an enforcement point;
- observations and definitions from the tooling reports of enforcement points (the logic behind `ReportTooling` and `ReportDefinitions`);
- organization-wide blocks, published in the watch stream;
- the content of each bundle's catalog file, and the argument declarations and types of its Cedar schema;
- usage rules: their form, their compiler to Cedar, and the generator that P1-06's check at submission calls;
- the core event types of RFC-0002, the public API and metrics.

**Out:**

- RFC-0002's contract text, protobuf, schemas and vectors ([P0-03](../phase-0/P0-03-module-contracts.md), step 12);
- the bundle builder, the seeded policies and the check of `@rule` statements at submission (P1-06, through interfaces it defines and this plan implements);
- the transport of the module API: P1-07 wires `ReportTooling` and `ReportDefinitions` to step 4, and carries the blocks of step 7 in the watch stream, as it wires ingestion to P1-02;
- the enforcement point's side: discovery, references, redaction, the catalog check, exposure, provider-run tools and arguments (P1-09);
- the console (P1-10.7) and the CLI (P1-11);
- the MCP network gateway (Phase 2), stateful usage rules (Phase 2), imports from endpoint security tools (Phase 3 discovery).

## Deliverables

- `internal/catalog`: entries, definitions, enablement, declared tooling, observations, blocks and the usage-rule compiler, with its queries in `internal/catalog/queries` and their generated code in `internal/catalog/catalogdb` (a new block in `sqlc.yaml`).
- `internal/api/rest/catalog.go`, with the OpenAPI operations of step 1, and `Catalog` in `rest.Options`.
- `metrics.NewCatalog`, and the wiring in `cmd/whitetower/main.go`. Its variable `catalog`, which holds the event catalog, becomes `eventCatalog`, so it no longer shadows the new package.
- A migration with the tables of [domain model section 3.9](../../architecture/domain-model.md#39-mcp-servers-tools-and-models), and the wider check on `inbox_items.kind`.
- The permissions of step 1 in `internal/authz`.
- The core event types of RFC-0002, section 9, each with its schema, example, catalog entry, rule in `internal/audit/facts.go` and line in `internal/audit/testdata/facts.json` (AGENTS.md, "Audit events").
- Security tests ST-75, ST-80 and ST-81.

## Steps

### 1. Decisions, permissions and API first

- **Open questions of RFC-0002.** The maintainer confirms or changes these proposed answers before step 2, and the RFC records the decisions:
  - the advisory committee approves catalog entries (not the steering committee);
  - adding a usage rule follows the normal approval of policies (an urgent restriction uses a disable or a block);
  - no agent may use every approved entry without enabling each one, not even with non-production credentials;
  - the limits stay: 256 servers, 4,096 tools and 256 models per report, references of at most 2 KiB, 500 active blocks;
  - numbers in usage rules are integers.
- **Permissions.** Nine new permissions in `internal/authz`, named like the existing ones, with the rows of the permission matrix (requirements, section 5.2.1):

  | ID | Grants |
  | --- | --- |
  | `catalog.view` | Steering, advisory, owner, operator, auditor and admin: all |
  | `catalog.entry.approve` | Advisory: approves or declines entries, definitions and digests |
  | `catalog.block.issue` | Steering, advisory, operator |
  | `catalog.unblock.request` | Steering, advisory, operator |
  | `catalog.unblock.approve` | Steering, advisory |
  | `tooling.enable.request` | Advisory: all; owner: own |
  | `tooling.enable.approve` | Advisory |
  | `tooling.disable` | Advisory: all; owner: own; operator: all |
  | `tooling.declare` | Owner: own; operator: all |

  - Each is mapped to its operations in `Authorizer.registerDefaults`; an operation missing there is refused.
  - The permission matrix test (ST-17) grows from 24 to 33 permissions, so it checks 7 × 33 = 231 pairs, and `resttest/testdata/me.json` is regenerated.
  - **Separation of duties.** Nobody approves their own request to enable or to unblock: `authz.CheckApproval`, with the requester as the author, and the same check again in the database, as `reject_self_approval` and `halt_release_two_people` do.
  - **Break-glass** gets none of them, not even `catalog.view`: it halts, and reads only what P1-03 lets it read (HUM-06, ST-20).
  - **`own`** passes the middleware, so each handler checks ownership, with P1-04's ownership check rather than another copy of `IsAgentOwner`.
- **API.** OpenAPI operations under the tag `catalog`, reviewed with P1-10.7:
  - the catalog: list and read servers, tools and models; approve an entry, a new definition or a new digest, with its classification and the arguments policies may see, or decline it; block; request and approve unblocking; the active blocks and their spread;
  - an agent's tooling, under `/agents/{id}` from P1-04: what is observed, enabled and declared; request enabling; approve; disable; declare tooling for an agent without an enforcement point;
  - compile a usage rule into its Cedar statements, for the console's forms and for policy-as-code repositories, so that nothing else needs a compiler (`catalog.view`).
- **API conventions,** as P1-02 and P1-03 built them:
  - entries, requests and blocks have UUIDv7 IDs in their paths; keys, which contain slashes, are query filters;
  - members and parameters are camelCase (`readOnly`, `openWorld`, `definitionSha256`), although bundles and events use snake_case;
  - lists are objects with a named array and `nextCursor`, with `limit` and `cursor` (`rest.PageSize`, `rest.EncodeCursor`, `rest.DecodeCursor`);
  - updates take `If-Match` with the row's version (`rest.ETag`);
  - refusals that come from state, such as a request already pending, an entry not approved or the cap of 500 blocks, answer with a new code, `conflict` (409), added to `problem.go` and to the [errors reference](../../reference/api-errors.md);
  - error details name nothing internal: never `err.Error()`.

**Done when:** the operations are merged and agreed with the console side, the permission tests cover every new row of the matrix, and for every `own` grant an owner is refused on an agent they do not own.

### 2. Catalog

- **Entries.** Servers, tools and models, with the references and keys of RFC-0002, section 3, matched as exact strings. The core assigns keys, unique in the catalog and immutable once an entry is approved, except the agent's own tools (`agent/<name>`), whose entries belong to their agent. This step fixes the grammar of keys (server slugs, the reserved `agent` and `provider.<provider>`, model names that keep their dots), and P0-03 step 12 uses it in the schema of the catalog file.
- **States.** `discovered` or `approved`; an entry shows as blocked while an active block covers it (step 7).
  - Approving a tool pins the hash of its definition, which must be stored (step 4). A tool of an MCP server can be approved only once its server is; approving a server can approve its tools at once, but the reviewer still sees each definition in full.
  - **Declining.** The reviewer can decline an entry, a new definition or a new digest, with a reason. It leaves the queue of what waits for review and stays not approved, so it stays denied; it can still be approved later, and reports of it bring it back to the queue only with a new definition or digest. Reviewers can decline at once every entry that waits for review from one agent.
  - Approving a self-hosted model pins the digest of its weights when the runtime reported one.
  - The reviewer classifies each tool (`read_only`, `destructive`, `open_world`), starting from the MCP annotations or, without them, from the protocol's conservative defaults, and declares the arguments policies may see, with their types from the tool's input schema.
- **Changed definitions and digests.** A reported definition or digest that differs from the approved one waits for review, while the approved one stays pinned: enforcement points deny the tool or the model, and hide the tool, until the new one is approved (RFC-0002, section 7.1).
- **Argument declarations stay stable.** A declaration that an active policy version reads cannot be withdrawn, and a declared argument's type cannot change while a usage rule uses it (RFC-0002, section 7.5).
- **Unpinned packages.** Local servers launched through `npx`, `uvx`, `pipx run` or `bunx` without an exact version are flagged for reviewers (T-77).
- **Redaction.** Everything stored from a report is redacted again (CORE-11).
- **Events:** `whitetower.catalog.discovered.v1`, `whitetower.catalog.approved.v1`, `whitetower.catalog.declined.v1`, `whitetower.catalog.definition_changed.v1`. They carry keys and the SHA-256 of references, never references in clear, descriptions or schemas (NFR-20). An event lists at most 100 entries, so it stays within the 64 KiB of an event; more take several events. `catalog.*` events have no subject, so owners' audit reads, which filter on the agent, never show them.

**Done when:** every transition and every refusal is tested, a definition or digest change keeps the approved one pinned, only the advisory committee approves or declines, a declined entry leaves the queue and stays denied, and no event carries a reference, a description or a schema.

### 3. Enablement and declared tooling

- **Enabling.** The owner or the advisory committee requests enabling tools and models for an agent, with a reason; someone other than the requester approves (HUM-04, step 1). A request can name an MCP server, to enable its approved tools at once. Only approved entries can be enabled, and never for a retired or rejected agent.
- **Disabling** takes effect at once: the owner, the advisory committee or an operator disables, with a reason. Enabling again needs a new request.
- **History.** A request is decided once and never changes afterwards, and each change writes its event: `whitetower.tooling.enabled.v1` (actor: the approver) and `whitetower.tooling.disabled.v1` (actor: who disabled, with the reason). `tooling.*` events have the agent as their subject.
- **Lifecycle.** Enabling tooling is part of "policy and harness assignment", between `validated` and `ready`; it is not a guard of the lifecycle (P1-04, step 5).
- **Reviews.** Each enabled entry keeps when it was last used (`agent_tooling.last_used_at`), filled by a job from allowed decisions, never by a write per decision. P1-04's periodic reviews read, through an interface this plan implements, the enabled tooling unused for `lifecycle.review_unused_tooling_days` (90 by default; a setting administrators edit, domain model section 5), as candidates to disable (CAT-09).
- **Declared tooling.** Owners and operators can declare the tooling of agents without an enforcement point, so that the inventory is complete; nothing enforces it (CAT-08). It is accepted only for agents below coverage C2, read through P1-04's coverage function (step 8), or, until that lands, for agents that no enforcement point instance serves.
- **Inbox.** The migration widens the check on `inbox_items.kind` with entries and definitions waiting for review, requests to enable tooling and requests to unblock (P1-04, step 10).

**Done when:** separation of duties holds on every path, through the API and in the database (ST-81), a disable is recorded at once, and a review lists the unused enabled tooling (tests with a fake clock).

### 4. Observations and definitions from tooling reports

The logic behind `RegistryService.ReportTooling` and `RegistryService.ReportDefinitions`, which P1-07 wires to them. Like P1-02's ingestion, it takes its caller as input, for example a `catalog.ReportCaller` with the instance's ID and the agents it serves, as `audit.IngestCaller` does, and does not build the module registry.

- **Validation and limits.** The report's schema, its counts and sizes (RFC-0002, section 4.2), kept as constants as `audit.MaxBatchEvents` is, and a rate limit per instance and agent (`internal/platform/ratelimit`, as ingestion's).
- **Reports never authorize** (CORE-10). New references become `discovered` entries, the agent's own tools entries of that agent, and changed definitions and digests wait for review; nothing is approved, enabled or unblocked.
- **A bound on waiting entries** (CORE-13, DC-10). For each agent and each kind, the entries its reports brought that still wait for review are bounded: one report's worth by default (256 servers, 4,096 tools, 256 models), a setting administrators can change (`catalog.pending_entries_per_agent`, domain model section 5). Beyond it, the report is still recorded, but its new entries are left out, stay unknown and are denied, and the response says how many. Approving or declining frees room, so a compromised agent cannot make the catalog, or the reviewers' queue, grow faster than people decide.
- **Definitions.** The response lists the definition hashes the core lacks. `ReportDefinitions` stores each definition under the hash the core recomputes (SHA-256 of RFC 8785 canonical JSON, as RFC-0002 section 3 defines it; the vectors of P0-03 step 12 then check it on both stacks), and refuses one that matches no hash the agent's reports name. Canonical JSON reuses `github.com/gowebpki/jcs`, which the audit log and the reference bundle verifier already use. Definitions are stored as their canonical bytes, as `audit_events.canonical` is, never re-encoded (JSONB would refuse some strings and reorder members), so every stored hash can be recomputed.
- **Observations.** For each agent, the entries observed and when each was first and last seen, so the console shows tooling waiting for a decision, and enabled tooling the agent no longer has. A report replaces its instance's previous one for that agent.
- **Events.** `whitetower.tooling.observed.v1` is written only when the observed set changes; it and the events of step 2 that a report causes carry the instance's ID in their data, and their actor is the system. A report's new entries go into `catalog.discovered.v1` events of at most 100 entries each.

**Done when:** a report makes nothing usable (ST-75); oversized and too frequent reports are refused, and new entries beyond the bound are left out; a definition whose recomputed hash matches no reported one is refused; and canary secrets placed in a report never reach the database or an event.

### 5. Bundles (with P1-06, once RFC-0002 is in the contracts)

P1-06 builds the bundles; this plan supplies, through the interfaces P1-06 defines:

- **the catalog file's content,** `catalog.json` in format `whitetower.catalog.v1`: the entries enabled for the agent and those observed for it, with their status, enablement, pinned definition and digest, classification, and the arguments policies may see. It holds no observation times, so that a report that changes nothing else rebuilds nothing;
- **the argument declarations and their types,** from which P1-06 generates each bundle's Cedar schema, with one `ToolArgs` record per tool (RFC-0002, section 7.6);
- **the rebuild triggers,** through P1-06's chunked rebuild (step 6 of P1-06): a change to an agent's enablement or observations rebuilds its bundle, coalesced per agent, and a change to a shared entry rebuilds the bundles of the agents that observe or enable it. Blocks never rebuild bundles.

**Done when:** the same inputs give the same catalog file, a report makes nothing enabled in any catalog file, a disable reaches the agent's next bundle, and the kit's reference bundle verifier (`test/conformance/bundle`) accepts a bundle with its catalog file.

### 6. Usage rules (with P1-06, once RFC-0002 is in the contracts)

- **The form** of RFC-0002, section 8: tools, conditions on arguments, operators, transforms, and `if_absent` (missing arguments match by default).
- **The compiler** turns a rule into one Cedar `forbid` statement per tool, annotated with the rule's canonical JSON (`@rule`). It takes argument types from the declarations, because a condition compiles differently for a string and for a set (`in` becomes `contains` on a string and `containsAny` on a set).
- **The generator interface** that P1-06's check at submission calls (step 3 of P1-06): a version whose `@rule` statements differ from what the compiler produces from their annotations is refused, so the form the console shows is what runs.
- **Validation.** Generated rules validate in strict mode against one Cedar schema covering the whole catalog, for global versions, and against the agent's schema for agent-specific ones.

**Done when:** generated rules validate with `cedar-go` in strict mode, a hand-edited rule statement is refused through P1-06's check, and the vectors of transforms and missing arguments, shared with P1-09 (ST-79), pass on the core's compiler.

### 7. Blocks (once RFC-0002 is in the contracts, and the design of the halt path is reviewed)

Blocks travel on the halt path, which must never become a bottleneck (NFR-03). One design note covers them with P1-07's governance state service and acknowledgements and with P1-08's halts; it is written in [P1-08's](P1-08-kill-switch.md) progress notes and reviewed before any code ([AGENTS.md](../../../AGENTS.md), work reserved for the reviewer).

- **Blocks** cover a server and its tools, a tool, a model, every model of a provider or every model of an endpoint, named by reference and published as the SHA-256 of the reference's string form (RFC-0002, section 6). A block takes effect at once, with a reason; lifting it needs an unblock request and the approval of someone else (step 1). At most 500 are active.
- **Publication.** Blocks travel in their own record of the watch stream, never in the fleet record, through P1-07's governance state service. They take their versions from the global state sequence, and are committed without waiting for any bundle (CORE-12). They never change an entry's status and never rebuild a bundle.
- **Propagation.** Enforcement points acknowledge the state version that carries a block as soon as they apply it (EP-15). The spread of each block comes from `instance_agents.observed_state_version`, through P1-08's tracking keyed by state version, and counts enforcement points only.
- **Break-glass** cannot block (step 1).
- **Events:** `whitetower.catalog.blocked.v1` (actor: the issuer, with the reason) and `whitetower.catalog.unblocked.v1` (actor: the approver), each with the block's ID and the state version.

**Done when:** ST-80 passes with the harness of P1-08: with 500 active blocks, a block reaches every mock enforcement point within NFR-24, and halts of one agent and of the fleet still meet NFR-03. Lifting needs a second person (ST-81).

### 8. Metrics

`whitetower_catalog_entries` by kind and status, `whitetower_catalog_reports_total` by outcome, `whitetower_catalog_blocks_active`, and the propagation of blocks, measured like that of halts. No label takes a value that a client chose: keys and references never become labels.

**Done when:** the metrics appear on the operations listener, and the propagation of blocks is in the report of ST-80.

## Acceptance criteria

- A report alone never makes anything usable; an approved and enabled tool is usable; a disabled one is denied from the next bundle on (ST-75).
- A changed tool definition is denied and hidden until its new definition is approved (with P1-09, ST-76).
- Nobody approves their own request to enable or to unblock (ST-81).
- Usage rules made with the form validate in strict mode, and a hand-edited rule statement is refused.
- A block reaches every connected enforcement point within NFR-24, and halts with 500 active blocks still meet NFR-03 (ST-80).
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-16-mcp-servers-tools-and-models) pass: ST-75, ST-80 and ST-81.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| RFC-0002 changes in its review | Steps 1 to 4 do not touch the contracts; steps 5 to 7 wait for P0-03 step 12 |
| The RFC's review (two weeks and an external reviewer) delays steps 5 to 7 | Announce it now, and review it together with RFC-0001, which is also waiting for its external review |
| Reports flood the catalog, or reviewers | Limits, rate limits and the bound on each agent's entries waiting for review (CORE-13, DC-10); discovered entries stay inert; approving a server can approve its tools at once, each definition still shown (T-74, T-75) |
| The Go core and the Python enforcement point compute different definition hashes (number formatting, Unicode, key order) | Definition-hash vectors run on both stacks (P0-03 step 12); the core recomputes every hash |
| Blocks slow halts | Their own record, hashes, a cap, no bundle rebuilds, and measurement with P1-08's harness (T-80, DC-9) |
| `cedar-go` and `cedarpy` disagree on generated rules | Vectors shared with P1-09 run against both in CI |
| P1-04's reviews need this plan's unused-tooling list, and this plan needs P1-04's agents | P1-04 defines the interface and stubs it until step 3 lands |

## Notes for implementers

- `internal/catalog` is a domain package: it imports neither `internal/api` nor `pkg/`.
- References and keys follow RFC-0002, section 3, exactly. The enforcement point computes references, and the core only compares them as strings.
- Store every time you compare later with the injected clock (AGENTS.md, pitfalls).
- Reported text is untrusted: it is logged only through `logging.Sanitize`, and the console and the CLI show it as plain text (T-76).
- Do not copy these deviations of earlier plans: lists returned as bare arrays, `err.Error()` in problem details, checks of role names in handlers, and a principal's ID as an event's subject.
- In REST tests, pass `authz.NewAuthorizer()` to `resttest`, as `audit_test.go` does, so the matrix's refusals are tested.

## Progress notes

The plan lands in six pull requests.

| Pull request | Steps | Status |
| --- | --- | --- |
| 1. Permissions, API and catalog | 1, 2 | Not started |
| 2. Enablement and declared tooling | 3; ST-81 for enabling | Not started |
| 3. Observations and definitions | 4; ST-75 | Not started |
| 4. Bundles | 5, with P1-06; needs P0-03 step 12 | Not started |
| 5. Usage rules | 6, with P1-06 | Not started |
| 6. Blocks and metrics | 7, 8; ST-80, ST-81 for unblocking; needs P1-07's blocks record and the reviewed design | Not started |
