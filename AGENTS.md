# AGENTS.md

How coding agents implement White Tower's plans. Read it all before your first part, and the [work queue](#work-queue) before each new one.

White Tower is an open-source, self-hosted control plane that governs AI agents: an inventory of agents, their identities, policies distributed to enforcement points, a tamper-evident audit log and a kill switch. The [README](README.md) and the [requirements](docs/requirements/mvp-requirements.md) say what it is for.

## How the work flows

1. You implement **one part** at a time: the next one in the [work queue](#work-queue), or the one the maintainer names. A part is one pull request: a plan step, or a coherent piece of one.
2. You push it on its own branch, and write a [handoff report](#handoff-report).
3. A reviewer judges the part, as [How parts are judged](#how-parts-are-judged) describes. You fix what the review asks, on the same branch.
4. The maintainer opens the pull request and merges it. Only then does the next part start: never build on a part that is not merged.

## Rules you never break

- **Language.** Everything in the repository is in English: code, comments, commits, documents, handoff reports. Talk to the maintainer in Spanish.
- **Branches.** Branch from an up-to-date `main`: `feat/<plan>-<topic>` (for example `feat/p1-02-ingestion`), `fix/<topic>` or `docs/<topic>`.
- **Commits.**
  - Follow Conventional Commits, scoped by plan, for example `feat(P1-02): ingestion from modules` or `fix(P1-02): ...`. The body says what changed and why.
  - Sign off every commit with `git commit -s`, and keep the git identity the repository is configured with.
  - Never credit an AI tool: no `Co-Authored-By` line, no "Generated with" line, in commits or anywhere else.
- **What you never commit.** `docs/research/` is local material: stage with `git add -A -- . ':!docs/research'`. No scratch files, no debug output.
- **What you never do with the repository.** Push your branch, and nothing more:
  - never push to `main`, merge, or open or close pull requests unless asked;
  - never create tags or releases: there is none before the MVP;
  - force-push only when the maintainer agrees, and with `--force-with-lease`.
- **Contracts.**
  - `api/proto`, `api/manifest` and `api/policy` change only as the plan or an accepted RFC says.
  - `api/events` too, except the new event types of the core that a plan's state changes need ([Audit events](#audit-events)).
  - `api/openapi` changes come first, before the code that serves them.
  - If a change you need is not written down, stop and ask.
- **Generated code** is never edited by hand: run `task gen`. That covers `internal/api/rest/gen`, `pkg/apiclient`, `pkg/moduleapi`, `internal/<domain>/<domain>db` and `web/src/api/schema.gen.ts`.
- **Controls.** Never weaken one to get a change through:
  - no skipped or deleted tests, and no lowered thresholds;
  - no edits to CI workflows, to the exclusions of `.golangci.yml`, to rulesets or to `CODEOWNERS`;
  - a `//nolint` needs a comment that says why.

  When a check fails, fix the cause.
- **Scope.** Do the whole part, and nothing else. No drive-by refactors and no reformatting. Anything the part needs outside its scope goes in the handoff report, as a follow-up.
- **Secrets.** None in code, tests, logs or documents. The only development keys are those in `deploy/compose/dev/secrets`.
- **Dependencies.** A new one needs a written justification in the handoff report:
  - what it does, and why neither the standard library nor an existing dependency is enough;
  - how well it is maintained;
  - that its license is compatible with Apache-2.0.
- **Docker.** Database tests start their own containers and remove them.
  - Never stop, remove or change containers, volumes or databases you did not create. That includes other projects' (this machine may run other PostgreSQL servers) and the development stack's volume, `whitetower-dev_postgres-data`.
  - If Docker was not running, start it for the tests (`docker desktop start`) and stop it afterwards.
- **Stop and ask** in any of these cases. A question costs less than a rewrite.
  - The plan is ambiguous.
  - A contract or a requirement would change.
  - The part needs code outside its scope.
  - A test fails and you cannot explain why.
  - A design choice has trade-offs that no plan, ADR or RFC settles.

## Where the truth lives

| What | Where |
| --- | --- |
| What to build, step by step, and what is already done | The plan and its progress notes, `docs/plans/phase-1/P1-xx-*.md`; statuses in [`docs/plans/README.md`](docs/plans/README.md) |
| Requirements, by ID | [`docs/requirements/mvp-requirements.md`](docs/requirements/mvp-requirements.md) |
| Architecture, domain model, lifecycle | [`docs/architecture/`](docs/architecture/) |
| Decisions | [`docs/adr/`](docs/adr/README.md) |
| Module contracts | [`docs/contracts/module-contract-v0.1.md`](docs/contracts/module-contract-v0.1.md) and `api/`; their changes in [`docs/rfcs/`](docs/rfcs/README.md) |
| Threats, and the security tests each plan owns | [`docs/security/threat-model.md`](docs/security/threat-model.md), [`docs/security/security-tests.md`](docs/security/security-tests.md) |
| Packages, import rules, test helpers | [`docs/development/internals.md`](docs/development/internals.md) |
| Tools and everyday tasks | [`docs/development.md`](docs/development.md) |
| Contribution and governance | [`CONTRIBUTING.md`](CONTRIBUTING.md), [`GOVERNANCE.md`](GOVERNANCE.md) |

## Work queue

Take the first part that is not done.

| # | Part | Notes |
| --- | --- | --- |
| 1 | P0-03 step 11, corrections from the review of RFC-0001, code part 3: the schemas of `api/`, the Rego sketch, comments, and the kit's path checks | It depends on no feature plan. [P0-03's progress notes](docs/plans/phase-0/P0-03-module-contracts.md#progress-notes) of 2026-10-22 (corrections, part 3) list each change. |
| 2 | P0-03 step 11, corrections from the review of RFC-0001, code part 4: vectors on both stacks | After row 1. The same notes list the vectors and the changes to the Go profile and the Python checker, which must both pass every vector. A schema library in the Python checker is a new dependency to justify. |
| 3 | P1-04 fix: label keys follow the decision request schema | Can run alongside: it depends on no feature plan. `internal/inventory/validate.go` and the OpenAPI document's `Labels` pattern take the pattern of `api/policy/decision-request.schema.json` (contracts, CORE-17); no migration is needed before a release. On a `fix/<topic>` branch. |
| 4 | P0-03 step 11, corrections from the review of RFC-0001, code part 5: the manifest schema, its examples and manifest vectors | After row 2; it depends on no feature plan, and lands before P0-03 step 12, which edits the same schema. [P0-03's progress notes](docs/plans/phase-0/P0-03-module-contracts.md#progress-notes) of 2026-10-23 (corrections, part 4) list each change. |
| 5 | P0-03 step 11, corrections from the review of RFC-0001, code part 6: the bundle schema, bundle vectors and both verifiers | After row 4. The same notes list the cases; the Go and Python verifiers must both pass every vector. |
| 6 | P0-03 step 11, corrections from the review of RFC-0001, code part 7: event schemas, references and an HMAC vector | After row 5; it depends on no feature plan, and lands before P0-03 step 12, which edits `decision.made` too. [P0-03's progress notes](docs/plans/phase-0/P0-03-module-contracts.md#progress-notes) of 2026-10-23 (corrections, part 5) list each change. |
| 7 | P1-02 fix: ingestion of module events | Can run alongside rows 1 to 6, and lands before P1-07 serves `Publish`. [P1-02's progress notes](docs/plans/phase-1/P1-02-audit-log.md#progress-notes) of 2026-10-23 list it: sources by slug and stream ID, a finding for repeats, and de-duplication before scope and for 28 days at least. A new core event type follows [Audit events](#audit-events). On a `fix/<topic>` branch. |
| 8 | P0-03 step 11, corrections from the review of RFC-0001, code part 8: the quarantine events, the kit's skeleton, and examples | After row 6; it depends on no feature plan. [P0-03's progress notes](docs/plans/phase-0/P0-03-module-contracts.md#progress-notes) of 2026-10-23 (corrections, part 6) list each change. |
| 9 | P0-03 step 12, pull requests 2 and 3: RFC-0002 in the protobuf, the schemas and the vectors | After rows 1, 2, 4 to 6 and 8, the code parts of RFC-0001's review, which edit the same files. RFC-0002 is accepted provisionally (2026-10-26) and in the specification (pull request 1), and the part depends on no feature plan. [Step 12 of P0-03](docs/plans/phase-0/P0-03-module-contracts.md#12-rfc-0002-in-the-contracts-once-rfc-0002-is-accepted-before-the-tag) lists what changes; its [progress notes](docs/plans/phase-0/P0-03-module-contracts.md#progress-notes) of 2026-10-23 and 2026-10-26 add what RFC-0002's review decided and what writing the specification settled. The vectors take the cases of the URL and address check in `test/conformance/vectors/inputs/url-and-address-check.json`. The Go and Python stacks must both pass every vector. |
| 10 | P1-04 pull requests 4 to 8: lifecycle engine, reviews and guard job, coverage, instances, search and export, inbox and notifications, bulk import (steps 5 to 11) | The version counter is merged (P1-07.1, pull request 1), and the lifecycle and the requirements say that drills do not suspend (the note's section 13, decision 1). [P1-08's design note](docs/plans/phase-1/P1-08-kill-switch.md#progress-notes) (section 14) lists what they add: the lifecycle engine's entry point for the transitions White Tower makes, where T12 skips drills; the active selector halts folded into every write of the state record; the shared form of the selector halts' advisory lock, taken first by every writer that creates an agent or changes its labels or risk tier, with the key of `internal/govstate`; a guard job that suspends one agent per transaction; a bulk import that writes at most 100 agents per transaction; coverage C3 through an interface of P1-08; and `state_version` in `whitetower.agent.updated.v1` when a change concerns what enforcement points see. Its tables already exist in `00001_init.sql` (`agents`, `agent_owners`, `ownership_transfers`, `use_cases`, `use_case_decisions`, `lifecycle_transitions`, `reviews`, `inbox_items`): change them only with new migrations. Their timestamps default to `now()`, so give every time the guard job compares from `clock.Clock`. Stub the interfaces of P1-06 (an approved agent policy), P1-08 (the active selector halts that `publishState` adds, and coverage C3) and P1-16 (the unused tooling that reviews list). Tooling is not a lifecycle guard. ST-23, ST-24. |
| 11 | P1-16 pull requests 1 to 3: permissions, API, catalog, enablement, declared tooling, observations and definitions (steps 1 to 4; ST-75, ST-81) | Once P1-04's agents and their API are merged. The maintainer answered RFC-0002's open questions on 2026-10-21 (P1-16 step 1). No contract changes: the core event types of RFC-0002, section 9, follow [Audit events](#audit-events). Reports and definitions take the instance's identity and its agents as input; P1-07 wires `ReportTooling` and `ReportDefinitions` later. Reuse `authz.CheckApproval`, `internal/platform/ratelimit` and P1-04's ownership check. The catalog's tables, and the new kinds of `inbox_items`, go in a new migration. |
| 12 | P1-05: agent identity and credentials | After P1-04. Split it into parts first. Its tables already exist (`signing_keys`, `machine_credentials`, `workload_issuers`, `workload_identity_bindings`, `used_assertions`). The credentials of a module whose manifest declares the `enforcement-point` capability carry an environment, checked when they are created (step 7; [P1-08's design note](docs/plans/phase-1/P1-08-kill-switch.md#progress-notes), section 13, decision 7). |
| 13 | P1-06: policy model and distribution | Once P1-04's agents and their API are merged. Split it into parts first. Its RFC-0002 parts (the catalog file and the Cedar schema in each bundle, the seeded `wt-catalog`, the check of `@rule` statements) need P0-03 step 12: build the rest first, behind the interfaces that P1-16 implements. Its writes of the governance state follow [P1-08's design note](docs/plans/phase-1/P1-08-kill-switch.md#progress-notes), section 2: every row locked before the version, and rebuilds in chunks of at most 100 agents, one job at a time. |
| 14 | P1-02 fix: the locks of the audit partitions | Can run alongside: it depends on no feature plan, and lands before P1-08 step 2. As [P1-08's design note](docs/plans/phase-1/P1-08-kill-switch.md#progress-notes) says (section 2), `ensure_audit_partitions` creates each new partition as a table and attaches it, and `drop_audit_partition` drops with a short `lock_timeout`, retried at its next run. On a `fix/<topic>` branch. |
| 15 | P1-02 pull request 8: evidence bundles (step 11; AUD-10, ST-87) | Can run alongside: it builds only on what P1-02 and P1-03 built. [Step 11 of P1-02](docs/plans/phase-1/P1-02-audit-log.md#11-evidence-bundles-aud-10) designs it, and the plan's [progress notes](docs/plans/phase-1/P1-02-audit-log.md#progress-notes) of 2026-10-27 say why: AUD-10 became a Should. The OpenAPI operation comes first. It lands before row 17, whose audit commands use it. |
| 16 | P1-17: settings, in three pull requests (ST-84, ST-85) | Can run alongside: it needs only P1-01 to P1-03, and the notifications of its pull request 3 wait for P1-04's inbox (P1-04 pull request 7). The registry is a platform package, which imports nothing above it, so the audit writer and the inbox reach the store through interfaces that `cmd/whitetower/main.go` wires. Its three operations replace the placeholder `manageSettings` of `internal/authz`. The `settings` table already exists in `00001_init.sql`: give `updated_at` from `clock.Clock` and `updated_by` from the caller, never from the column defaults. The new core event type follows [Audit events](#audit-events). |
| 17 | P1-11, first part: skeleton, login and audit (steps 1, 2 and 7; ST-57 to ST-59) | Can run alongside rows 10 to 13: it needs only P1-03 and P1-02. Split P1-11 into parts first. `wtctl` has only `version` today. A keychain library is a new dependency. Build on `pkg/auditverify`, and on the evidence bundles of row 15 for `audit evidence` and `audit verify --evidence`; the API serves no consistency proof and no JSON Lines export yet, so ask before adding an operation. |
| 18 | P1-10.1: console foundations (ST-54, ST-56) | Can run alongside. Create `docs/plans/phase-1/P1-10-web-console/P1-10.1-foundations.md` with its pull request table. Check what P1-01 built in `web/`. Every string in English and Spanish. P1-10.0, the UX design, needs prospective users: it is the maintainer's. |
| 19 | P1-12.2 pull request 3: PostgreSQL reference setup (step 4) | Can run alongside: it depends on no feature plan. The setup replicates synchronously to any one of its two standbys, so a failover keeps committed halts, and one standby that stops answering never makes a commit wait ([P1-08's design note](docs/plans/phase-1/P1-08-kill-switch.md#progress-notes), section 10). |
| 20 | P1-03 pull request 7: the erasure of a person (step 13; HUM-09, ST-88) | Can run alongside: it builds only on what P1-03 built. [Step 13 of P1-03](docs/plans/phase-1/P1-03-human-identity-and-access.md#13-erasure-of-a-person-hum-09) designs it. The OpenAPI operation comes first; the new core event type follows [Audit events](#audit-events), and the status of an erased principal takes a new migration. |

After these rows, follow the dependencies in [`docs/plans/README.md`](docs/plans/README.md): P1-10.4 after P1-10.1; the rest of P1-07 after P1-05; P1-16 pull requests 4 and 5 after P0-03 step 12 and P1-06; then P1-08, P1-16 pull request 6, P1-09, P1-15 and the rest of the console and the CLI. P1-07 and P1-09 are XL: split each into its subplans first.

Reserved for the reviewer:

- **RFC-0002's contract text** (P0-03 step 12): pull request 1 put it in the specification, and appendix A's examples of its methods and of the blocks record follow the protobuf of pull request 2.
- **Designs on the halt path:** P1-08, the kill switch, organization-wide blocks (P1-16 step 7), and any change to the watch stream, leases, halts, blocks or the fleet record (P1-07 steps 5 and 6). The design note in [P1-08's progress notes](docs/plans/phase-1/P1-08-kill-switch.md#progress-notes) was accepted on 2026-10-20. It binds those parts and every plan that changes what enforcement points see, and where a plan says less or otherwise, the note decides; a change to it is the reviewer's, before any code that departs from it. The halt path must never become a bottleneck (NFR-03, NFR-24), even when the whole fleet halts at once with 500 blocks active.
- **New ADRs and RFCs:** drafted only when the maintainer asks.

### Plans in several parts

If the plan has no table of pull requests in its progress notes, your first part adds one, like P1-02's: a row per pull request, with its steps and its status.

An XL plan is split into subplans before it starts (the [plans index](docs/plans/README.md#how-the-plans-work)). Its first part creates the subplan files, in a folder named after the plan, each with its own table of pull requests, and the plan file becomes their overview.

- Keep each part reviewable: about 800 changed lines at most, generated code aside.
- Each part leaves `main` working.

## How to implement a part

1. Update `main` (`git switch main`, then `git pull --ff-only`) and create your branch.
2. Read the plan, its progress notes and what they reference. Then read, in full, the code you will extend and its tests.
3. Write a short plan of your own, five to ten lines: the files you will touch, what you will add, the tests that will prove it. It opens your handoff report.
4. Contracts first: OpenAPI, event types, migrations. Run `task gen`.
5. Write the code in small steps, each built and tested before the next ([conventions](#code-conventions)).
6. Write the tests ([testing](#testing)), and the documentation ([documentation](#documentation)).
7. Run the [checks](#checks-before-you-hand-over), review your own diff as the reviewer will, then commit, push and write the [handoff report](#handoff-report).

## How the reviewer works, and how you should

The reviewer will check that you worked this way. These habits make the difference between a part that passes and one that comes back.

- **Read before you write.**
  - Follow the data through the code you change: where it comes from, who sets it, who reads it.
  - Search for what exists (`grep -rn`) before you add a helper, a type, a query or an error.
- **Verify, never assume.**
  - Check that a function exists, and its exact signature, before you call it: `go doc <package>.<Name>`, or the source in `$(go env GOMODCACHE)`.
  - Check a column, a default or a constraint in the migrations before you rely on it.
  - Check the names of generated code after `task gen`.
  - Run a command rather than guess its output.
- **Prove that your tests can fail.** Break the code on purpose, watch the test fail, then restore the code with an edit. Never restore with `git checkout -- <file>` or `git restore`: they also throw away your own uncommitted work.
- **Think about the hard cases**, because the code will meet all of them:
  - a restart, or a failure in the middle of a transaction;
  - two replicas at once;
  - an empty, huge, malformed or hostile input;
  - a clock in the past or the future;
  - the database or a module that does not answer.
- **Leave no trace.** Before committing:
  - delete scratch files, temporary tests and debug output;
  - check that `git status` shows only what the part changes;
  - read `git diff` line by line, the way the reviewer will.
- **Be honest in the report.** Say what failed, what you did not run and what you are unsure of. A skipped test did not pass. A claim the reviewer cannot reproduce costs more than a gap you admit.
- **Do not loop.** If a fix fails twice, stop: explain what you tried, and ask.
- **Spend effort where it counts.**
  - Read the plan step and the sections it references, not every document.
  - While you iterate, run one package or one test (`go test ./internal/audit -run TestName`); run the whole suite once, at the end.
  - Do not read back a file you just wrote.

### Pitfalls already met in this repository

| Pitfall | What to do |
| --- | --- |
| Code compared the application's clock with a time that PostgreSQL set. The tests, on a fake clock fixed in the past, passed one morning and failed from the next day on | Keep every decision on one clock, the injected `clock.Clock`. Store the times you will compare later yourself, never with `now()` |
| A sed replacement also changed the helper it meant to call, which then called itself | After a bulk edit, read every changed line |
| `git checkout -- <file>`, run to undo a test change, also removed a fix not committed yet | Undo with edits. Commit before risky experiments |
| A file read with the wrong encoding on Windows was reported as corrupt | Read text as UTF-8, and look at the bytes before you claim corruption |
| Database tests skip without Docker, and a local run looked green | Run them with Docker, with `-v`, and check that no `--- SKIP` appears |
| CI job logs need repository admin rights, which agents do not have | Read check results through `https://api.github.com/repos/J466Y/WhiteTower/commits/<sha>/check-runs`, and ask the maintainer for the log of a failed job |

## Code conventions

[`docs/development/internals.md`](docs/development/internals.md) holds the rules, and the linter enforces part of them. These are the ones agents miss most.

- **Imports.**
  - Domain packages, `internal/<domain>`, never import `internal/api`, `internal/server`, `internal/cli`, `internal/webui` or `pkg/`.
  - `internal/platform` imports nothing above it.
  - `pkg/auditverify` imports nothing of White Tower.
- **Wiring.** `cmd/whitetower/main.go` makes every dependency and passes it on. No global state: no package-level variables that change, no default registry and no default logger.
- **State changes** run in `db.InTx`, through its `Tx`, and write their audit event in the same transaction (`audit.Writer.Record`). Effects outside the database run in an `AfterCommit` hook.
- **SQL.**
  - Queries are written by hand in `internal/<domain>/queries/*.sql`, and sqlc generates their code into `internal/<domain>/<domain>db`. A new domain package adds its block to `sqlc.yaml`.
  - Migrations are new numbered files in `internal/platform/db/migrations`, and only move forward: never edit a merged one.
  - Grants go table by table. Append-only tables get the triggers, and the grants, that the existing ones have.
- **Time** comes from `clock.Clock` (see the first [pitfall](#pitfalls-already-met-in-this-repository)).
- **Errors** are wrapped with `%w`, and say what failed. What reaches a client names nothing internal ([errors reference](docs/reference/api-errors.md)).
- **Logs** go to the `slog.Logger` passed in. Values that a client chose pass through `logging.Sanitize`. Never log secrets, prompts or tool arguments.
- **Metrics** start with `whitetower_`, register on the registry that `main` makes, and never take a label value that a client chose.
- **Settings** are fields in `internal/platform/config`, each with a comment. Secrets are read from files, named by settings ending in `_file`. After changing settings, regenerate the reference: `go test ./internal/platform/config -run TestReferenceIsCurrent -update`.
- **Comments** say why, in full sentences, and every exported identifier has a doc comment. Match the density and the tone of the code around them.
- **Reuse before you add.**
  - Do not add a second helper that does what an existing one does.
  - Leave no type, function, parameter, variable or constant that nothing uses.
  - Add no abstraction with a single user, unless a test needs it.
- **Names** follow the code around them: same words for the same things, same patterns for constructors, options and errors.

### Audit events

A new event type of the core needs all of the following, in the same part:

1. `api/events/schemas/whitetower.<area>.<event>.v1.json`: the schema of its `data`. It refuses unknown members, and names people only by pseudonymous IDs (NFR-20).
2. `api/events/examples/whitetower.<area>.<event>.v1.json`: one complete, valid event.
3. Its entry in `api/events/catalog.json`: summary, emitters `["core"]`, subject, schema and example.
4. Its rule in the `rules` map of `internal/audit/facts.go`.
5. The golden file of the indexed examples, regenerated with `go test ./internal/audit -run TestEveryExampleIsIndexed -update`. Read its diff.

## Testing

- **Names.** Tests read as sentences about behavior: `TestTheSealerSealsEveryEvent`, `TestARollbackFailsTheConsistencyCheck`.
- **Structure.** Helpers call `t.Helper()`, and cases sharing a shape go in a table.
- **Coverage.** Test failures and refusals, not only the happy path: authorization, input validation, every error a caller can see.
- **Helpers** (details in [internals](docs/development/internals.md#writing-tests)):
  - `dbtest` gives a migrated PostgreSQL per test;
  - `clocktest` is a fake clock: wait for the code under test with `WaitTimers`, then `Advance`;
  - `golden` compares with files under `testdata`, rewritten with `-update`;
  - `resttest` serves the public API.
- **Determinism.** Never use `time.Sleep` to wait for something: wait on a condition, or drive a fake clock. A test must pass whatever the date.
- **Security tests.** A test that implements an entry of the [security test catalog](docs/security/security-tests.md) starts with the comment `// Security test ST-nn: <what it checks>`. `test/security` checks those markers.
- **Untrusted input.** A parser of input from outside gets a fuzz test, with seeds; run it for a while before you hand over: `go test -run '^$' -fuzz FuzzName -fuzztime 30s ./path`.
- **Races.** CI runs every test with `-race`. Without cgo you cannot run it locally, so guard shared state with the race detector in mind.

## Documentation

Update the documentation in the same part.

- **The plan's progress notes.** Add a dated section, `### YYYY-MM-DD: <part>`: what was built, the decisions taken, and any difference from the plan, with its reason. Update the part's row in the plan's table, and the plan's status in [`docs/plans/README.md`](docs/plans/README.md), for example "In progress (4 of 7 pull requests)".
- **Requirements** change only when the maintainer decides. The threat model changes only when the reviewer asks; if you think a trust boundary changed, say so in the report.
- **References.**
  - `docs/development/internals.md`, for a new package or rule;
  - the configuration reference, for new settings;
  - the API's descriptions, in the OpenAPI document;
  - a runbook, for anything an operator must do.
- **Style.** Write like the existing documents:
  - plain English, short sentences, active voice;
  - tables for sets of facts, lists for steps;
  - no em dashes, and no marketing.

## Checks before you hand over

These are the checks CI runs. Every one must pass, unless you name it in the report with the reason.

```sh
go vet ./... && go vet -tags e2e ./test/...
go test ./...                                   # Docker running; then check no database test skipped
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run ./...
go tool -modfile=hack/tools/go.mod task verify:gen    # if contracts, SQL or OpenAPI changed
GOTOOLCHAIN=go1.26.0 go build ./... && GOTOOLCHAIN=go1.26.0 go test ./<changed packages>   # the oldest supported Go
```

- **Console.** If you changed it, run `pnpm --dir web run lint`, `typecheck`, `test` and `build`. Every string goes in both English and Spanish.
- **Environment.** The maintainer works on Windows. Use the Bash tool's POSIX syntax, and forward slashes in paths.

## Handoff report

Write it in English, in your last message, ready to become the pull request's description:

```markdown
## <plan> pull request <n>: <title>

Branch `<branch>`, commits `<sha>` (signed off).

### Plan
<your five-to-ten-line plan, updated to what you actually did>

### What and why
**Plan step and requirements:** <for example P1-02 step 5, AUD-02; ST-10, ST-11>

### Design
<decisions taken, alternatives considered, and why this one>

### Reused and added
- Reused: <existing functions, types, queries and helpers this part builds on>
- Added: <each new file, type and exported function, with its purpose in one line>

### Tests and checks
- <each test, and what it proves>
- Commands run, and their results: vet, tests (database tests ran: yes or no), lint, gen, Go 1.26, console.

### Differences from the plan
<none, or each one with its reason; the plan's progress notes say the same>

### Follow-ups and open questions
<what is left, what you are unsure of>

### New dependencies
<none, or each one with its justification>
```

## How parts are judged

The reviewer rates each criterion pass, minor or blocking.

| Criterion | What is checked |
| --- | --- |
| Purpose | The part does what its plan step asks, all of it, and its acceptance criteria hold |
| Scope | Nothing beyond the part, and nothing of it missing; follow-ups are written down |
| Design | It fits the architecture, the ADRs and the contracts. It sits in the right package and layer, stays simple, handles failure, is secure by default, and adds no bottleneck to a hot path |
| Integration | It reuses what exists: no duplicate or overlapping helpers, no second name for one thing. It is wired in `main`, configured and documented, and its generated code is current |
| Cleanliness | No dead code, unused identifiers, commented-out code, leftovers or debug output; comments are accurate; tests are readable |
| Tests | Behavior is covered, failures and refusals included. The tests are deterministic, the database tests ran, and the security tests carry their markers. The tests fail when the code is broken |
| Documentation and honesty | Plan notes, statuses and references are current, and the handoff report matches what the branch holds |

**Blocking, whatever the rest:**

- a red check;
- a skipped test reported as passing;
- a contract change that no plan or RFC covers;
- a weakened control;
- a secret anywhere;
- AI attribution;
- `docs/research/` or scratch files committed;
- changes unrelated to the part.
