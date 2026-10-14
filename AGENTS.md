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
| 1 | P1-02 pull request 4: ingestion from modules (step 5; ST-10, ST-11) | Domain logic in `internal/audit`. Plan P1-07 wires `EventService.Publish` to it later, so take the instance's identity, its agents and the event types it declares as input; do not build the module registry. The new type `whitetower.audit.gap_detected.v1` follows [Audit events](#audit-events). Reuse `internal/platform/ratelimit`. Update the sequence rows of a batch in the order of their sources, or two batches deadlock (spike S3). ST-11 is a fuzz test. |
| 2 | P1-02 pull request 6: export (step 8) | Sinks with a cursor each (`audit_export_cursors`). An OTLP log exporter would be a new dependency: justify it. Checkpoints leave as ordinary events. |
| 3 | P1-02 pull request 7: retention and throughput (step 9, the rest of step 10) | The plan leaves the storage of pruned tree data open: propose it in the progress notes, and have it reviewed before coding. `pkg/auditverify` learns pruned ranges as an optional capability of its `Source`, found with a type assertion, and still imports nothing of White Tower. The benchmark reuses `hack/spikes/s3`. |
| 4 | P1-03: human identity and access | Split it into parts first ([Plans in several parts](#plans-in-several-parts)). |
| 5 | P1-02 pull request 5: query API (step 6; ST-12) | Needs P1-03's permissions. Inclusion proofs are computed from the stored tree hashes, which `audit.Log` reads, and checked with `pkg/auditverify` in the tests. |
| 6 | P1-12.1: images, Compose, Helm | Can run alongside rows 4 and 5. Check what P1-01 already built. |

After these rows, follow the dependencies in [`docs/plans/README.md`](docs/plans/README.md).

Reserved for the reviewer:

- **The follow-up of [RFC-0002](docs/rfcs/0002-mcp-servers-tools-and-models.md):** the requirements, the new plan P1-16 and the roadmap. Until it lands, do not start P1-04, P1-06, P1-07, P1-09, P1-10 or P1-11: RFC-0002 changes them.
- **Designs on the halt path:** P1-08, the kill switch, and any change to the watch stream, leases, halts or the fleet record. Write the design in the plan's progress notes, and have it reviewed before any code. The halt path must never become a bottleneck (NFR-03), even when the whole fleet halts at once.
- **New ADRs and RFCs:** drafted only when the maintainer asks.

### Plans in several parts

If the plan has no table of pull requests in its progress notes, your first part adds one, like P1-02's: a row per pull request, with its steps and its status.

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
