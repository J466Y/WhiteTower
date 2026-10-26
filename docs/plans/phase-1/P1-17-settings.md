# P1-17: Settings

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | M |
| **Depends on** | P1-01, P1-02 (the audit writer), P1-03 (roles and `settings.manage`); P1-04's inbox (its pull request 7) for the notifications of step 4 |
| **Unblocks** | P1-08 step 6, P1-10.6; the registration of the keys of P1-06 (step 4) and P1-16 (pull request 2) |
| **Requirements** | API-01 and API-03 for settings; the row "Manage role mappings and settings" of the permission matrix (requirements, section 5.2.1) |
| **Decisions** | ADR-0003, ADR-0004; the maintainer's decisions of 2026-10-21 (a plan of its own) and 2026-10-22 (bounds, notifications, dismissals, `audit.retention_months`) |

## Goal

The platform administrator reads and changes White Tower's runtime settings through the public API, and through the console of P1-10.6. The domain that owns each setting validates every change, every change is audited, and a change that can weaken a control notifies the steering committee.

On 2026-10-21 the maintainer decided that the settings get a plan of their own. P1-04, P1-06 (the quorum of policy approvals, step 4), P1-08 (the leases, step 6) and P1-16 rely on changing settings, and P1-10.6's console shows them, but no plan owned the settings API (`/api/v1/settings`, [architecture](../../architecture/mvp-architecture.md), section 4.2) or an audit event for a change of setting.

## Scope

**In:** the API; a registry in which each domain declares the keys it owns; validation, optimistic concurrency, the audit event, notifications to the steering committee and effects after commit; the reference, generated from the registry; the registration of P1-04's five seeded keys (step 6).

**Out:**

- the settings themselves, which their plans own: P1-04, P1-06, P1-08 and P1-16, each of which registers its keys, except those that step 6 registers on its behalf;
- the console page (P1-10.6);
- the file and environment configuration (`internal/platform/config`), which the server reads at start;
- role mappings and bindings, the other half of the permission matrix's row (P1-03).

## Deliverables

- `internal/platform/settings`: the registry and the store, with their queries in `internal/platform/db/queries`, where the background jobs keep theirs.
- `internal/api/rest/settings.go`, with the OpenAPI operations of step 1, and `Settings` in `rest.Options`.
- The registrations of the keys of step 6, in their owners' packages, and the wiring of every registration in `cmd/whitetower/main.go`.
- In `internal/inventory`, the read of `inventory.data_categories` `FOR SHARE` in `checkCategories`, before `Next` (step 6).
- The core event type `whitetower.setting.changed.v1`, with its schema, example, catalog entry, rule in `internal/audit/facts.go` and line in `internal/audit/testdata/facts.json` (AGENTS.md, "Audit events").
- For pull request 3 (step 4): the kind `setting_changed`, in a migration that widens the check on `inbox_items.kind` and among the API's inbox kinds; and the event ID that `audit.Writer.Record` gives its caller.
- A migration that deletes the row of `audit.retention_months`, which nothing reads (step 6).
- The background job `settings-effects` (step 5), and its row in the table of background jobs of the [architecture](../../architecture/mvp-architecture.md), section 3.1.
- `docs/reference/settings.md`, generated from the registry, and its test (step 7).
- `docs/development/internals.md`: the registry, and the rule that a plan that adds a setting registers it.
- Security tests ST-84 and ST-85.

## Steps

### 1. API first

Write the OpenAPI operations, under a new tag `settings`, and agree them with the console side (P1-10.6). They replace the placeholder `manageSettings` of `internal/authz`, which maps to `settings.manage` but names no operation of the document.

| Operation | Request | What it does |
| --- | --- | --- |
| `listSettings` | `GET /api/v1/settings` | Lists the settings by key, each with its value, version, owner, whether it can be edited, its description and bounds, whether a change notifies the steering committee, and who changed it last and when |
| `getSetting` | `GET /api/v1/settings/{key}` | Returns one setting, with the ETag that a change must send back |
| `editSetting` | `PUT /api/v1/settings/{key}` | Replaces the value, with `If-Match` on `settings.version` and a reason, and returns the setting at its new version |

- **Refusals** use the codes of the [errors reference](../../reference/api-errors.md):

  | Request | Problem |
  | --- | --- |
  | A change without `If-Match` | `precondition_required` |
  | A change at a version that is no longer current | `precondition_failed` |
  | A key that the `settings` table does not hold | `not_found` |
  | A change of a key that no owner has registered yet, which is listed read-only (step 2) | `conflict` |
  | A value that the owner's validator refuses | `bad_request`, with the owner's detail |
  | A value larger than 16 KiB, or a change without a reason or with one longer than 1,000 characters | `bad_request` |

- **Permissions.** Reading and changing need `settings.manage`, which only the admin role holds (`internal/authz`, `matrix.go`; requirements, section 5.2.1). `Authorizer.registerDefaults` maps the three operations to it, and the break-glass test that names `manageSettings` among the refused operations names `editSetting` instead. The store checks the permission again itself, through `auth.Authorizer`, as the inventory does, so that a token's scopes and a break-glass session's limits apply whatever calls it.
- **Break-glass** gets none of the three (ST-20): `settings.manage` is not among the permissions that a break-glass session keeps.
- **Conventions,** as P1-02 and P1-04 built them: a list is an object with a named array and `nextCursor`, and takes `limit` and `cursor`; the ETag is `rest.ETag` of the version; `If-Match` is the shared parameter `IfMatch`, declared optional, and the handler refuses a change without it (`precondition_required`), so that `TestEveryOperationIsGuarded` still sees 401 and 403; people appear as `PrincipalRef`; error details name nothing internal. The check on `settings.key` allows no slash, so a key is a path parameter.

**Done when:** the operations are merged, the generated clients compile, the permission tests cover them, and the console side has agreed to them. P1-10.6 has no owner yet, so the maintainer's review stands for it, as it did for P1-04's API.

### 2. Store and registry

`internal/platform/settings` holds both. It is a platform package, so it imports nothing above it ([internals](../../development/internals.md)), and every domain, the audit log included, can declare its keys there without an import cycle. What the store needs from above it, the audit writer and P1-04's inbox, reaches it through interfaces of its own, which `cmd/whitetower/main.go` satisfies. The store names the permission by its ID, `settings.manage`, in a constant of its own, since the depguard rule `platform` refuses an import of `internal/authz`; `authz.Authorizer` accepts a permission ID as an operation (`ResolveOperation`).

- **Registration.** At wiring time, in `cmd/whitetower/main.go`, each domain registers the keys it owns. A key registered twice stops the server at start.

  | Member | What it gives |
  | --- | --- |
  | Name | The key, as the `settings` table holds it |
  | Owner | The domain that owns the key, such as `inventory` or `policy` |
  | Description | One or two sentences, for the API and the reference |
  | Shape and bounds | In words, for the API and the reference |
  | Validator | Decodes the value, refusing members it does not know, and checks its bounds; it may read the database in the change's transaction. The detail of its refusal reaches the client, so it names nothing internal |
  | Notification | Whether a change notifies the steering committee (step 4) |
  | Effect | Optional work that a change triggers after commit (step 5) |

- **What is listed.** The store lists every row of the `settings` table. A registered key can be edited. A row that no owner has registered yet is listed read-only, without an owner or a description, until its plan registers it (step 6). A key that the table does not hold is refused: the store never inserts a row, so a plan that adds a key adds its row with a migration, as P1-06 and P1-16 do.
- **A change** runs in `db.InTx`. It locks the setting's row, checks its version against `If-Match`, runs the owner's validator, and writes the value with the next version, `updated_at` from `clock.Clock` and `updated_by` from the caller, never from the column defaults (the first pitfall of AGENTS.md). In the same transaction it records its audit event (step 3), the steering committee's inbox item when the key notifies (step 4), and the queued effect when the key has one (step 5): a change commits with all of them or not at all.
- **A value** is JSON of at most 16 KiB, so that the event, which carries the value before and after, stays within the 64 KiB of one event ([contracts](../../contracts/module-contract-v0.1.md), section 4.8). A value equal to the current one, compared as canonical JSON (RFC 8785), changes nothing: no new version and no event, as P1-04's edits that change nothing.
- **Concurrency.** The row lock orders two changes of one key, on one replica or two: the second, sent with the version that the first replaced, answers `precondition_failed`.
- **Readers** keep reading the table at use, as `internal/inventory` does: `inventory.data_categories` at each proposal and edit, and `killswitch.lease_ttl_seconds` at each write of an agent's governance state. Nothing caches a setting, so no cache needs invalidating, and a change applies from the next read on every replica.

**Done when:** each refusal of step 1 changes nothing and writes no event; a change made on one replica is read on another (`dbtest.OpenReplica`); and a change whose audit event cannot be recorded is rolled back entirely.

### 3. The audit event

A new core event type, `whitetower.setting.changed.v1`, with the five parts that AGENTS.md lists under "Audit events".

- **Its data:** the key, the value before and after, the new version, the actor by pseudonymous ID (NFR-20) and the reason, of 1 to 1,000 characters, as in the other core events. The schema refuses unknown members.
- **No subject.** A setting is not an agent, so owners' audit reads, which filter on the agent, never show the event; the steering and advisory committees, operators and auditors read it (permission matrix).
- **Its rule** in `internal/audit/facts.go` indexes the actor and the reason, as the rule of `whitetower.principal.deactivated.v1` does.
- **No secret.** A setting never holds one: secrets are files, named by the `_file` settings of `internal/platform/config`, so the event can carry the values in clear.

**Done when:** the example validates and is indexed in the golden file, and each change of step 2 writes exactly one event, with the value it replaced and the value it wrote.

### 4. Notifications

- **Which keys.** A key's owner marks whether a change of it can weaken a control. Any change of such a key notifies the steering committee, whatever its direction: the committee sees every change of a control, and the store needs no rule about which direction weakens it.
- **The first keys that notify** are these, as the maintainer decided on 2026-10-22:
  - `policy.approval_quorum` (P1-06, step 4), and `killswitch.lease_ttl_seconds` and `killswitch.unconfirmed_after_seconds` (P1-08, step 6), which their plans register;
  - `catalog.pending_entries_per_agent` (P1-16, pull request 2), since raising it loosens the bound of DC-10;
  - `lifecycle.review_unused_tooling_days` (P1-16, pull request 2), since a longer period keeps unused tooling off the candidates to disable that reviews list, which CAT-09 asks for;
  - two of the keys that this plan registers for P1-04 (step 6): the review intervals and the grace period, since rarer reviews and a later automatic suspension weaken INV-06 and INV-05.
- **A later key that notifies:** `catalog.redaction_rules` (P1-16, pull request 3), under the same rule (DC-11), since removing a redaction rule lets secrets in URL paths reach the catalog (CAT-10; RFC-0002, EP-14).
- **How.** The notification is an item of P1-04's inbox (its pull request 7), as DC-4 asks for grants of steering, advisory or operator. It is addressed to the steering role, of a new kind `setting_changed`, and its subject is the change's audit event (`subjectType` `audit_event`), which the committee may read (`getAuditEvent`). It is written in the change's transaction, with `created_at` from `clock.Clock`, so a change never commits without it.
- **How it leaves the inbox.** The item asks for no action, so no handling takes it out. Each member of the steering committee has their own copy, and dismisses it once they have read the event: a dismissal takes the item out of that member's inbox only, so every member sees every change, whoever made it (the maintainer's decision of 2026-10-22). The dismissal is an operation of the inbox that P1-04 pull request 7 adds for the items that ask for no action, with the record of who dismissed what, and DC-4's notices of grants use it too.
- **What changes for it.**
  - The migration of pull request 3 adds `setting_changed` to the check on `inbox_items.kind`, and the inbox kinds of the API (`x-extensible-enum`) gain it.
  - `audit.Writer.Record` returns no event ID today: pull request 3 lets its caller learn the ID it records, so that the item can name the event.
- **Until the inbox lists items.** Pull request 3 waits for P1-04's inbox; until then, the audit event alone records a change of a key that notifies.

**Done when:** a change of a key that notifies puts one item in the steering committee's inbox, in its transaction, and a change of any other key puts none (ST-85); each member of the committee has their own copy of the item, and a member's dismissal takes it out of their own inbox only.

### 5. Effects after commit

Some changes must reach state outside the `settings` table: after a change of `killswitch.lease_ttl_seconds`, P1-08 step 6 re-publishes the agents whose lease changed. An owner gives such a key an effect.

- **Queued in the change's transaction,** as a row of the `outbox` table, the transactional outbox of ADR-0003, which nothing uses yet. The row's topic is `setting.effect`, its payload the key and the version, and its `created_at` comes from `clock.Clock`. The job reads and removes only the rows of that topic, and a later reader of the outbox, such as the webhooks of API-05, reads only its own topics, so that neither takes the other's rows and an effect never leaves the core as a webhook. An `AfterCommit` hook would not do: a crash right after the commit would lose the effect, and every replica that commits a change would run effects at the same time.
- **Run by one job.** A background job, `settings-effects`, runs on one replica at a time (`internal/platform/jobs`), every 5 seconds. It runs the queued effects in order, one at a time, with one run for all the queued changes of a key, and removes their rows once the effect succeeds. One job at a time is what the design of the halt path asks of the writers that change many agents ([P1-08's design note](P1-08-kill-switch.md#progress-notes), section 2), and P1-08's effect writes at most 100 agents per transaction.
- **Idempotent.** An effect reads the setting's current value, so a retry, or several changes in a row, end in the same state.
- **Writers under way.** A reader whose writes an effect corrects reads the setting `FOR SHARE` before `Next`, as step 6 does for the categories. A change then waits for the writers under way, and the effect, which runs after the commit, sees what they wrote.
- **A failure** raises an alert: the log names the key, and the job's run ends with an error, which `whitetower_job_failures_total` counts. The job goes on with the effects of the other keys, and retries the failed one at its next run. A failure never undoes the change, which is committed and audited.

**Done when:** an effect runs after its change commits, and never for a change that rolled back; a failed effect is retried at the next run and counted, holds back no other key's effect, and its change stays (tests with a fake clock).

### 6. The seeded keys

The first migration seeds eight keys (`00001_init.sql`). This plan registers P1-04's five seeded keys, which need no effect, on its behalf and in its package, with the rules its plan gives. Where it gave none, the bounds below are the ones the maintainer accepted on 2026-10-22.

| Key | Owner | Default | Rules | Notifies |
| --- | --- | --- | --- | --- |
| `inventory.data_categories` | `inventory` (P1-04) | The ten categories of the domain model, section 5 | At least one, since every agent and use case names one; distinct and not blank, each of at most 63 characters, the API's bound on an agent's categories. A category stays while an agent that is neither retired nor rejected, or a use case that is neither validated nor rejected, names it: the inventory refuses any edit of their categories that keeps one the setting lacks. The validator reads them in the change's transaction | No |
| `lifecycle.review_interval_days` | `inventory` (P1-04) | Low 365, medium 365, high 180, critical 90 | The four risk tiers, none missing and no other, each 1 to 730 days | Yes: a longer interval makes reviews rarer (INV-06) |
| `lifecycle.review_grace_days` | `inventory` (P1-04) | 14 | 0 to 90 days | Yes: a longer grace period delays the automatic suspension (INV-05) |
| `lifecycle.review_reminder_days` | `inventory` (P1-04) | 30, 7 and 1 | 1 to 10 distinct numbers of days before the due date, each 1 to 365 | No |
| `lifecycle.review_signoff_risk_tiers` | `inventory` (P1-04) | High and critical | Distinct risk tiers, which include `high` and `critical`, whose reviews P1-04 step 6 and the permission matrix give an advisory sign-off; `low` and `medium` can be added | No: `high` and `critical` always stay, so no change removes a sign-off that P1-04 step 6 and the permission matrix require |

**A removed category is never written.** At read committed, a change that removes a category and a proposal or an edit that names it would miss each other: the validator counts, in the change's transaction, the agents and use cases that name the category, while the inventory reads the setting with a plain `SELECT` where it checks categories (`checkCategories`). Pull request 1 therefore makes the inventory read the setting `FOR SHARE` there, in proposals, new use cases and edits of the categories of agents and use cases, before the transaction takes its governance state version (`StateVersions.Next`), as [P1-08's design note](P1-08-kill-switch.md#progress-notes) asks of every row lock (section 2). A removal then waits for the proposals and edits under way, and they wait for it and read the new value.

None of these keys needs an effect. A review stores its due date, the end of its grace period and whether it needs a sign-off when it is scheduled (`reviews.due_at`, `grace_ends_at` and `signoff_required`), so a change of the interval, the grace period or the sign-off tiers applies to the reviews scheduled after it; the reminders and the categories are read at use. Nothing reads the four `lifecycle.review_*` keys before P1-04 pull request 5, which builds the reviews and the guard job and reads them at use; it may tighten these rules in their registration.

The other seeded keys stay read-only:

- `killswitch.lease_ttl_seconds` and `killswitch.unconfirmed_after_seconds`, until P1-08 registers them with their validators and the lease's effect (its step 6). A change of the lease before then would leave every agent on its old lease, since nothing would re-publish them.

`audit.retention_months` goes: nothing reads it, since the retention job takes its period from `audit.retention.days` in the file configuration, at least 180 days unless `audit.retention.allow_short` is set ([P1-02's progress notes](P1-02-audit-log.md#progress-notes), 2026-10-14). Registered, it would let the administrator change a value that changes nothing, so pull request 1 deletes its row with a migration (the maintainer's decision of 2026-10-22). Shortening the retention of evidence then still needs access to the server's configuration, apart from the administrator's role.

Later plans add keys with the migrations that insert their defaults, and register them in the same part: `policy.approval_quorum` (P1-06 step 4), `lifecycle.review_unused_tooling_days` and `catalog.pending_entries_per_agent` (P1-16 pull request 2), `catalog.redaction_rules` (P1-16 pull request 3), and `killswitch.drill_max_seconds` (P1-08 step 8). When P1-06 step 4 or P1-16 pull request 2 or 3 lands before this plan, this plan registers their keys on their behalf, with the rules their plans give.

**Done when:** each key of the table is listed with its owner and bounds; a change within its rules is accepted, and one beyond them refused with the owner's detail; the read-only keys refuse every change; and a fuzz test, seeded with the defaults, gives each validator of the table random values, and checks that it accepts or refuses every one and never fails otherwise.

### 7. The reference

`docs/reference/settings.md` lists every setting: its key, owner, default, bounds, whether a change notifies the steering committee, and description, with the rows that no owner has registered yet as read-only. It is generated, as the [configuration reference](../../reference/configuration.md) is, and says so.

- A test in `cmd/whitetower`, `TestSettingsReferenceIsCurrent`, builds the registry as `serve` does, reads the defaults from a migrated database (`dbtest`), renders the page, and fails when the file differs; `go test ./cmd/whitetower -run TestSettingsReferenceIsCurrent -update` rewrites it. The defaults come from the migrations, so they are never written twice.
- It also fails when a registered key has no row, so a plan that registers a key adds its migration.

**Done when:** the reference is in the repository, and the test fails after a change to a registration until `-update` rewrites the file.

## Acceptance criteria

- The platform administrator lists, reads and changes settings through the API; every other role, a token without the scope `settings.manage` and a break-glass session are refused (ST-84).
- A change is refused, and changes nothing, without `If-Match`, at a stale version, with a value that its owner refuses, for an unknown key and for a key listed read-only, each with the problem of step 1.
- Every change commits with its `whitetower.setting.changed.v1` event, or not at all: a forced failure of the audit write rolls the change back (ST-85).
- A change of a key that can weaken a control puts an item in the steering committee's inbox, in the change's transaction (ST-85).
- An effect runs once its change is committed, one at a time, and a failed one is retried and counted, while the change stays.
- The keys of step 6 are registered with their rules, the row of `audit.retention_months` is gone, and the other seeded keys are listed read-only.
- `docs/reference/settings.md` is current, and its test fails when it is stale.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-17-settings) pass: ST-84 and ST-85.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| A malicious platform administrator ([threat model](../../security/threat-model.md), TA-6 and T-83) weakens a control through a setting: a quorum of one, longer leases, rarer reviews | Every change is audited with its actor and reason (step 3); each owner's validator bounds its values; a change of a key that can weaken a control notifies the steering committee (step 4, DC-11) |
| A setting changes before its effect is built: the lease would change while every agent kept its old one | Such a key stays read-only until its owner registers it with its effect (step 6) |
| A replica caches a setting and keeps the old value after a change | Readers read the table at use, and nothing caches a setting (step 2) |
| An effect fails and leaves the state behind its setting | The job retries it at each run, logs it and counts it (step 5); the change stays |

## Notes for implementers

- Keep the two kinds of settings apart: `internal/platform/config` holds what the server reads from its file and environment at start, and this plan what the administrator changes at runtime. A secret is never a runtime setting.
- The store's refusals follow the inventory's pattern: a kind for each problem of step 1, and a detail that names nothing internal, which the REST API maps to its codes.
- Reuse `rest.ETag`, `rest.IfMatch`, `rest.Stale`, `rest.PageSize`, `rest.EncodeCursor` and `rest.DecodeCursor`, `PrincipalRef`, `github.com/gowebpki/jcs` for canonical JSON, `auth.Authorizer` and `jobs.Runner`.
- Store every time with the injected clock: `settings.updated_at`, and the `created_at` of the inbox item and of the outbox row (AGENTS.md, pitfalls).
- A validator refuses members it does not know, so a misspelled risk tier is refused rather than ignored.
- In REST tests, pass `Authorizer: authz.NewAuthorizer()` in the `rest.Options` given to `resttest.New`, which otherwise allows everything, so that the matrix's refusals are tested.

## Progress notes

The plan lands in three pull requests. The first two need only P1-01 to P1-03; the third waits for P1-04's inbox (its pull request 7).

| Pull request | Steps | Status |
| --- | --- | --- |
| 1. API, store and registry, audit event, keys of P1-04 | 1, 2, 3, 6; ST-84 | Not started |
| 2. Effects and the reference | 5, 7 | Not started |
| 3. Notifications | 4; ST-85 | Not started |
