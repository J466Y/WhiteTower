# P1-08: Kill switch

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L |
| **Depends on** | P1-04, P1-05, P1-07 |
| **Unblocks** | P1-09, P1-10.5, P1-15 (end-to-end tests), P1-14; P1-16 step 7, through the accepted design of the halt path and the harness of step 10 |
| **Requirements** | KIL-01 to KIL-10, NFR-03 to NFR-05, NFR-24 (the harness that measures it) |
| **Decisions** | ADR-0005, ADR-0010, [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) |

## Goal

Anyone with the right role can stop one agent, a selection of agents or the whole fleet from the console, the API or the CLI, in seconds and without asking permission. The system shows which instances confirmed the stop and how long it took, keeps stopped agents from getting credentials, and makes sure that bringing anything back takes two people.

## Scope

**In:** the design of the halt path, blocks included; halt domain and API, fleet and selector halts, propagation tracking, release workflow, lease policy, break-glass integration, drills, fault-injection tests, performance validation and its harness, runbooks.

**Out:** the watch transport (P1-07); what the enforcement point does inside the agent (P1-09); the network quarantine module (P1-15); the console screens (P1-10.5); stopping workloads (Phase 2 harness module); the blocks of [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) (P1-16) and their transport (P1-07).

## Deliverables

- `internal/killswitch` with its OpenAPI operations.
- Propagation metrics and alerts.
- The fault-injection test suite.
- The measurement harness of step 10, which P1-16 reuses for blocks.
- Runbooks: halting, unconfirmed halts, releasing, and stopping one environment.

## Steps

**The design comes first.** The design note of the halt path is in this plan's [progress notes](#progress-notes), accepted by the maintainer on 2026-10-20. It binds this plan, P1-07 steps 5 and 6, P1-16 step 7, and every plan that changes what enforcement points see; where a step says less or otherwise, the note decides. Changes to it are reserved for the reviewer ([AGENTS.md](../../../AGENTS.md)). The halt path must never become a bottleneck, not even when the whole fleet halts with every instance connected and 500 blocks active. The note covers:

- one version counter, held only from a writer's version to its commit, and the rules that keep writers from waiting under it;
- the fan-out through each replica's governance state hub, and renewals only while the replica is current;
- the acknowledgements, halt acknowledgements in batches of their own;
- tracking, halts, releases, selectors and drills;
- the blocks of P1-16, which share the counter, the hub and the streams, but travel in a record of their own, never in the fleet record ([threat model](../../security/threat-model.md), DC-9): a stream holds at most one pending block change, and the state acknowledgements that blocks cause (EP-15) are coalesced.

### 1. API first

- `POST /api/v1/halts`: target (agent, fleet or selector), agent ID or selector, reason, optional `drill` flag, and an idempotency key so retries never create two halts.
- A selector names `riskTiers` (one to four, any of which matches) and `labels` (one to 16, all of which must match), at least one of the two, and its description says that the halt stops the matched agents in every environment. The generated handlers drop the members a schema does not name, so the operation decodes its body itself. It refuses with `bad_request` any member it does not know, at the top level or in the selector, and a selector that names an environment or nothing; the detail names the member (the design note, section 8).
- A read-only preview of a fleet target, and, with the selector halt (Should), of a selector target, with the permission that issuing it needs, break-glass included: the number of agents it matches now, their connected instances, and a page of those agents. It runs the halt's own matcher on the main pool, never on the halt path's connections. The halt also stops the agents and instances that match or connect later.
- `GET /api/v1/halts`: active halts and history.
- `GET /api/v1/halts/{id}`: status per instance.
- Release requests and their approvals.

Permissions follow the matrix: halting an agent is open to steering, advisory, its owner and operators; halting the fleet, or the agents a selector matches, to steering and operators. `POST /api/v1/halts` maps to `halt.agent.issue`, and for a fleet or selector target the domain also checks `halt.fleet.issue`; the operation replaces the placeholders `haltAgent` and `haltFleet` of `internal/authz`. Releases are requested and approved by people only (step 5).

**Done when:** the operations are merged and agreed with P1-10.5 and P1-11.

### 2. Halt domain

In one transaction, in the order of the design note (section 8), all at the transaction's governance state version:

- create the halt record;
- set the run state to halted for the targets;
- write its audit event, `whitetower.halt.issued.v1`;
- for an agent halt that is not a drill, move the agent to `suspended` with the halt as reason (T12, KIL-06), through the lifecycle engine's entry point for the transitions White Tower makes itself (P1-04), which writes its own transition and event.

After commit, notify the other replicas. Token issuance is blocked at once for every audience but the module API, because the gate of P1-05 reads the run state; the enforcement point keeps its channel to the core ([threat model](../../security/threat-model.md), DC-1).

**Done when:** after a successful response, the halt is visible on every replica and the agent's next token request for any audience but the module API fails (test).

### 3. Fleet and selector halts

- A fleet halt is one fleet state record. It covers every agent, including agents registered or connecting later, and **does not change lifecycle states** (KIL-06).
- A selector halt (Should) stores its selector (risk tiers and labels) and applies it to current and future agents, in every environment. A selector that names an environment, any other member, or nothing is refused with `bad_request` and creates no halt (the design note, section 8). Its release records the agents it covered.
- An agent stays halted while any halt covering it is active.
- Blocks (RFC-0002) never enter the fleet record: a fleet halt changes `fleet_state` and never the blocks record, so it costs the same whatever the number of active blocks.

**Done when:** an agent registered after a fleet halt starts halted, and releasing one of two overlapping halts leaves the agent halted. A selector that names an environment, an unknown member or nothing is refused and creates no halt. One selector halt closes the gates of two mock instances of the same agent that authenticate as the agent, one on a production credential and one on a non-production credential, and the token endpoint then refuses both credentials for every audience but the module API.

### 4. Propagation tracking

- **Expected pairs** of instance and agent: the instances whose streams carry a targeted agent when a replica applies the halt, every instance shown as connected whose scope covers a targeted agent, and those whose streams open while it is active (the design note, section 7). They include the network quarantine module of each cluster where a targeted agent has pods (P1-15), while it serves the agent.
- **Acknowledgements** report each layer with its timestamp: gate closed, in-flight action interrupted, process terminated, network quarantined (with the number of workloads covered).
- **Halt status:** propagating, then confirmed (every expected pair acknowledged), partially confirmed, or unconfirmed after a timeout (10 seconds by default), which fires an alert.
- **Metrics:** `whitetower_halt_propagation_seconds` (issued to acknowledged), `whitetower_halt_effect_seconds` (issued to in-flight interruption or termination) and `whitetower_halt_quarantine_seconds` (issued to network quarantine applied).
- An instance is flagged as suspect when it reports an allow decision or an executed action whose time is after its acknowledged gate closing ([threat model](../../security/threat-model.md), DC-6). Denials, and evidence buffered before the halt and delivered afterwards, are expected.
- **Reuse for blocks.** Build the tracking (expected instances, acknowledgements, status, timeout, alert, metrics) so that P1-16 tracks the spread of blocks with it, keyed by state version instead of halt ID: for a block, the expected instances are the connected enforcement points, and a state acknowledgement at or after the block's version counts (`instance_agents.observed_state_version`). A second tracker would duplicate this one.

**Done when:** the status and the metrics are correct in tests with mock instances that acknowledge, delay, stay silent and lie, including a mock quarantine module.

### 5. Release workflow

- A release request, with a reason, is made by an authorized person; an owner may request the release of their own agent's halt.
- A **different** authorized person approves it (KIL-05), following the permission matrix: steering, advisory or an operator for an agent halt; steering or an operator for a fleet or selector halt.
- Both are people: a service account is refused (`forbidden`), and a trigger refuses a requester or an approver that is not a person, since a person and their own service account are one person (the design note, section 8).
- On approval, the run state returns to running if no other halt covers the agent.
- For an agent halt, the agent **stays suspended**: reinstating it is a separate lifecycle transition (P1-04), so a release never puts an agent back into service on its own.

**Done when:** releasing with one person is impossible (tests), and the lifecycle state is unchanged by a release.

### 6. Lease policy

- Lease TTL per risk tier comes from the settings, with defaults from P0-05; renewals are sent every third of the shortest TTL in scope, and at least every 30 seconds (P1-07; the design note, section 4), and only while the replica is current (section 5).
- An edit of `killswitch.lease_ttl_seconds` is refused unless every tier's lease is 10 to 300 seconds, and re-publishes the agents whose lease changed, at most 100 per transaction.
- The core cannot see an enforcement point's clock, so it treats an instance as **lost** once it has sent no heartbeat and held no stream for longer than the shortest TTL in its scope (CORE-4; the design note, section 7). The console shows a lost enforcement point as "failed closed (lost contact)", and a runtime-control module lost before it acknowledged a halt, for that halt, as "lost contact: layer not applied" (the design note, section 7).

**Done when:** the tracker of every replica marks lost instances (the design note, section 7), and they are counted in the halt status.

### 7. Break-glass (Should)

The break-glass session of P1-03 can call the halt endpoints and nothing else. The console's minimal break-glass page (P1-10.5) and the CLI both use it.

**Done when:** with the IdP stopped, a break-glass session halts an agent and the fleet (end-to-end test).

### 8. Drills (Should)

- A drill is a halt with `drill=true` on an agent that its owner marked as eligible. It closes the gate like any halt, but **does not suspend the agent** (no T12), so the agent is back in service when the drill ends (the design note, section 13, decision 1).
- It is released automatically once confirmed, or after `killswitch.drill_max_seconds` (60 by default; an edit outside 10 to 300 seconds is refused). The release is a system action, without the two-person rule, and is audited.
- Timings are recorded. A drill, like any halt, gives the agent coverage C3 under the design note's per-agent rule (section 7; INV-08).
- Drills can be scheduled.

**Done when:** a drill on a mock agent runs, is released and updates coverage.

### 9. Fault injection and end-to-end tests

- A core replica crashes during a halt: the enforcement points reconnect and still see it halted.
- Database failover during a halt.
- Network partition between an enforcement point and the core: it halts within the TTL plus a tolerance.
- Duplicate, late and forged acknowledgements; forged ones are rejected.
- An enforcement point restarts while halted and starts halted (KIL-07).

**Done when:** every scenario runs in CI with the mock module, and those needing real infrastructure run in the P1-12 environment.

### 10. Performance validation

With 500 mock instances, halt one agent and the whole fleet repeatedly. Measure against NFR-03 to NFR-05 and publish the results, which feed P1-13 and the pilot. Every run adds the background load of the design note (section 11): token requests, audit events at the sustained rate of NFR-07 (200 per second), a rebuild of every bundle once P1-06 is merged, and a replica restart. One scenario issues a selector halt over 1,000 agents with an agent halt and a fleet halt right behind it: the report shows how long the version counter is held while the rows are stamped, and how long the halts behind it wait.

The harness extends the load test of P1-07 (its step 10) with halt scenarios, rather than being a second harness (the design note, section 14). It drives scripted scenarios against the mock module of P1-07, and reports per-instance timings from issue to acknowledgement. P1-16 reuses it, with scenarios of its own, to measure the spread of blocks (NFR-24) and halts with 500 active blocks (ST-80), so build it to be run again with new scenarios.

**Done when:** the report is in `docs/performance/`, and the harness runs from one documented command.

### 11. Runbooks

- How to halt an agent or the fleet.
- What to do when a halt stays unconfirmed: check the network quarantine layer (P1-15); otherwise kill the process or pod manually, revoke credentials and isolate the network by hand.
- How to release, and then how to reinstate.
- How to stop one environment, which a halt cannot do in v0.1:
  - a halt stops its agents in every environment, and a label such as `env=production` selects agents, not instances;
  - for an emergency in production, halt the agents involved, with one selector halt where they share labels or a risk tier, or, when in doubt, the fleet. A fleet or selector halt changes no lifecycle state, so one two-person release restores its agents without reinstating anyone; an agent halt suspends its agent (T12), which then needs its own release and a reinstatement (T13);
  - for a problem confined to non-production, use the platform's own controls, or revoke the agent's non-production credentials, which stops the enforcement points that authenticate as the agent there within the token's remaining lifetime plus the lease TTL. An enforcement point that authenticates as its module keeps serving the agent until the module's own non-production credential is revoked, which stops it for every agent it serves;
  - a global policy that forbids actions where `principal.environment` is the one to stop is slower, takes two people and relies on credential labels, so it is never the first stop.

**Done when:** the runbooks are reviewed by an operator and rehearsed once.

## Acceptance criteria

- Halts of one agent and of the fleet reach 500 mock instances within the NFR-03 target, with confirmed status per instance.
- In the partition test, the mock instance halts within its TTL plus tolerance.
- A release, other than a drill's, needs two distinct authorized people, never a service account, and leaves an agent-halted agent suspended; a drill leaves the agent's lifecycle state unchanged.
- A fleet halt covers agents registered after it was issued.
- A selector halt stops the matched agents' instances on production and non-production credentials alike, and a selector that names an environment is refused.
- Every step is audited, and the runbooks are reviewed.
- The harness of step 10 runs again with new scenarios, as P1-16 needs for ST-80.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-08-kill-switch) pass: ST-40 to ST-45.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Enforcement points acknowledge but do not stop | Layered acknowledgements; suspicious activity flagged; token issuance stopped for every audience but the module API; network quarantine on Kubernetes (P1-15); stopping workloads in Phase 2 |
| Accidental fleet halt | Strong confirmation in the console and CLI (reason plus an explicit confirmation), fast two-person release, and drills that build familiarity |
| An operator expects a halt to stop one environment only | The console and the CLI say that a halt stops its agents in every environment, and the runbook of step 11 names the slower tools for one environment |
| Halt storms (many halts issued in a short time) | Idempotency keys; coalesced state changes in the governance state hub |
| The blocks of P1-16 slow halts (T-80, DC-9) | The accepted design: a record of their own, never in the fleet record; at most 500 active, hashed; the version counter held only until commit; merged block changes; halt acknowledgements apart. P1-16 measures halts with 500 active blocks with the harness of step 10 (ST-80) |

## Notes for implementers

- Never make halting depend on anything slower than one database transaction: no synchronous calls to modules, and no approval. Nor on the number of active blocks: a halt's transaction neither reads nor writes blocks.
- Keep the halt path free of optional dependencies (SMTP, webhooks): notifications happen after commit and may fail without affecting the halt.
- The halt, the suspension (for an agent halt that is not a drill) and the state version must be in one transaction; test it with a failure injected between them.
- Spike S2 measured this path with 1,000 enforcement points: a fleet halt was delivered with p99 ≤ 310 ms and acknowledged with p95 0.63 s. Most of the difference is 1,000 acknowledgements written in a burst: write them in batches ([report](../../spikes/S2-watch-streams.md)).

## Progress notes

### 2026-10-19: design of the halt path (accepted on 2026-10-20)

This is the design note that the Steps section asks for. The reviewer wrote it, and the maintainer accepted it on 2026-10-20, with the decisions of section 13. It binds P1-07 steps 5 and 6, this plan and P1-16 step 7, and every plan that changes what enforcement points see: P1-04 (lifecycle, attributes, owners and halt mode), P1-06 (bundles) and P1-07 (bindings). Where a plan says otherwise, this note wins, and section 14 lists what each plan aligns. It builds on the [contracts](../../contracts/module-contract-v0.1.md) (sections 4 and 5), [spike S2](../../spikes/S2-watch-streams.md) and the current schema. On 2026-10-20 it was checked against what P1-04 merged (pull requests #48, #50 and #51) and P1-03's fix (#49), and corrected where they differ.

#### 1. Principles

1. **One order.** Everything enforcement points see is a write to one of four records, stamped with a version from one counter. Writers commit in version order, so "everything after version V" is always well defined.
2. **A halt waits for nothing slow.** It is one short transaction. Everything after it, from the fan-out to the tracking, happens after commit and off its path.
3. **Each replica holds the whole governance state in memory.** The hub reads the database; streams never do. At MVP scale the state takes a few megabytes, and at most about 70 MB at the inventory's bounds (section 4).
4. **A stream holds at most one pending change.** New changes merge into it, so a slow client never slows the hub or another stream, and a halt never queues behind other changes.
5. **A renewal is a promise.** A replica renews leases only while it can show that it is current. When it cannot, leases run out and enforcement points fail closed.
6. **The database enforces what the halt path relies on,** as it already does for separation of duties: the head (section 2), the immutability of halts, and a release by two different people, never a service account.

#### 2. Versions and the head

The records that enforcement points see:

| Record | Table | Carries |
| --- | --- | --- |
| Agent state | `governance_state` | Lifecycle state, agent and selector halts, bundle reference, lease TTL, halt mode, attributes (owner included) |
| Fleet state | `fleet_state` | Active fleet halts |
| Blocks (P1-16) | `catalog_blocks` | Active blocks, and lifted ones with the version that lifted them |
| Scope | `module_agent_bindings` | The agents each module's instances may watch |

Every agent has its state row from its creation: T1 inserts it in the agent's own transaction, and every later writer updates it and never inserts one. A writer that finds no state row for an agent it changes fails its transaction (section 10).

- **The counter.** A single-row table, `governance_head`, holds the last version handed out; this note calls its row the head, and the plans call it the version counter. A transaction takes its version through one SQL function, `next_governance_version()`, which runs `UPDATE governance_head SET version = version + 1 RETURNING version`. The update holds the row's lock until commit, so the next writer gets its version only after this one commits: commit order is version order. This has the effect of spike S2's advisory lock, and also tells readers the last committed version. The migration seeds the head from `governance_state_version_seq`, and the runtime role loses its use of the sequence, so no code can take a version any other way. A version taken by a transaction that rolls back is handed out again, which is harmless: it was never visible.
- **One version per transaction.** Every record a transaction changes gets the same version. The function moves the head on its first call in a transaction and keeps the version in a transaction-local setting; a later call in the same transaction returns that version without moving the head. The function and the triggers read the setting as `NULLIF(current_setting('whitetower.governance_version', true), '')`: on a pooled connection, a setting that an earlier transaction set locally reads as an empty string, not as NULL.
- **One interface.** Writers take the version through `StateVersions.Next(ctx, tx)`, the interface that P1-04 already calls (`internal/inventory/state.go`). `internal/govstate` implements it (section 14). Every other domain that writes these records declares the same one-method interface, under the same name, and `cmd/whitetower/main.go` gives each the same implementation. Since a second call returns the same version, a halt and the T12 it applies share one. The first call in a transaction also registers the notification of section 3.
- **The order of a writer.** A writer does its checks and takes every row lock first. Then it calls `Next`. After that, it waits for no lock: it reads only what the head keeps still, such as the active blocks (section 9) or the active selector halts (section 8), stamps the rows it changed, inserts the rows that carry the version (a halt, a lifecycle transition), writes the audit events that carry it, and commits. The head is held from `Next` to the end of the commit: a few milliseconds, and tens of milliseconds for a selector halt or its release (section 11). `TestAProposalBecomesADraftOwnedByItsProposer` checks that a proposal's records share one version, and every writer has such a test.
- **No waiting for a row under the head.**
  - Every row lock a writer holds while it waits for the head is `FOR NO KEY UPDATE` or weaker, never `FOR UPDATE`. The foreign-key checks of rows inserted under the head take key-share locks, which, of the row locks, only `FOR UPDATE` blocks. A `FOR UPDATE` on an agent, held by a writer that waits for the head, would block a row that the head's holder inserts for that agent; PostgreSQL breaks that cycle only after `deadlock_timeout`, 1 second by default, and every halt queued on the head waits that long.
  - A writer locks an agent's row and then its state row, both before `Next`, and several agents in ascending ID order. So a writer that holds the head never waits for a state row that another writer locked before asking for the head.
  - P1-04 departs from both rules today, harmlessly while its versions come from a sequence that no writer waits for: `LockAgent` takes `FOR UPDATE`, and `publishState` locks the state row only by writing it, after `Next`. Both change with the head (section 14).
- **No waiting for a table under the head.** Inserts under the head take ROW EXCLUSIVE locks on their tables, which wait behind any ACCESS EXCLUSIVE request already queued, even one that itself waits for a long reader such as an audit search or a backup. So DDL on a table that writers under the head use never queues for long. In particular, the audit log's partition job creates a new partition as a table and then attaches it, which takes only SHARE UPDATE EXCLUSIVE on `audit_events`, and drops an old one with a `lock_timeout` of 100 ms, retried at its next run (section 14, P1-02).
- **The database checks it.** AFTER ROW triggers, so that the CHECK constraints answer first, refuse any version written to these tables that is not the transaction's:
  - on `governance_state` and `fleet_state`, every insert and update;
  - on `halts`, the inserted `state_version` and the `released_version` that a release sets;
  - on `lifecycle_transitions`, every insert;
  - on `catalog_blocks` and `module_agent_bindings`, the version columns that P1-16 and P1-07 add.

  An update that leaves the version columns unchanged, such as the tracker's propagation outcome (section 7), needs no version. A writer that forgets `Next` fails in its tests, instead of breaking resumption in production.
- **Bounded writers.** Since every writer queues on the head, none may hold it long:

  | Writer | Rows stamped per transaction |
  | --- | --- |
  | Agent halt; a lifecycle transition, the guard job's (P1-04 step 7) included; an edit of what enforcement points see, or a change of the primary owner (P1-04); a binding; a block | 1 |
  | Fleet halt | 1 (`fleet_state`) |
  | Selector halt, or its release | The matching agents: at most 1,000 at MVP scale |
  | Bundle rebuilds (P1-06); the bulk import (P1-04 step 11); re-publishing the agents whose lease changed after an edit of `killswitch.lease_ttl_seconds` (step 6); any other change to many agents | At most 100 agents per chunk, one job at a time |

  A halt then waits behind a few transactions of a few milliseconds each, or tens of milliseconds behind a selector halt (section 11), which step 10 measures.

#### 3. The hub

Each replica runs one hub (P1-07 step 5).

- **What it holds.** The current agent states, the fleet state, the active blocks, the bindings, and the removals it has read since it started (lifted blocks, removed bindings), with their versions. It reads the attributes of each agent with the one type that `internal/govstate` defines for the `attributes` column, which the inventory also writes with (section 14). It also holds `applied`, the version up to which it has read everything, and `syncedAt`, the time of its last successful read on `clock.Clock`. Each record is encoded once per version, and every stream sends the same bytes.
- **How it reads.** In one consistent snapshot (a read-only transaction at REPEATABLE READ, which the `db` package gains, or one statement), it reads the head's committed version and every record whose version, or removal version, is above `applied`. Then `applied` becomes the head's version, since everything up to it is in the snapshot. Spike S2 read two tables in two statements, which could skip a change; one snapshot cannot.
- **When it reads.** After each notification, every second, and whenever a stream asks for a version above `applied`. Reads run one at a time, and one read serves every notification that arrived meanwhile. A lost notification therefore delays a change by one second at most.
- **Notifications are sent after commit,** in a statement of their own, from the `AfterCommit` hook that the first `Next` of a transaction registers; the notify bus gains a publish outside a transaction. This departs, for governance changes only, from the repository's rule that notifications go in the transaction ([internals](../../development/internals.md)): PostgreSQL fails a notifying transaction at commit when its notification queue is full, and the commit would wait on the database-wide notification lock while it holds the head. A notification only asks the hubs to read sooner, so a full queue or a lost listener can never fail or delay a halt's transaction.
- **Applying a read.** Under its lock, the hub updates its records, merges into each stream's pending change what concerns that stream (section 4), and wakes the streams. It also hands the new halts and blocks to the tracking (section 7). This takes microseconds per stream.

#### 4. Streams

- **Scope.** A stream carries the instance's scope, as the contracts define it (section 4.3): its own agent for an enforcement point inside an agent, otherwise the agents bound to its module. It is not filtered by the agents an instance serves, which matter only to tracking: RC-1 needs every halted agent in scope, including those whose workloads start later. Only enforcement points' streams carry blocks.
- **Opening.** The hub registers the stream and builds its first pending change under one lock, so no change can fall between them (the snapshot race of spike S2):
  - `since_version` is 0, or older than what the hub has read since it started: a snapshot of the whole scope at `applied`;
  - otherwise, every record in scope whose version is above `since_version`, with the removals since then;
  - `since_version` above `applied`: the hub reads first, and if the database is still behind, section 10's version regression applies.
- **The pending change.** There is one per stream. It holds the latest state of each agent that changed or entered the scope, the fleet state if it changed, the blocks added and the IDs of those removed (net of each other), the agents that left the scope (net of those that came back), and the target version: the hub's `applied` when it last merged. Its size is bounded by the scope, never by time or traffic.
- **The writer.** One goroutine per stream sends the pending change as one `StateChange` at its target version, or as a snapshot when it is marked so. A change over 1 MiB is sent as a snapshot instead, split into parts (CORE-5 allows a snapshot at any time), whose first part carries the fleet state and the blocks. A typical agent's state encodes in a few hundred bytes, but at the inventory's bounds (64 labels, with values of up to 255 characters) it takes about 70 KB, so about 15 such agents fill 1 MiB: a module with many of them in scope gets its snapshots in many parts. Each send has a deadline of 5 seconds: a stream that misses it is ended (CORE-7), and its enforcement point resumes elsewhere or receives a snapshot.
- **Renewals.** Once its pending change is sent, the writer renews when the interval is due (a third of the shortest TTL in scope, at most 30 seconds), and at once after a snapshot, after an agent enters the scope, and after a resumption catches up. A renewal carries the stream's target version and `server_time` from `clock.Clock`, and goes out only while the replica is current (section 5).
- **Merging keeps the order.** The merged change carries the latest of everything up to its target version. A halt merged with a burst of other changes arrives in the same message, never behind them. A halt issued and released within one send never reaches that stream. A release needs two people, and a drill is released only once every expected pair has acknowledged it, or after `killswitch.drill_max_seconds`, far beyond a send's deadline of 5 seconds, so this needs no special case.
- **Ends.** Each has its code:
  - token expiry: `UNAUTHENTICATED` (CORE-1, timed on `clock.Clock`);
  - revocation: `PERMISSION_DENIED` (MAN-4);
  - a slow client, a stale replica or a drain: `UNAVAILABLE`;
  - a third stream of one instance: `ABORTED`, since two are allowed for the token rollover of I-2.

  A draining replica ends its streams over 2 seconds, so enforcement points reconnect to the other replica with their leases intact.

#### 5. When a replica may renew

A replica is current while its last successful read is less than 3 seconds old, three read intervals; otherwise it is stale. While stale, it sends no renewal: the leases of its streams run out and enforcement points fail closed (KIL-04), instead of trusting a replica that may have missed a halt committed through the other one. Once its last successful read is 10 seconds old, it ends its streams with `UNAVAILABLE` and reports not ready, so enforcement points move to a healthy replica. Spike S2 renewed whenever a stream's queue was empty, so a replica cut off from the database kept leases alive while it missed halts; this closes that gap ([threat model](../../security/threat-model.md), T-31).

#### 6. Acknowledgements

P1-07 step 6.

- **Validation.** Every item must concern an agent in the caller's scope, or the whole request is refused (CORE-2). An acknowledgement of a halt that is unknown or does not cover the agent is not recorded and is counted, but it does not fail the request, so a valid acknowledgement in the same request is never lost (ST-40). An acknowledgement of a released halt is recorded only for an expected pair, so that a drill's later layers are still measured; it changes nothing else, neither the run state, nor the release, nor the propagation outcome.
- **Halt acknowledgements** go to the replica's halt writer, which collects them for 10 ms, or up to 100, and writes them in one transaction on the halt path's own connections (section 11). The response goes out once its items are committed, so "recorded" holds. A fleet halt's 500 acknowledgements take a handful of batches, instead of one commit each: spike S2's 1,000 commits per fleet halt dominated its latency.
- **Merging layers.** Each report is kept per halt, instance, agent and layer. A report replaces an earlier one only when its `after_receipt` is larger, so retries and duplicates change nothing, and a layer moves from `not_done` to `done` as the instance reports it.
- **State and bundle acknowledgements** are coalesced per instance and agent, keeping the highest version, and flushed every 250 ms on the main pool; their requests return after the flush. They never share a batch with halt acknowledgements, so a burst of them, after a block for example, never delays a halt's.
- **No rate limit refuses a halt acknowledgement.**

#### 7. Tracking and status

Step 4 of this plan, reused for blocks.

- **Expected pairs** (instance, agent) are written after commit, never in the halt's transaction. When a hub applies a new halt, it lists its own streams whose scope covers a halted agent, and hands those pairs to its halt writer. A stream that opens while the halt is active adds its own. For a runtime-control instance, a pair counts only while the instance serves the agent (I-6, RC-6). Each hub writes the pairs of its own streams. Before it judges a propagating halt, the tracker of every replica also adds a pair for every instance shown as connected whose scope covers a halted agent, whichever replica streams it, such as one that is reconnecting or cut off, so that a halt never reads confirmed while one of them may still act. A pair is unique, so one written twice counts once, and nothing needs coordinating.
- **Acknowledged** means the gate layer reported `done` for an enforcement point, and the quarantine layer `done` or `not_applicable` for a runtime-control module. The later layers are shown per instance and feed the metrics of step 4, but do not decide the status.
- **Status.**
  - A halt is propagating until every expected pair is acknowledged, and is then confirmed.
  - At the timeout, `killswitch.unconfirmed_after_seconds` (10) after issue, a halt not yet confirmed becomes partially confirmed (some pairs acknowledged) or unconfirmed (none), and the alert fires. It still moves to confirmed if every pair is acknowledged later, while the halt is active.
  - A pair whose instance is lost (CORE-4) before it acknowledges counts as not acknowledged: the halt is not confirmed while it lasts, and becomes partially confirmed or unconfirmed at the timeout. It shows as "failed closed (lost contact)" for an enforcement point, and as "lost contact: layer not applied" for a runtime-control module, which applies no new layer once it loses contact. A pair acknowledged before its instance was lost stays acknowledged, and an instance that returns and acknowledges before the release still moves the halt to confirmed.
  - A halt with no expected pair, once the tracker has added its pairs, is confirmed, with no instance to show.
- **One rule, every replica.** Every replica runs the tracker every second. Each transition is one conditional update (from propagating to confirmed, for example), so replicas never contradict each other, and only the one whose update succeeds raises the alert. No leader is needed, so a failed leader never delays an alert by the jobs' takeover time.
- **The outcome outlives the release.** `halts` keeps its propagation outcome and `confirmed_at` apart from its release, and `halt_expectations` and `halt_layer_reports` are kept with it, so reports still see them afterwards.
- **Coverage C3** (P1-04 step 8) is read per agent, from the pairs, never from a halt's status. A halt or a drill within C3's period counts for an agent it covered when the agent had at least one expected pair and each of its pairs was acknowledged within the maximum of its target: 5 seconds (NFR-03) for an enforcement point, 10 seconds (NFR-23) for a runtime-control module. The time runs from `issued_at`, or from when the pair was added, to the core's receipt of the acknowledging report. P1-04 reads it through an interface that this plan implements; until then, no agent reaches C3.
- **Lost instances.** Each replica refreshes `last_seen_at` for the instances it streams every 5 seconds, so a crashed replica's instances stop being refreshed. The tracker records the loss: on each run, every replica moves, in one conditional update, each `connected` instance whose `last_seen_at` is older than the shortest TTL in its scope (which P1-07 keeps in `module_instances.lease_ttl_seconds`) to `lost`. A deregistered instance stays `disconnected`, never `lost`. A heartbeat, a new stream or the refresh brings a lost instance back to `connected`.
- **Blocks** use the same tracker, keyed by state version: the expected instances are the enforcement points connected when the block arrives, and a state acknowledgement at or after the block's version counts.

#### 8. Halts, releases, selectors and drills

- **An agent halt** (step 2).
  - The body checks the request, takes `issued_at` from `clock.Clock`, and locks the agent's row and its state row with `FOR NO KEY UPDATE`. It fails if the state row is missing (section 2).
  - After `Next`, it inserts the halt, adds it to the agent's state, gives the agent's row a new version (`agents.version`, its ETag) and writes `halt.issued`.
  - Unless the halt is a drill (section 13, decision 1), it then applies T12 through the lifecycle engine's entry point for the transitions White Tower makes itself (T7, T8, T11, T12; P1-04). That entry point runs in the halt's transaction and at its version, never takes one of its own, checks no permission and no If-Match (the halt endpoint already authorized `halt.agent.issue`), and never refuses. It moves an agent in `validated`, `ready` or `active` to `suspended` with reason `halt`, writes its `lifecycle_transitions` row and `agent.lifecycle_changed` as the system, and leaves an agent in any other state as it is.
  - A halt never fails because of a concurrent change: it locks rather than checks a version. A change whose If-Match was read before the halt fails instead, with `precondition_failed`, so an edit never writes `active` over the `suspended` of T12. The notification follows the commit.
- **A fleet halt** locks and stamps `fleet_state` only, whatever the number of agents or blocks.
- **A selector halt** (Should).
  - It follows the fleet rows of the permission matrix (section 13, decision 3): issuing it needs `halt.fleet.issue`, and its release is approved by steering or an operator.
  - A selector names risk tiers, any of which matches, and labels, all of which must match; when it names both, an agent must match both (decision 2). Like every halt, it stops the agents it covers in every environment, whatever credential their instances use: the run state is per agent, and the environment is a label of each credential that nothing verifies in the MVP. A selector that names an environment, any other member, or nothing is refused with `bad_request` before the transaction, and the detail names the member. No member is ever ignored, in the selector or anywhere else in the request: the API's generated handlers drop the members a schema does not name, so the operation decodes its body itself and refuses any member it does not know (step 1).
  - It locks the matching agents' state rows in ID order and stamps them together.
  - **It takes turns with the writers that change what it matches.** A selector halt and its release take, first in their bodies, an exclusive transaction-level advisory lock on a single key, which `internal/govstate` defines and every selector halt shares. Every writer that creates an agent, or changes its labels or risk tier, takes the shared form of the same lock first. At read committed they would otherwise miss each other: the halt would not see the new labels or the new agent, and the writer would not see the halt.
  - **Agents that match later take the halt.** Every write of an agent's state record, in P1-04's `publishState`, adds after its version the active selector halts that the agent matches, through an interface that this plan implements (step 3). This matters for a creation and an edit of the labels or the risk tier; any other write finds the halts already there.
  - Once a halt covers an agent, no write removes it: only a release does.
  - **What it covered stays on record.** While the halt is active, the agents it covers are the state rows that carry it. Its release, which locks those rows anyway, records their IDs on the halt (`covered_agent_ids`), so the incident record lists them afterwards, agents without instances included, without holding the head longer.
- **Releases** (step 5).
  - **Made by people.** A release is requested and approved by people: both are refused to service accounts (`forbidden`), as the decisions on proposals are ([lifecycle](../../architecture/lifecycle.md), section 3), and a trigger refuses a `requested_by` or `decided_by` that is not a person (decision 4). Comparing principals would not be enough: a person and their own service account are two principals but one person (P1-03's notes of 2026-10-19).
  - The body locks the halt, the request and every row that carries the halt, and checks the two people and, for a fleet or selector halt, that the approver is from steering or an operator.
  - After `Next`, it removes the halt from those rows, records `released_version` and writes `halt.released`. An agent halted on its own stays suspended.
- **Service accounts that halt** act with the roles bound to them that their responsible person still holds (P1-03): an agent halt needs the steering, advisory or operator role, and a fleet or selector halt the steering or operator role. The `own` grants never apply to a service account, since only a person owns an agent. When that person leaves, or loses the role, the automation's halts are refused (section 10).
- **Drills.** A drill closes the gate, is measured, and is released by the system once confirmed, or after `killswitch.drill_max_seconds` (60 by default). **It does not suspend the agent** (no T12): a release never reinstates, so a drill that suspended would take the agent out of service until someone reinstated it (section 13, decision 1).
- **Halts are immutable.** Once inserted, a halt changes only in its release, its propagation outcome and `confirmed_at`, and the release trigger tests the drill flag of the row as it was before the update. Today any column can change, so `UPDATE halts SET drill = true, status = 'released'` would release a real agent halt without a second person. Decided release requests become immutable too.

#### 9. Blocks

P1-16 step 7.

- A block is issued or lifted in a transaction of its own, which stamps only its `catalog_blocks` row and never touches the fleet state or an agent's state (DC-9). It checks the cap of 500 active blocks after `Next`, under the head, where no concurrent issue can race it.
- The hub keeps the active blocks as one shared, immutable list. A stream's pending change keeps the blocks added and removed since its last send, net of each other, so a resumed stream ends with the right set of active blocks. This replaces P1-07 step 5's "receives each addition and removal once".
- Only enforcement points' streams carry blocks. A fleet halt writes no block, and a block writes no fleet state; when both are pending for a stream, its one merged change carries both (section 4).
- The state acknowledgements that blocks cause are coalesced (section 6), so a block's burst never delays a halt's acknowledgements.

#### 10. Failures

| Failure | What happens |
| --- | --- |
| A notification is lost, or the listener reconnects | The next read, within a second, catches the change |
| A replica crashes | Its streams end. Enforcement points reconnect to the other replica within a third of their TTL (I-4), resume, and keep their leases. Its instances stop being refreshed, and are lost after their TTL if they do not reconnect |
| A replica loses the database | It stops renewing after 3 seconds and ends its streams after 10: leases run out rather than trust a stale replica |
| The database fails over | Halts committed before the failover are kept when replication is synchronous (P1-12 step 4). Otherwise, the row on version regression applies |
| No synchronous standby answers | With two standbys and a quorum of one, one standby that stops answering never makes a commit wait. If both stop, commits wait until CloudNativePG drops them from the synchronous standbys, after its health checks, and then go on without one (preferred data durability). Every writer queued on the head waits that long, halts included, and P1-12 step 4 measures it. A failover after that can lose committed halts: the row on version regression applies, with its alert |
| A client resumes from a version above the database's head, after an asynchronous failover or a restore (version regression) | The core moves the head just past it, by at most a million versions (`advance_governance_version`), reads, and answers with a full snapshot at that version. The client replaces its state with the database's, never keeps one the database lost, and CORE-5 holds. An alert says that changes were lost, and the restore runbook re-issues halts (P1-12 step 8) |
| A writer breaks the rules of section 2: a `FOR UPDATE`, or a row locked after `Next` | Every writer queued on the head waits with it, halts included. PostgreSQL finds a cycle only after `deadlock_timeout` (1 second) and aborts one transaction, which `InTx` runs again, so the API sees only the delay. Each writer's tests prevent it |
| The audit log's partition job meets a long reader | A new partition is attached without waiting for readers, and an old one is dropped with a short `lock_timeout` and retried: writers under the head wait behind the drop for its `lock_timeout` of 100 ms at most (section 2) |
| An agent has no state row | The halt fails with an internal error rather than commit a halt that no stream would carry. Every agent has its row from T1, the evaluation seed's included (section 14) |
| The person responsible for a service account that halts leaves, or loses the role | The automation's halts are refused: `unauthenticated` while that person is inactive, `forbidden` once they lack the role. The operations guide says to watch for it |
| A slow client | Its pending change keeps merging; after 5 seconds without progress its stream ends |
| A reconnect storm | Snapshots come from memory: no database read per stream, apart from the instance check |
| A halt storm | Each halt is one short transaction on the head; idempotency keys stop duplicates |
| A burst of blocks or bundle rebuilds | They queue on the head one short transaction at a time, merge into pending changes, and their acknowledgements are coalesced apart from halts' |
| A halt's transaction fails | Nothing is visible. The API answers with an error, and the caller retries with the same idempotency key |

#### 11. Budget for NFR-03

A fleet halt at MVP scale, 500 enforcement points on 2 replicas, in the expected case:

| Step | Time |
| --- | --- |
| Wait for the head, then commit | A few milliseconds, the standby's flush included; tens behind a selector halt |
| Notification, then the hub's read | A few milliseconds; one second when the notification is lost |
| Merge into some 250 streams per replica, and send | A few milliseconds |
| Network, gate closed, acknowledgement sent | Two round trips |
| Acknowledgements collected and committed | 10 ms to collect, then a few batches of 100 |

We expect well under a second at p95. The worst case for a connected, healthy enforcement point adds about a second, a lost notification, and stays inside the 5-second maximum. Spike S2 measured p95 0.63 s with one commit per acknowledgement, which this design removes; step 10 measures it. The budget assumes the rules of section 2: a writer that breaks them can add a second (section 10).

- **How it is measured.** The metric runs from `issued_at` to the core's receipt of each gate acknowledgement, both on `clock.Clock`, and the harness of step 10 also times it on its own clock. The runs of step 10 add background load: token requests, audit events at the sustained rate of NFR-07 (200 per second), a rebuild of every bundle once P1-06 is merged, and a replica restart. P1-16 runs them again with 100 block changes and 500 active blocks (ST-80).
- **Connections of its own.** The halt path has a pool of 4 connections per replica: issuing halts and releases, the hub's reads and the halt writer. A burst of tokens, events or state acknowledgements can never make a halt wait for a connection.

#### 12. Schema changes

New migrations, in the plans that need them:

| Change | Plan |
| --- | --- |
| `governance_head`, `next_governance_version()`, `advance_governance_version(target)`, the version-check triggers, and the runtime role's use of the sequence revoked | The first part of section 14 (P1-07) |
| `module_agent_bindings`: `state_version` and `removed_version`, so a resumed stream learns of scope changes | P1-07 |
| `module_instances.environment`: the environment of the credential the instance registered with (section 13, decision 7) | P1-07 |
| `halts`: `released_version`; `propagation` and `confirmed_at`, apart from `status` (active or released); `covered_agent_ids`, which the release of a selector halt sets; immutable columns; the release trigger on the old drill flag; issuers that are service accounts; idempotency keys unique per issuer | P1-08 |
| `halt_release_requests`: immutable once decided; a cancellation records who and when; a trigger refuses a requester or an approver that is not a person | P1-08 |
| `halt_acks`, unused today, replaced by `halt_expectations` (the expected pairs) and `halt_layer_reports` (one row per layer: outcome, `after_receipt`, detail, workloads and the core's receipt time) | P1-08 |
| `lifecycle_transitions.actor_type`: service accounts | P1-04 (pull request 4, as it plans) |
| Setting `killswitch.drill_max_seconds`: 60 by default, 10 to 300 | P1-08 |

Every time compared later comes from `clock.Clock`, never from a column default: `issued_at`, `released_at`, `confirmed_at`, receipt times, `last_seen_at`.

#### 13. Decisions of the maintainer

The maintainer took these decisions on 2026-10-20.

1. **Drills do not suspend the agent.** A drill is an agent halt (`halts_drills_target_one_agent`), and until this decision every agent halt suspended its agent (T12, KIL-06). Coverage C3 needs, on each agent within its period (90 days by default), a halt or drill acknowledged within its targets (section 7), and only the advisory committee or an operator reinstates an agent (T13): drills that suspended would take every agent out of service at each drill. The [lifecycle](../../architecture/lifecycle.md) (T12, its guard and section 7), KIL-06, KIL-09 and the run-state bullet of the requirements' section 5.1.1 say so before P1-04 pull request 4, which builds T12 (section 14).
2. **Halts follow the agent into every environment, and selector halts name risk tiers and labels only,** although KIL-02 (Should) named environments among its examples. In the MVP, the environment is a label that the owner or an operator gives each credential, and nothing checks it against where the workload runs ([threat model](../../security/threat-model.md), T-73 and R-14). A halt narrowed by that label would let a production workload on a key labeled `non_production` keep running, and the tracking would not expect it, so the halt would read confirmed: a kill switch may stop too much, never less than it says. The inventory's `environments` only describe the agent, with names its owner chooses (such as `production` or `prod`), unrelated to each credential's label. So an environment selector is refused (section 8), and an emergency in production is stopped by halting the agents involved or, when in doubt, the fleet. With the clarifications of decision 6, the contracts are to say, while RFC-0001 is in review, that a halt applies wherever the instance runs, and that a field an instance does not know never narrows it (section 14), so a later environment field is additive and fails safe. Halts limited to one environment wait for an RFC of their own, once each instance's environment comes from a verified identity, such as one workload issuer or SPIFFE trust domain per environment (AID-07, AID-09); an instance whose environment is not verified will still apply every halt.
3. **Selector halts follow the fleet rows of the permission matrix,** which has no row for them, since a selector can match the whole fleet: issuing needs `halt.fleet.issue`, and the release is approved by steering or an operator.
4. **Releases are requested and approved by people only,** never by service accounts, as the second person of HUM-04 requires: a service account may halt, but never requests or approves a release. Only the system releases a drill (section 8).
5. **The token window is accepted.** A token request that read the state just before a halt committed can still get a token, within milliseconds. A token issued just before the halt is as valid, for its lifetime (5 minutes by default, AID-03), and the stream closes the gate whatever token a workload holds, so the window gains an attacker nothing. Closing it would make every token request lock the fleet row that fleet halts update, and halts would wait for token traffic.
6. **Contract clarifications** go into the contracts now, while RFC-0001 is in review and changes are free, with the rule of decision 2:
   - an enforcement point applies every agent state a change carries, whatever that state's own version, since an agent that enters the scope keeps its older version;
   - a failure of an established `Watch` stream is transient whatever its code, except `PERMISSION_DENIED`, and `UNAUTHENTICATED`, which needs a new token first; connect-go reports a stream cut in the middle of a message as `INVALID_ARGUMENT`;
   - a renewal's version may pass versions that carried nothing for the stream;
   - the core may answer any resumption with a snapshot, including one at a version it moved forward after a regression.
7. **The core tells each instance the environment of its credential.** `RegisterInstanceResponse` returns the environment recorded for the credential the instance registered with, and `module_instances` keeps it. An enforcement point puts it in the subject of every decision (contracts, section 6.2), never one from its own configuration, nor from its access token, which RFC 9068 (section 6) forbids a client to inspect. The core refuses to register an enforcement point whose credential has no environment, since every decision needs one. An enforcement point that authenticates as its module takes its module credential's environment, which a module credential must have when the module's manifest declares the enforcement-point capability. The environment serves decisions and the console's grouping of instances, and never decides what a halt covers (decision 2).

#### 14. What follows

- **A first part: the first pull request of P1-07.1.** It needs nothing from P1-05, and lands before P1-04 pull request 4, so that the lifecycle engine and the guard job are built and tested against the head rather than a stub.
  - It creates the version mechanism of section 2 and implements `StateVersions` in `internal/govstate`, with the after-commit notification of section 3 and the notify bus's publish outside a transaction.
  - It defines in `internal/govstate` the one type of the state's attributes (today the unexported `attributes` of `internal/inventory/state.go`), which the inventory writes and the hub reads, and the key of the selector halts' advisory lock (section 8), which P1-04's writers take in its shared form.
  - It brings P1-04's writers under the rules of section 2: `LockAgent` takes `FOR NO KEY UPDATE`, and `publishState` locks the state row before `Next`, each with a test that fails without the change.
  - It migrates the rest of what P1-04 and P1-12.1 merged: it removes `inventory.SequenceVersions` and the query `NextStateVersion`, wires the implementation in `cmd/whitetower/main.go`, `internal/inventory/inventory_test.go` and `internal/api/rest/inventory_test.go`, rewrites the comments that give the lock to P1-07 (`state.go`, `main.go`) and the example of the internals, and moves the fixtures of `hack/db/schema_checks.sql` off `nextval`. The evaluation seed (`deploy/compose/eval/seed/seed.sql`) writes each seeded agent's state row, as T1 does: today its agents have none until their first edit, which the rule of section 2 would refuse.
- **P1-04,** from pull request 4, on the head:
  - the point in `publishState` where this plan's interface adds the active selector halts, for every write of the record (today only `Propose` is marked);
  - the lifecycle engine's entry point for the system's transitions (section 8), which give the agent's row a new version; the guard job suspends one agent per transaction, and the bulk import writes at most 100;
  - in its pull request 6, coverage C3 through an interface that this plan implements, under the per-agent rule of section 7 (its step 8);
  - every writer that creates an agent, or changes its labels or risk tier, takes the shared form of the selector halts' advisory lock first, with the key of `internal/govstate` (section 8);
  - `whitetower.agent.updated.v1` requires `state_version` when a change concerns what enforcement points see.
- **P1-07:**
  - step 5: scope rather than served agents; one pending change per stream; reads in one snapshot; renewals only while the replica is current; the codes of section 4; `module_instances.lease_ttl_seconds` kept as the shortest TTL in scope;
  - step 6: section 6;
  - step 8: the mock module also plays a runtime-control module, for the tests of this plan's step 4, and an enforcement point that authenticates as the agent, for the test of this plan's step 3;
  - step 10: its load test is the base that this plan's harness extends with halt scenarios (step 10), so it is built to take new scenarios;
  - registration: `RegisterInstanceResponse` returns the instance's credential environment, `module_instances` keeps it, the public API's instances show it (an additive change to the OpenAPI document), and an enforcement point whose credential has none is refused (decision 7);
  - acceptance: reconnection within a third of the shortest TTL, rather than 30 seconds.
- **P1-06:** rebuild chunks of at most 100 agents, one job at a time, with every row locked before `Next`.
- **P1-08 itself:** its steps and acceptance criteria were aligned with this note on 2026-10-20.
- **P1-02,** in a fix of its own before P1-08 step 2: `ensure_audit_partitions` creates each new partition as a table and attaches it, and `drop_audit_partition` drops with a short `lock_timeout`, retried at the next run (section 2). Today both take `ACCESS EXCLUSIVE` on the partitioned tables, about once a month.
- **P1-05,** step 7: the credential of a module whose manifest declares the enforcement-point capability carries an environment, checked when the credential is created (decision 7).
- **P1-12,** step 4: the reference setup replicates synchronously to any one of its two standbys (a quorum of one), with preferred data durability, so a failover keeps committed halts. One standby that stops answering never makes a commit wait; if both stop, commits wait until CloudNativePG drops them, a delay that step 4 measures (section 10). Each commit waits for one standby's flush, a round trip that the budget of section 11 allows.
- **P1-15:** its streams carry no blocks. It writes one rule per halt rather than one per halted agent, a selector halt's rule selecting its agents with a set-based selector on `whitetower.io/agent-id`, as the fleet halt's single rule does, and sizes its client's rate limit for bursts: at client-go's default of 5 requests per second, 500 rules would take about 100 seconds, against the 10 of NFR-23. Its layer reports go to `halt_layer_reports` (section 12).
- **P1-10.5 and P1-11:** no environment control; before confirming, they show what the halt stops, from the preview of step 1, and say that it stops these agents in every environment (decision 2). P1-10.5 also shows a runtime-control module lost before it acknowledged a halt, for that halt, as "lost contact: layer not applied", while a layer it acknowledged stays shown as applied, and each instance's environment (decision 7).
- **P1-16** step 7: section 9, and the runs of this plan's step 10 again, with 100 block changes and 500 active blocks (ST-80).
- **P1-09 and the conformance kit:** the clarifications of decision 6; decision 2's rule, that an instance applies every halt wherever it runs and that no field it does not know narrows one, so it decodes JSON discarding unknown fields, as connect-go's codec does (protojson's default refuses them, which would fail S-13); and decision 7: it takes the subject's environment from its registration.
- **Documents:**
  - the domain model (sections 2, 3.3, 3.5, 3.6, 3.9, 4, 5 and 6): versions from `next_governance_version()`, never from the sequence; `halt_acks` replaced; the new columns of `halts` and `module_instances`; `killswitch.drill_max_seconds`;
  - the lifecycle, before P1-04 pull request 4 (decision 1): section 3 (the transitions White Tower makes lock instead of checking a caller's version; T12), the meaning of T12's guard in section 4, and section 7, since drills do not suspend; `agent-lifecycle.yaml` keeps the guard's name;
  - the requirements: KIL-02, KIL-05, KIL-06, KIL-09, section 5.1.1, the permission matrix (decisions 1 to 4) and the glossary's C3, read per agent (section 7), before P1-04 pull request 4 for decision 1;
  - the internals (notifications of governance changes after commit, and the test example);
  - the architecture: its paragraph on versions (section 6), and the halt tracker that runs on every replica in place of the leader-elected lease watchdog (section 3.1, and the high-availability row of section 9); and P1-07's lines on the sequence and the advisory lock;
  - the threat model (T-31 and DC-9: the version counter instead of the advisory lock and the sequence, and renewals only while the replica is current), and RFC-0002, section 6 (blocks take their versions from the version counter);
  - the contracts and RFC-0001 (decisions 2, 6 and 7): the clarifications; the rule that a halt applies wherever the instance runs and that a field an instance does not know never narrows it; the environment in `RegisterInstanceResponse`, with MAN-5 and I-7; and the event schema's selector, which loses `environment`;
  - AGENTS.md (the parts above, in the work queue).
