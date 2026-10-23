# P1-02: Audit log

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | In progress (see [progress notes](#progress-notes)) |
| **Size** | L |
| **Depends on** | P1-01 |
| **Unblocks** | P1-03 and every plan that changes state (through the writer, step 1); P1-11 (verification commands) |
| **Requirements** | AUD-01 to AUD-10, NFR-08 to NFR-10, NFR-19, NFR-20 |
| **Decisions** | ADR-0003, ADR-0006 |

## Goal

The tamper-evident audit log: every core change recorded in the same transaction, events from enforcement points ingested reliably, everything sealed into a Merkle tree with signed checkpoints, searchable, verifiable by third parties and exported continuously to the organization's SIEM.

**Ordering note:** steps 1 and 2 (the writer) must land first, within about a week, because every other plan writes audit events. The rest can proceed in parallel with P1-03 and P1-04.

## Scope

**In:** event model and writer, storage, sealer, checkpoints, ingestion from modules, query API, verification library, export, retention, tamper and throughput tests.

**Out:** the `wtctl` commands (P1-11, built on the library from step 7); the console screens (P1-10.4); the transport of the module API (P1-07 wires `EventService.Publish` to step 5).

## Deliverables

- `internal/audit`: writer, ingestion, sealer, checkpoints, query, export, retention.
- `pkg/auditverify`: a verification library usable offline and by third parties.
- OpenAPI operations for events, checkpoints and keys.
- The tamper test suite and a throughput benchmark.

## Steps

### 1. Event model and writer

- **Event model**, compatible with CloudEvents: `id`, `source`, `type`, `time`, `subject`, `data`, plus White Tower fields:
  - actor (human, agent, module or system, and its ID);
  - action, outcome or decision, and reason;
  - request and trace IDs;
  - before and after values for core changes.
- **Writer:** `audit.Writer.Record(ctx, tx, event)` validates mandatory fields and `data` against the event catalog schemas (`api/events`), and inserts in the caller's transaction.
- **Canonical bytes:** the writer produces the event's canonical JSON (RFC 8785) once and stores those exact bytes. Leaves are hashed over them, and verification recomputes from them. Re-serializing from JSONB would not reproduce the same bytes.
- **Redaction and pseudonymization:** secrets are never written, and humans are identified by pseudonymous principal IDs (NFR-20).

**Done when:** a domain operation whose audit insert fails is rolled back entirely (test).

### 2. Storage

- Monthly partitions, created ahead of time by a job.
- Indexes for the queries of step 6.
- Privileges from P0-02: the runtime role can only INSERT into audit tables, and triggers reject UPDATE and DELETE.
- Since events are never updated, sealing state lives in a separate leaves table (`audit_leaves`: tree index, event ID, leaf hash).
- A **queue of unsealed events** (`audit_unsealed`: event ID and ingestion time, indexed on both). Ingestion fills it in the event's own transaction, and the sealer empties it. The runtime role may SELECT, INSERT and DELETE on it, but not UPDATE. Spike S3 validated this design; the migration does not have the table yet.

**Done when:** tests prove the runtime role cannot modify or delete events, and partitions exist three months ahead.

### 3. Sealer (subplan candidate, together with steps 4 and 7)

A leader-elected job:

1. Takes up to 5,000 events off the queue of unsealed events (`DELETE … RETURNING`), and orders them by ingestion time, then ID. Only committed events are in the queue, so an event whose transaction commits late is sealed in a later batch, never skipped. No row locks are needed: only one sealer runs, and if a second one ever did, the primary key on the leaf index would reject its batch.
2. Assigns tree indexes itself. An event committed late just gets a later index, so there are no gaps.
3. Computes RFC 6962 leaf hashes over the canonical bytes, and stores the intermediate hashes with `golang.org/x/mod/sumdb/tlog` (`StoredHashesForRecordHash`). It keeps the right edge of the tree in memory, at most one hash per level, which is all an append reads.
4. Commits one batch per transaction, in rounds every 200 ms that drain the queue. The sealing delay is then about one round ([spike S3](../../spikes/S3-audit-throughput.md)).

It must be crash-safe: after a restart, or after any failed batch, it reloads the tree size and the right edge from the database and resumes from the last committed index, without duplicates or gaps. Sealing lag, and the time to claim a batch from the queue, are exported as metrics.

**Done when:** killing the sealer in the middle of a batch and restarting it leaves a consistent tree (test), and sealing lag stays within NFR-09 under load.

### 4. Checkpoints

- A job signs a checkpoint at least every 60 seconds when there are new leaves, or every N leaves: a signed note in the C2SP `tlog-checkpoint` format (log origin such as `whitetower.example.org/audit`, tree size, root hash), with the Ed25519 checkpoint key.
- Each checkpoint is stored and also emitted as a `whitetower.audit.checkpoint.v1` event, which the next batch seals.
- Public keys are published at `/api/v1/audit/keys`.
- Rotation uses key IDs; old checkpoints stay verifiable with the old public key.

**Done when:** checkpoints verify with standard signed-note tooling, and rotation keeps old checkpoints verifiable.

### 5. Ingestion from modules (subplan candidate, together with step 8)

The logic behind `EventService.Publish`:

- **Authorization:** an instance may only publish the event types declared in its manifest, for the agents it serves.
- **Validation:** the envelope, and `data` against its schema.
- **De-duplication:** on source and ID; duplicates are reported as accepted.
- **Gap detection:** per source, using `wtseq`; a gap produces a `whitetower.audit.gap_detected.v1` event. Each batch updates its sources' sequence rows in the order of the source, so batches that share sources cannot deadlock (spike S3 hit this deadlock at 10,000 events per second).
- **Atomicity:** each batch is inserted in one transaction, with a result per event. The events and their entries in the queue of unsealed events go in one statement.
- **Backpressure:** when sealing lag or database latency passes a threshold, the core answers "resource exhausted" with a retry hint, and enforcement points keep buffering (NFR-08). Rate limits apply per instance.

**Done when:** duplicate, out-of-order and gapped batches produce the expected results (tests), and backpressure never loses an acknowledged event.

### 6. Query API

- `GET /api/v1/audit/events`: filters on time range, agent, actor, type, decision or outcome, and source; cursor pagination; a maximum page size.
- `GET /api/v1/audit/events/{id}`: the event with its inclusion proof against the latest checkpoint.
- `GET /api/v1/audit/checkpoints` and `GET /api/v1/audit/keys`.

Permissions follow the matrix: auditors, steering, advisory and operators see everything; owners see their own agents' events. Reads are audited (AUD-09).

**Done when:** each filter is covered by tests, and permission tests pass for every role.

### 7. Verification library

`pkg/auditverify` provides:

- recomputing leaves and the tree from events, reporting the first discrepancy;
- verifying checkpoint signatures;
- checking an inclusion proof;
- checking a consistency proof between an external checkpoint and the current tree;
- reading the log in chunks of about 10,000 leaves, which PostgreSQL joins to their events by index. One query over the whole log makes it hash-join and sort everything on disk (spike S3).

It works online (through the API) and offline (against an export). `wtctl audit verify`, `prove` and `consistency` (P1-11) are thin wrappers around it.

A consistency check that runs on a schedule, against the latest checkpoint the SIEM holds, catches a log rolled back by a database administrator, and alerts when it fails ([threat model](../../security/threat-model.md), DC-8). P1-12 documents how to run it.

**Done when:** the tamper suite of step 10 is detected by the library.

### 8. Export

- A job with a persisted cursor per sink ships sealed events in index order: at-least-once, never skipping.
- **Sinks:** OTLP over HTTP as log records (body is the event JSON; key fields as attributes), and JSON Lines to a file with rotation or to stdout. Syslog (RFC 5424 over TLS) is a Should.
- Checkpoints are exported like any other event, so the SIEM holds them outside White Tower.
- Optional pseudonymization of human identifiers on export (NFR-20).
- Health metrics and alerts per sink.

**Done when:** after a core restart, the collector has every event exactly once or more, and none is missing (test).

### 9. Retention

- Retention is configured per event class. Six months is the default minimum (NFR-10); going lower requires an explicit override and logs a warning.
- A job drops whole partitions older than the retention period and keeps the tree hashes and checkpoints, so what remains still verifies. The drop itself is an audited event.
- Storage, measured in spike S3 with events of about 700 bytes: about 2.2 KB per retained event, of which the leaf and its tree hashes (about 370 bytes) stay after the drop. This step decides whether that tree data is kept whole or compacted to the few hashes that stand for a dropped range, which costs the consistency proofs of the checkpoints inside it.
- Optionally, partitions are archived to S3 Object Lock-compatible storage (MinIO in air-gapped sites) before dropping (Could).

**Done when:** after dropping a partition, verification reports the pruned range and still validates everything else.

### 10. Tests and benchmarks

- **Tamper suite:** using a superuser, modify, delete, insert and reorder events. `auditverify` must detect each case, and after a full rewrite of history, the consistency proof against a previously exported checkpoint must fail.
- **Crash tests** for the sealer and the exporter.
- **Throughput benchmark** against NFR-07 and NFR-09, reusing the P0-05 S3 setup.
- **Fuzzing** of the ingestion parser.
- The catalog's examples validate.

**Done when:** all of the above run in CI (fuzzing: a short run on each pull request, a long run nightly).

## Acceptance criteria

- No core state change can commit without its audit event (forced-failure test).
- 200 events per second sustained with p95 sealing delay of 5 seconds or less, and checkpoints at least every 60 seconds. 2,000 events per second for 60 seconds without loss, on the reference hardware from P0-05 (NFR-07, NFR-09).
- Every manipulation in the tamper suite is detected; a rewrite of history is detected with an exported checkpoint.
- Exports reach an OpenTelemetry collector and a JSON Lines file with no gaps across restarts.
- After a retention drop, the remaining log still verifies.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-02-audit-log) pass: ST-06 to ST-12.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Sealer throughput | Measured in spike S3: at 2,000 events per second the sealer was busy 18% of the time, and it kept up at 10,000 per second. Batching as in step 3 |
| Audit storage grows with the average event rate: about 2.2 KB per retained event (spike S3) | Sizing guidance in P1-12; retention per event class; compaction of dropped months' tree data (step 9) |
| Audit volume from token issuance and decisions grows faster than expected | Per-class retention; measure in the pilot; aggregation of low-value events is a Phase 2 option |
| The checkpoint event is sealed in the next batch, so the tree always contains the checkpoints up to the previous one | Documented in the specification; verification handles it |

## Notes for implementers

- `golang.org/x/mod/sumdb/tlog` and `golang.org/x/mod/sumdb/note` provide tree hashing, proofs and signed notes; `transparency-dev/formats` has checkpoint parsing if needed.
- Never compute hashes over JSONB round-trips: keep the canonical bytes.
- Keep the audit tables out of the ORM-style convenience layer: only the writer and the sealer touch them.
- The spike code in [`hack/spikes/s3`](../../../hack/spikes/s3/README.md) has working versions of the ingestion, sealing and verification queries.

## Progress notes

The plan lands in seven pull requests. The first holds the writer, which every other plan needs.

| Pull request | Steps | Status |
| --- | --- | --- |
| 1. Event model, writer and storage | 1, 2, ST-09 | Done |
| 2. Sealer and checkpoints | 3, 4 | Done |
| 3. Verification library and tamper suite | 7, part of 10, ST-06 to ST-08 | Done |
| 4. Ingestion from modules | 5, ST-10, ST-11 | Done |
| 5. Query API | 6, the keys of step 4, ST-12 | Done |
| 6. Export | 8 | Done |
| 7. Retention and throughput | 9, the rest of 10 | Done |

### 2026-10-09: event model, writer and storage

- `api/events` embeds the event catalog in the binary. `audit.LoadCatalog` compiles it: the envelope's schema and, for each type, the schema of its data, who emits it and whether it is about an agent.
- `audit.Writer.Record(ctx, tx, event)` records an event of the core in the caller's transaction, and queues it for the sealer in the same statement:
  - The envelope: source `/core`, a UUIDv7, the time from the clock in UTC to the millisecond, the trace context and, as `wtrequestid`, the ID of the request, which ties the event to the access log. The contract and the envelope's schema now define `wtrequestid`.
  - The event is stored as its canonical JSON (RFC 8785, with `gowebpki/jcs`), and checked from those bytes against the envelope's schema and its type's. The core cannot record a type that only modules emit.
  - Every data schema refuses unknown members, so an email address or a name cannot slip into an event (NFR-20).
  - The event is written when `Record` is called, not in a `BeforeCommit` hook as P1-01 foresaw: a failure then surfaces where the change records its event, and still rolls it back.
- The columns of `audit_events` (actor, action, outcome, reason) are read from the event by a rule per type, never given apart from it, so they always say what the canonical bytes say. `LoadCatalog` refuses a type without a rule, and a rule without a type; a golden file holds what is indexed of every example of the catalog.
- Migration 2:
  - `audit_unsealed`, the queue of events to seal, which the runtime role may read, add to and take from, but not change;
  - the event catalog came after the schema, and the indexed actors and outcomes now include service accounts and cancelled actions.
- `audit-partitions`, the first background job, keeps the partitions of the audit tables three months ahead, checking every hour.
- Tests:
  - an event is stored with the columns of its canonical bytes, the request and trace IDs, and its entry in the queue;
  - ST-09: a change whose event is invalid, or which the database refuses, is rolled back entirely;
  - the runtime role cannot update, delete or truncate events;
  - a dropped partition is created again by the job, three months ahead;
  - the catalog's examples are valid and indexed, and invalid events are refused by name.

### 2026-10-09: sealer and checkpoints

- `internal/platform/keys`: the shared interface of the signing keys that plan P1-05 foresees, with a file backend. Its first key is Ed25519, in PKCS #8 PEM, as `openssl genpkey -algorithm ed25519` writes it; its ID is its RFC 7638 thumbprint, tested against RFC 8037's example. P1-05 adds ES256 and rotation with overlap.
- `audit.Sealer` is the background job `audit-sealer`, on one replica at a time:
  - Each round, every 200 ms, drains the queue: batches of at most 5,000 events, each in one transaction, which takes them off the queue (`DELETE ... RETURNING`, no row locks), orders them by ingestion time and audit ID, and stores their RFC 6962 leaves and the tree's new hashes (`golang.org/x/mod/sumdb/tlog`), with `COPY`.
  - The sealer keeps the tree's right edge in memory, which is all an append reads. A failed round makes the next one load the tree again from the database, so a crash in the middle of a batch leaves no gap and no duplicate. Should two sealers ever run at once, the primary key of the leaves refuses the batch of the one that is behind.
  - A failed round is logged once, and the end of the failures once; retries back off up to 5 seconds.
  - Metrics: `whitetower_audit_sealing_delay_seconds` (NFR-09), `whitetower_audit_claim_seconds`, `whitetower_audit_sealed_total`, `whitetower_audit_tree_size`, `whitetower_audit_last_checkpoint_timestamp_seconds` and `whitetower_audit_sealing_failures_total`.
- Checkpoints: once the interval has passed (`audit.checkpoint_interval`, a minute at most, AUD-03), or after 10,000 new leaves, the sealer signs a C2SP tlog-checkpoint over the tree, under the log's origin (`audit.origin`) as the key's name. It stores the checkpoint and records its `whitetower.audit.checkpoint.v1` event in one transaction, and the next round seals that event. An idle log signs no more: a checkpoint needs a leaf besides the previous checkpoint's own event.
- The checkpoint key comes from `audit.checkpoint_key_file`, which `serve` requires with `audit.origin`. The sealer registers its public half in `signing_keys` as the active checkpoint key, and retires the others, whose public halves stay so that their checkpoints still verify. Publishing the keys at `/api/v1/audit/keys` comes with the other audit operations, in PR 5.
- Compose and `task run` use a development key, public like the development passwords. ST-03 covers the new secret file: a canary key, which the server signs with, never leaves it.
- The catalog's checkpoint example is now a real checkpoint, signed as the sealer signs one. The first pull request's notes said its note was mis-encoded: it was not; the file had been read with the wrong encoding.
- Tests, with the tree recomputed independently from the events' canonical bytes:
  - every event is sealed, in order, and the tree's hashes are those that `tlog` computes;
  - a batch that fails in its middle leaves a consistent tree, and the next round goes on from it (the criterion of step 3);
  - two sealers at once do not fork the tree;
  - checkpoints verify with `golang.org/x/mod/sumdb/note`, and say the tree's size and root (the criterion of step 4);
  - after a rotation, the old key's checkpoints still verify with its public half (the criterion of step 4);
  - checkpoints come at their interval, and an idle log signs no more;
  - `Run` recovers from failed rounds.

### 2026-10-13: the sealer's clock

The sealer stored each checkpoint with the database's clock and, once it loaded the tree again, compared that time with its own clock to decide when the next checkpoint was due. Two tests passed only while the database's clock was behind their fake clock, and failed in CI from 2026-10-13. A checkpoint now takes its time from the sealer's clock, which also decides when the next one is due.

### 2026-10-14: verification library and tamper suite

- `pkg/auditverify` verifies the log from the outside. It imports nothing of White Tower (`depguard`, rule `verifier`): it implements the tree and the checkpoints from their standards, so that a fault in the core is not repeated in what checks it.
  - `Verify` reads the whole log through a `Source`, 10,000 leaves at a time. It recomputes every leaf from its event and the tree from the leaves, keeping only the tree's right edge, and checks the stored leaves, tree hashes and checkpoints against them.
  - It reports problems in the order of the log, so the first one is where the log first differs from what was signed: a leaf or an event missing, an event altered, a stored tree hash altered, a checkpoint invalid, altered, beyond the log or at odds with the events.
  - The caller gives the keys that checkpoints must be signed with, as Ed25519 keys or as the JSON Web Keys the core publishes. A log rewritten and signed again with another key verifies with that key, so the keys must come from somewhere the database's administrators cannot change.
  - `Extends` checks that the log still holds the tree of a checkpoint kept outside it, such as the SIEM's (DC-8): `ErrShorter` for a rollback, `ErrForked` for a rewrite. It reads a few stored hashes, so it can run often; `Verify` checks those hashes against the events.
  - `OpenCheckpoint`, `CheckInclusion` and `CheckConsistency` check what the query API (PR 5) and exports (PR 6) will serve. Opening checkpoints, which come from outside, is fuzzed.
  - A missing event reports a problem but does not stop the tree: the leaf's stored hash keeps it going. Retention (PR 7) drops events, and what remains must still verify.
- `audit.Log` reads the database for the library. A domain package does not import `pkg/`, so it satisfies `auditverify.Source` without naming it. Leaves are read with their events through the events' primary key, as spike S3 found fastest; a stored value that is not a hash counts as missing.
- `test/tamper` is the tamper suite. As a superuser, with the append-only triggers off:
  - ST-06: an event modified, deleted, inserted or reordered, a leaf deleted, an event rebuilt into the tree, a checkpoint's stored root modified: each is found where it starts.
  - ST-07: the latest events and checkpoints removed. The log still verifies on its own, and the check against the checkpoint exported earlier fails, with `ErrShorter`, then with `ErrForked` once the log has grown back past it.
  - ST-08: the tree rebuilt over an altered event, and its checkpoints signed with another key. The log verifies with the key the database now holds, not with the genuine one, and the check against the exported checkpoint fails.
- Still to come: the library's sources for the API (PR 5) and for exports (PR 6), and the commands `wtctl audit verify`, `prove` and `consistency` (P1-11).

### 2026-10-14: ingestion from modules

- `audit.Ingester`: ingests batches of up to 500 CloudEvents from module instances (`EventService.Publish` logic), taking the instance identity, its served agents and its declared types as input.
- Validation: checks each event against the CloudEvents envelope and its data schema (`jsonschema`). Refuses events larger than 64 KiB or malformed payloads.
- Scope and authorization: verifies that event types are declared in the instance's manifest and permitted for module emitters, that agent sources match the agents the instance serves, and that module sources match its own instance ID. Core-only types and unauthorized sources are rejected.
- At-least-once de-duplication: inserts into `audit_event_ids` on `(source, event_id, ingest_month)`. Previously seen events return `StatusDuplicate`.
- Sequence tracking and gap detection: tracks per-source sequences in `audit_source_sequences`. A gap in `wtseq` records a `whitetower.audit.gap_detected.v1` event via `Writer.Record` in the batch transaction.
- Deadlock prevention: locks and updates source sequences in strictly sorted source order (`slices.Sort(uniqueSources)`), preventing cyclic waits between concurrent batches sharing sources (spike S3).
- Atomicity: accepted events and their queue entries in `audit_unsealed` are inserted in a single atomic CTE statement.
- Rate limiting and backpressure: per-instance token bucket rate limiting via `internal/platform/ratelimit`. Backpressure evaluates sealing lag via `OldestUnsealedTime`; if lag exceeds the threshold (NFR-09), `ErrResourceExhausted` is returned with a retry hint, ensuring no acknowledged events are lost (NFR-08).
- New core event type `whitetower.audit.gap_detected.v1`: schema in `api/events/schemas/`, example in `api/events/examples/`, registered in `catalog.json` and `rules` in `facts.go`, indexed in `facts.json`.
- Tests: ST-10 covers authorization refusals, per-instance rate limits, backpressure under lag, duplicate handling, out-of-order delivery, and concurrent deadlock avoidance. ST-11 fuzzes the CloudEvents parser and ingestion path.

### 2026-10-14: export

- `audit.Exporter`: background job (`audit-exporter`) that queries `audit_leaves` and exports sealed events strictly in Merkle tree index order (`leaf_index` 0, 1, 2, ...).
- Cursors: persistent per-sink progress tracking in PostgreSQL (`whitetower.audit_export_cursors`), updated atomically per batch. At-least-once delivery: on core restart or sink failure, export resumes from the last committed cursor without skipping any events.
- Sinks:
  - `JSONLSink`: streams events as line-delimited canonical JSON either to stdout or to a file with size-based rotation and backup retention.
  - `OTLPSink`: sends OpenTelemetry log records over HTTP (`/v1/logs`) using protobuf (`ExportLogsServiceRequest`), mapping canonical JSON to the log body, event timestamp to nanoseconds, and attributes (`specversion`, `id`, `source`, `type`, `subject`, `wtrequestid`, `trace_id`). Signed checkpoints are exported as ordinary events (`whitetower.audit.checkpoint.v1`).
- Pseudonymization: optional deterministic pseudonymization of human principal identifiers on export (NFR-20) via RFC 4122 UUID v5 derived with an HMAC-SHA256 namespace key, leaving the internal database log unaltered.
- Health metrics per sink: `whitetower_audit_exported_total`, `whitetower_audit_export_cursor_leaf_index`, `whitetower_audit_export_lag`, `whitetower_audit_export_failures_total`, and `whitetower_audit_export_duration_seconds`.
- Tests prove strict index ordering, cursor persistence, zero events skipped across core restarts or sink failures, OTLP protobuf formatting, JSONL file rotation, and export pseudonymization without affecting internal logs.

### 2026-10-14: retention and throughput

- Storage of pruned tree data (decision of step 9): `audit_leaves` and `audit_tree_hashes` stay whole in PostgreSQL, while older monthly partition tables of `audit_events_YYYY_MM` and `audit_event_ids_YYYY_MM` are dropped. This reclaims >83% of storage, maintains all historical checkpoints and consistency proofs intact, and preserves the append-only invariant on leaf and tree tables without row deletions.
- Configuration (`internal/platform/config`): `audit.retention.days` (minimum 180 days by default, NFR-10). Setting a lower retention threshold requires `audit.retention.allow_short: true` and logs an operator warning.
- Partition management and security:
  - Migration 3 creates table `whitetower.audit_pruned_ranges` (`(from_leaf_index, to_leaf_index, partition_name, dropped_at)`) with append-only and no-truncate triggers (`whitetower.reject_change()`).
  - PostgreSQL function `whitetower.drop_audit_partition(suffix)` (security definer) drops monthly partitions of `audit_events` and `audit_event_ids` for the runtime role without granting broad DDL privileges.
  - PostgreSQL function `whitetower.list_audit_partitions()` enumerates existing partition tables.
- Retention job (`audit.DropExpiredPartitions` and background job `audit-retention`):
  - Identifies partitions older than the retention threshold, queries the leaf index bounds (`PartitionLeafBounds`), records an audited event `whitetower.audit.partition_dropped.v1`, records the pruned index range in `audit_pruned_ranges`, and drops the partition tables.
  - Metrics: `whitetower_audit_partitions_dropped_total` and `whitetower_audit_pruned_leaves_total`.
- Core event type `whitetower.audit.partition_dropped.v1`: schema in `api/events/schemas/`, example in `api/events/examples/`, registered in `catalog.json` and `rules` in `facts.go`, indexed in `facts.json`.
- Verification library (`pkg/auditverify`):
  - `PrunedSource` interface: optional capability on `Source` providing `Pruned(ctx, visit func(from, to int64) error) error`.
  - `Report` records `PrunedRanges` and `PrunedLeaves`.
  - Missing events within lawfully pruned ranges are recognized without reporting verification failures (`EventMissing`), and checkpoints continue to verify against the Merkle tree reconstructed from leaf hashes.
  - `audit.Log` implements `PrunedSource` via structural typing without importing `pkg/auditverify`.
- Tests and benchmarks:
  - `retention_test.go`: proves partition dropping, pruned range recording, leaf/hash preservation, and active partition retention.
  - `test/tamper`: `TestRetentionDroppedPartitionPassesVerificationWhileUnlawfulDeletionFails` proves that lawfully pruned partitions pass verification with intact checkpoints, while any deletion outside pruned ranges is detected and fails verification with `EventMissing`.
  - `throughput_test.go`: `TestThroughputSustainedAndBurst` verifies sustained 200 eps (NFR-07) and peak burst of 2,000 eps (NFR-09) under concurrent publishers, ensuring queue drain, zero event loss, and checkpoint generation. `BenchmarkSealerRound` benchmarks batch sealing latency.

### 2026-10-16: query API (step 6, the keys of step 4, ST-12)

- Public REST API endpoints implemented in `internal/api/rest/audit.go` and defined in OpenAPI (`api/openapi/openapi.yaml`):
  - `GET /api/v1/audit/events`: filtered by time range (`from`, `to`), `agentId`, `actorId`, `actorType`, event `type`, `action`, `outcome`, and `source`; keyset cursor-based pagination with opaque URL-safe tokens; maximum page size 100.
  - `GET /api/v1/audit/events/{id}`: single event retrieval with cryptographic Merkle inclusion proof (`leafIndex`, `treeSize`, `rootHash`, `hashes`, `checkpoint`) computed via `golang.org/x/mod/sumdb/tlog.ProveRecord` and verified against the latest signed checkpoint. Events pending sealing return null proofs.
  - `GET /api/v1/audit/checkpoints`: list of stored checkpoints (tree size, base64 root hash, key ID, signed C2SP note, creation time).
  - `GET /api/v1/audit/keys`: public halves of checkpoint signing keys published as JWKs.
- Domain queries and logic in `internal/audit`:
  - `QueryEvents`: parameterized queries across partitioned `whitetower.audit_events` with keyset ordering `(event_time DESC, id DESC)`.
  - `GetEvent`: joins `audit_events` and `audit_leaves`, retrieves latest checkpoint, reads tree hashes via `txHashReader`, and computes `tlog.RecordProof`.
  - `IsAgentOwner`: verifies active agent ownership in `whitetower.agent_owners`.
- Role-based access control and scoping according to the governance matrix:
  - Steering, advisory, operator, and auditor roles have full access across all events and checkpoints (`ScopeAll`).
  - Owner role has scoped access (`ScopeOwn`): queries without `agentId` automatically scope to agents owned by the calling principal; querying or retrieving unowned agents or events without an agent returns 403 Forbidden.
  - User and admin roles are denied by default (403 Forbidden). Unauthenticated requests return 401 Unauthenticated.
- Auditing of audit log reads (AUD-09, ST-12):
  - Emits new core audit event type `whitetower.audit.read.v1` containing actor ID, type, operation, query parameters, and results count.
  - Schema in `api/events/schemas/whitetower.audit.read.v1.json`, example in `api/events/examples/whitetower.audit.read.v1.json`, registered in `catalog.json` and `rules` in `internal/audit/facts.go`.
- Tests:
  - `TestAuditQueryEndpoints`: covers filtering, keyset pagination, role scoping (steering, advisory, operator, auditor, owner, user, admin, anonymous), 404 handling, unsealed event handling, and cryptographic inclusion proof verification using `pkg/auditverify.CheckInclusion` and `pkg/auditverify.OpenCheckpoint`.
  - Security test ST-12: verifies that query and get operations record `whitetower.audit.read.v1` events in the database with accurate actor and query details.

### 2026-10-20: follow-up from the halt-path design

The design of the halt path, accepted on 2026-10-20 ([P1-08's progress notes](P1-08-kill-switch.md#progress-notes), sections 2 and 14), changes the two functions that manage the audit partitions, in a fix of its own before P1-08 step 2:

- `ensure_audit_partitions` creates each new partition as a table, then attaches it, which takes only SHARE UPDATE EXCLUSIVE on the partitioned table;
- `drop_audit_partition` drops with a `lock_timeout` of 100 ms, and `audit-retention` retries a drop that times out at its next run.

Today both take ACCESS EXCLUSIVE on the partitioned tables, `audit_events` and `audit_event_ids`, about once a month: `ensure_audit_partitions` creates partitions with `CREATE TABLE ... PARTITION OF` (migration 1), and `drop_audit_partition` drops them with `DROP TABLE` (migration 3). A request for that lock waits until every transaction that reads the tables ends, and every later request for a lock on them, an insert's included, queues behind it. So an audit search or a backup that holds the tables would make every writer of an audit event wait. Every writer of the governance state writes its audit event while it holds the version counter, so every writer queued on the counter, halts included, would wait with it.

### 2026-10-21: settings registered by P1-17

On 2026-10-21 the maintainer decided that the settings get a plan of their own, [P1-17](P1-17-settings.md), with which each plan registers the keys it owns. P1-17 registers none of this plan's keys:

- The first migration seeds `audit.retention_months` (6), but nothing reads it: the retention job takes its period from `audit.retention.days` in the file configuration, at least 180 days unless `audit.retention.allow_short` is set (2026-10-14).
- Registered, the setting would let the platform administrator change a value that changes nothing, so P1-17 lists it read-only.
- On 2026-10-22 the maintainer decided to retire it: P1-17 pull request 1 deletes the row with a migration, and the retention period stays in the file configuration, so shortening it still needs access to the server's configuration (P1-17, step 6).


### 2026-10-23: follow-up from the review of RFC-0001

The review of RFC-0001 changed what ingestion does with module events (contracts, sections 4.3, 8.2 and 8.4; [P0-03's progress notes](../phase-0/P0-03-module-contracts.md#progress-notes) of 2026-10-22 and 2026-10-23). A fix of its own lands it before P1-07 serves `Publish` ([AGENTS.md](../../../AGENTS.md), work queue):

- **Sources.** A source names a module by its slug, and an evidence buffer by a random stream ID, never by an instance ID. The caller carries its agent ID or its module's slug: `/agents/<agent-id>/ep/` is accepted only from that agent's own enforcement points, and `/modules/<slug>/` only from that module's instances. The rule that a module's source ends in the caller's instance ID goes, and the audit facts take the checked slug as the actor. `cloudevent.schema.json` narrows the stream ID to 16 to 64 lowercase hexadecimal characters, every example's source takes such an ID, with the cluster's name kept in the data, and the golden file of indexed examples is regenerated.
- **Repeats.** A source's `wtseq` that repeats, or goes back, under a new event ID is a finding: a new core event type, or an extension of `whitetower.audit.gap_detected.v1`, with every step of AGENTS.md's checklist for audit events.
- **De-duplication first.** It runs before the check of scope, so a retry of an accepted event stays `DUPLICATE`, even once its agent has left the instance's scope. Evidence about an agent recently unbound from the module is decided with the delivery period that P1-05 step 5 decides, if there is one.
- **De-duplication for 28 days at least.** The key keeps the month, since the table is partitioned by it, and the check also looks in the previous month's partition, with a test across a month boundary on the fake clock.
