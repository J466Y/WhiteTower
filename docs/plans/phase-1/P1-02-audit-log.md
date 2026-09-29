# P1-02: Audit log

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
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
