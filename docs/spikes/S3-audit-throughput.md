# Spike S3: audit log throughput

| | |
| --- | --- |
| **Plan** | [P0-05](../plans/phase-0/P0-05-spikes-and-nfr-targets.md), spike S3 |
| **Status** | Done |
| **Date** | 2026-09-29 |
| **Tested** | One laptop (Windows 11, Intel Core i5-1235U). PostgreSQL 17.11 in Docker Desktop's WSL 2 virtual machine (12 logical CPUs, 7.6 GiB), in its default configuration: `fsync` and synchronous commit on, `shared_buffers` 128 MB, `max_wal_size` 1 GB. Go 1.27.1 and `golang.org/x/mod` 0.41.0 (`sumdb/tlog`, `sumdb/note`). The core's real migration and runtime role |
| **Code** | [`hack/spikes/s3/`](../../hack/spikes/s3/README.md); raw numbers in [`results-1m.json`](../../hack/spikes/s3/results-1m.json) |

## The question

Can PostgreSQL with Merkle tree sealing sustain the audit load of NFR-07 (200 events per second sustained, 2,000 per second for 60 s) within the limits of NFR-09 (sealed within 5 s, a checkpoint at least every 60 s)? And the questions P0-05 adds:

- How long does verifying a large log take?
- Does the log still verify after retention drops a month?
- What do proofs cost?
- Is the Merkle tree worth it over a plain hash chain?

## Summary

**Yes, with a wide margin.**

- **At both NFR-07 rates, every event was sealed**, none was lost, and the p99 sealing delay was 201 ms and 341 ms.
- **The delay is the sealer's 200 ms round, not its work:** the sealer was busy 2.4% of the time at 200 events per second, and 17.9% at 2,000.
- **At 10,000 events per second**, five times the burst, it still kept up. Its queue emptied 0.2 s after the load stopped, and every event was sealed within 3.2 s.
- **Verification:** one million events verify in 6.6 s, about a minute for ten million. Proofs take about a millisecond.

**The Merkle tree stays (ADR-0006).** It computes as fast as a hash chain and stores two hashes per event. It proves any event with 20 hashes; a chain needs up to a million.

| Target | Result | Verdict |
| --- | --- | --- |
| NFR-07: 200 events/s sustained, 2,000/s for 60 s | 36,000 and 120,000 events ingested and sealed, none lost. Ingestion batches: p99 19 and 38 ms | Confirmed; kept up at 10,000/s |
| NFR-09: sealed within 5 s of ingestion | p99 201 ms at 200/s and 341 ms at 2,000/s; worst case 1.47 s, while a commit waited for the disk | Confirmed |
| NFR-09: a checkpoint at least every 60 s | Signing and storing a checkpoint takes 2 ms (p50), 8.6 ms at most | Confirmed; could be far more frequent |
| NFR-10: retention drops whole months, and the log still verifies | Dropping a month's partitions took 0.18 s. Afterwards the log verified against the same signed checkpoint, the dropped events counting by their stored leaf hashes, and every proof still checked | Confirmed |
| P0-05: time to verify ten million events | One million in 6.6 s, at the same rate as smaller logs; reading dominates | About 66 s by extrapolation |

**What the design needs** (the details are under [Findings](#findings)):

- **a queue of unsealed events**, which ingestion fills in each event's own transaction and the sealer empties;
- **per-source sequence rows updated in a fixed order**, or concurrent batches deadlock;
- **verification in chunks**, not one query over the whole log.

**Storage, not throughput, is what sizes a deployment:** about 2.2 KB per event while it is retained.

## Method

The program in [`hack/spikes/s3`](../../hack/spikes/s3/README.md) recreates the `whitetower` schema from the core's migration, adds a queue table, and works through the runtime role. It does the following, in order:

1. **Ingests** as plan P1-02 describes. Each batch is one transaction that:
   - de-duplicates on source and event ID;
   - stores the events with their canonical JSON (RFC 8785), and queues them for sealing in the same statement;
   - updates the per-source sequences used for gap detection.

   20 publishers send a batch every 250 ms each. Each publisher stands for a module instance with 50 agents of its own. The events are decisions with their context: 709 bytes of canonical JSON on average.
2. **Seals** with one sealer, in a round every 200 ms. Each transaction:
   - takes up to 5,000 events off the queue and orders them by ingestion time;
   - computes their RFC 6962 leaf hashes and the tree's stored hashes with `golang.org/x/mod/sumdb/tlog`;
   - writes the leaves and tree hashes.

   Rounds repeat until the queue is empty. The sealer keeps only the tree's right edge in memory: at most one hash per level, which is all an append reads.
3. **Signs checkpoints** every 60 s while a rate phase runs, and one after each load: C2SP signed notes with the tree size and root hash, signed with Ed25519 and stored in `audit_checkpoints`.
4. **Runs three rate phases:** 200 events per second for 3 minutes, 2,000 per second for 60 s, and 10,000 per second for 30 s to find the headroom. The sealing delay runs from the event's insertion to its sealing, both on the database clock.
5. **Grows the log** to one million events with a bulk load.
6. **Proves** the inclusion of 200 random events, and the consistency of every earlier checkpoint with the latest, and checks each proof as a client would.
7. **Verifies the whole log** as `wtctl audit verify` would. It checks the checkpoint's signature, recomputes every leaf from its event, rebuilds the tree, and compares the root with the checkpoint. It reads 10,000 leaves per query.
8. **Drops** a past month's partitions (10,000 events), as retention does, then verifies and proves again.
9. **Compares** the tree with a plain hash chain over the same leaves.

The program ran in a container sharing the database container's network namespace. An earlier run read from Windows through Docker Desktop's port forwarding, and with one query over the whole log, which made verification six times slower (finding 5).

## Results

**Rate phases.** Every published event was sealed. The sealing delay and the ingestion batch latency are in milliseconds:

| Phase | Events | Ingestion batch p50 / p99 / max | Sealing delay p50 / p95 / p99 / max | Largest queue | Queue empty after the end |
| --- | --- | --- | --- | --- | --- |
| 200/s for 3 minutes | 36,000 | 2.2 / 19 / 198 | 112 / 200 / 201 / 356 | 34 | 0.1 s |
| 2,000/s for 60 s | 120,000 | 3.8 / 38 / 1,443 | 127 / 230 / 341 / 1,470 | 1,200 | 0.1 s |
| 10,000/s for 30 s | 300,000 | 18 / 735 / 2,778 | 163 / 1,057 / 2,988 / 3,157 | 6,375 | 0.2 s |

Publishers held the target rate in every phase. In the second and third phases, 85 and 548 batches started late, because the publisher's previous batch had taken longer than 250 ms; the publishers caught up.

**The sealer's work:**

| Phase | Transactions | Events per transaction, mean / max | Transaction p50 / p99 / max, ms | Busy | Sealed per second of work | Time claiming from the queue | Time committing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 200/s | 900 | 40 / 70 | 3.7 / 21 / 96 | 2.4% | 8,177 | 14% (0.7 ms a claim) | 40% |
| 2,000/s | 295 | 407 / 1,575 | 19 / 237 / 1,306 | 17.9% | 11,146 | 52% (19 ms a claim) | 24% |
| 10,000/s | 128 | 2,344 / 5,000 | 57 / 673 / 1,896 | 48.6% | 20,427 | 14% (16 ms a claim) | 30% |

The slowest sealing transactions spent almost all their time committing: 1.3 s for 100 events at 2,000/s, and 1.65 s for 2,750 at 10,000/s. Ingestion's slowest batches took as long: 1.4 s and 2.8 s. Sealing never read a tree hash from the database; the 4,700 hashes read in the whole run all came from proofs.

**Checkpoints:** 5 signed and stored, taking 2.0 ms at p50 and 8.6 ms at most.

**Proofs** against the checkpoint of the one-million-event tree, in milliseconds, including reading the hashes from the database:

| Proof | n | p50 | p95 | p99 | max | Hashes |
| --- | --- | --- | --- | --- | --- | --- |
| Inclusion of a random event | 200 | 0.33 | 1.2 | 1.8 | 6.7 | 19 to 20 |
| Consistency of an earlier checkpoint | 4 | 0.92 | 1.3 | 1.3 | 1.3 | 17 |

**Verification of one million events:**

- 6.6 s in all, or 151,000 events per second. The root matched the signed checkpoint, and no leaf differed from its event.
- Reading the 740 MB of events and leaf hashes took 5.8 s (128 MB/s); hashing took 0.8 s.
- The 100 chunks of 10,000 leaves took 56 ms at p50 and 182 ms at most.
- Smaller logs verified at the same rate: 156,000 and 174,000 events per second with 125,000 and 213,000 events.

**Retention.** Dropping the past month's two partitions took 0.18 s. The log then verified against the same checkpoint: 990,000 leaves from their events and 10,000 from their stored hashes. All 54 new proofs checked.

**Storage per event,** indexes included, measured at one million events:

| Table | Bytes per event | Kept after retention |
| --- | --- | --- |
| `audit_events`: the event row with its canonical JSON (1,171), and the primary key and four indexes (358) | 1,527 | no |
| `audit_event_ids` (de-duplication) | 323 | no |
| `audit_leaves` | 172 | yes |
| `audit_tree_hashes` | 198 | yes |
| **Total** | **2,220** | **370** |

**Hash chain against Merkle tree,** over the same million leaves:

| | Hash chain | Merkle tree |
| --- | --- | --- |
| Computing | 171 ms | 177 ms |
| Proving one event | up to 999,999 hashes | 20 hashes |
| Proving that a later state extends an earlier one | the whole chain in between | 17 hashes |
| Storage besides the leaves | none | two hashes per leaf (198 bytes) |

## Findings

1. **Sealing is cheap; its delay is the round interval.** At 200 events per second, a round seals about 40 events in 4 ms. The delay's p50 is about half the round (112 ms), and its p99 the whole round (201 ms). The interval is the setting that trades delay for load: a one-second round would still leave NFR-09 a factor of five.
2. **A queue of unsealed events makes sealing both correct and cheap.**
   - **How it works:** ingestion inserts each event into a small `audit_unsealed` table, in the same transaction as the event. The sealer takes events off it with `DELETE … RETURNING`. Only committed events are visible to it, so an event whose transaction commits late is sealed in a later batch, never skipped. Trillian uses the same pattern.
   - **Why not the alternatives:**
     - a cursor on ingestion time skips late commits, because the ingestion time is taken before the commit;
     - searching for events without a leaf means scanning a table that only grows.
   - **Row locks cost a privilege.** The first version claimed events with `FOR UPDATE SKIP LOCKED`, which needs the UPDATE privilege; the runtime role lacks it, and the run failed with SQLSTATE 42501. Row locks are unnecessary with one sealer: the DELETE hands each event to exactly one transaction, and the primary key on the leaf index rejects a second sealer's batch. The final runs claimed without row locks, so the role needs only SELECT, INSERT and DELETE on the queue.
3. **The queue churns, and claiming slows between vacuums.** Every event passes through the queue once: 456,000 inserts and deletes in this run. Deleted rows stay in the table and its index until autovacuum cleans them, at most once a minute (`autovacuum_naptime`). That most likely explains why claims slowed: a claim took 0.7 ms at 200 events per second, and 19 ms at 2,000, half of the sealer's work in the burst. The cost is bounded by one minute of churn and was harmless here. P1-02 should export it as a metric, and sites near the burst rate can vacuum more often.
4. **The right edge of the tree is all sealing needs.** Appending reads only the roots of the complete subtrees on the tree's right edge: at most one hash per level, so no more than 20 for a million events. The sealer keeps them in memory and never read a tree hash from the database. Checkpoints compute the root from the same hashes, so signing one takes milliseconds.
5. **Verification must read in chunks.**
   - **One query over the whole log** makes PostgreSQL hash-join the leaves with the events and sort the result on disk. `EXPLAIN ANALYZE` of that query, at one million events: 128 hash batches, 740 MB of external sort, 11 s. At ten million, the spill grows tenfold.
   - **Chunks of 10,000 leaves** look each event up through the index on its ID, in its own month's partition only, and sort in memory. Their cost does not depend on the log's size: smaller logs verified at the same rate.
   - **Reading dominates:** 5.8 s of the 6.6 s. So verifying through the API, or across a slow link, is bound by moving about 740 bytes per event. The earlier run, which read through Docker Desktop's port forwarding with one query, took 39 s.
6. **Batches sharing sources must update their sequence rows in a fixed order.** At 10,000 events per second, with every publisher's batch mixing many sources, two ingestion transactions deadlocked on `audit_source_sequences` (SQLSTATE 40P01). Updating the rows in the order of their source removes the deadlock: a rerun at 10,000 events per second for 30 s, with every batch mixing all 1,000 sources, had none. Real enforcement points publish for their own agents, so their batches rarely share sources, but a module serving many agents does publish such batches.
7. **The disk sets the ceiling, not the sealer.** The slowest sealing transactions were commits that waited 1.3 to 1.7 s for the disk, and ingestion's slowest batches took as long. The stalls varied from run to run: the deadlock rerun at 10,000 events per second had a p99 sealing delay of 369 ms, not 3 s. The disk here is a virtual disk file on the laptop's SSD, behind WSL 2; a server with its own disk should stall less. Even so, NFR-09's 5 s absorbed the stalls at five times the burst rate.
8. **Storage sizes a deployment.**
   - **While retained:** about 2.2 KB per event. The event row with its canonical JSON takes 1.2 KB, its indexes 360 bytes, de-duplication 320 bytes, and the tree 370 bytes.
   - **After retention:** the tree's share stays, since the design keeps leaves and tree hashes so that the remaining log verifies.
   - **What the average rate means for disk:**

     | Average rate | Per day | Six months retained | Tree data kept per year |
     | --- | --- | --- | --- |
     | 10 events/s | 1.9 GB | 350 GB | 117 GB |
     | 50 events/s | 9.6 GB | 1.8 TB | 580 GB |
     | 200 events/s | 38 GB | 7 TB | 2.3 TB |

   NFR-07's 200 events per second is a capacity to absorb, not an expected average; deployments size their disk from their own average.
9. **A hash chain has no advantage worth its proofs.** It computes as fast and saves 198 bytes per event of tree hashes. In exchange, it cannot prove an event without the rest of the chain, and it cannot prove that a later checkpoint extends an earlier one without replaying everything in between. The second proof is how a SIEM detects a rewritten history (ADR-0006, decision 4).

## Changes this spike asks for

- **ADR-0006:** the Merkle tree is confirmed, and the hash chain fallback is no longer needed. Sealing goes through a queue of unsealed events.
- **Plan P1-02:**
  - storage: add the queue table `audit_unsealed`, with SELECT, INSERT and DELETE for the runtime role, and no UPDATE;
  - sealer:
    - claim without row locks;
    - seal up to 5,000 events per transaction in rounds every 200 ms;
    - keep the right edge in memory;
    - reload the tree size and right edge after any failed batch;
  - ingestion:
    - store the events and their queue entries in one statement;
    - update source sequence rows in the order of their source;
  - verification library: read in chunks of about 10,000 leaves;
  - retention: storage per event, and whether to compact the tree data of dropped months;
  - metrics: the claim time, alongside the sealing lag.
- **Plan P1-12:** sizing guidance for the database's disk, from the average audit rate and the retention period.
- **Requirements:** NFR-07, NFR-09 and NFR-10 confirmed by measurement, with their targets unchanged.

## Limitations

- **One laptop, default settings.** PostgreSQL ran with its default configuration on a virtual disk, next to the load generator, over loopback. A tuned server with its own disk would do better, especially at 10,000 events per second.
- **One million events measured, ten million extrapolated.** Smaller logs verified at the same rate. At ten million, though, the database (about 22 GB) no longer fits in memory and reads come from the disk. The events are stored in roughly leaf order, so those reads are mostly sequential.
- **Synthetic events.** One event type of about 700 bytes; real events vary in size, and storage scales with them.
- **Not tested here:** crashes of the sealer, leader election, and the export and query paths. P1-02 tests them.
- **Bytes per event depend on the indexes.** The four query indexes of the current migration cost about 300 bytes per event; P1-02 may keep fewer or other ones.
