# ADR-0006: Tamper-evident audit log with a Merkle tree and signed checkpoints

- **Status:** Accepted, by the maintainer on 2026-09-30
- **Date:** 2026-09-28
- **Related:** AUD-01 to AUD-10, NFR-07 to NFR-10; ADR-0003; [spike S3](../spikes/S3-audit-throughput.md)

## Context

The charter asks for "signed logs or WORM storage, exportable to the organization's SIEM" and for every policy decision and agent action to leave "an immutable, auditable trail". The audit log is one of the five functions of the core and a key selling point for compliance.

A table in a database is not immutable: whoever administers the database can change it. What can be achieved is **tamper evidence**: any change is detectable, including one made by a privileged insider, as long as some proof of the log's state is kept outside the attacker's reach.

## Decision

1. **Storage.** Events live in an append-only `audit_events` table in PostgreSQL. The runtime database role can only INSERT into it, and triggers reject UPDATE and DELETE. Tables are partitioned by month.
2. **Sealing.** A single background job (the sealer, one leader across replicas) assigns each new event a position in the log and appends it to a **Merkle tree with RFC 6962 hashing**. The leaf is the SHA-256 of the event's canonical JSON (RFC 8785). Intermediate tree hashes are stored in their own table. The reference implementation is `golang.org/x/mod/sumdb/tlog`, the code behind the Go checksum database; the `transparency-dev` libraries are the fallback. Ingestion adds each event to a **queue of unsealed events** in the event's own transaction, and the sealer takes events off it in batches, so an event whose transaction commits late is sealed later, never skipped.
3. **Checkpoints.** At least every 60 seconds (or every N events), the sealer signs a **checkpoint** (tree size and root hash) in the C2SP `tlog-checkpoint` signed-note format, with an Ed25519 key reserved for this purpose.
4. **Anchoring outside White Tower.** Checkpoints travel with the audit export stream (OTLP, JSON Lines) and can be stored by the SIEM, a WORM bucket or any other witness. A later consistency proof between an external checkpoint and the current tree shows that history has not been rewritten, even by a database administrator.
5. **Verification.** `wtctl audit verify` recomputes the tree from the events and checks the checkpoint signatures; `wtctl audit prove` produces and checks inclusion proofs for single events and consistency proofs between two checkpoints.
6. **Retention without losing verifiability.** Deleting old partitions (by the retention policy, itself an audited event) keeps the tree hashes, so the remaining events and all checkpoints still verify.
7. **Keys.** In the MVP, signing keys are read from files or Kubernetes Secrets, separate from the database. Access goes through an interface so KMS or HSM backends can be added.

## Consequences

**Easier**
- Tampering is detectable, and with externally held checkpoints it is detectable even for a database administrator.
- Proofs are logarithmic: one event can be proven without replaying the whole log.
- The formats are those of transparency logs (Go checksum database, Sigstore), not a custom design, and third parties can verify them with existing tools.
- The whole mechanism lives inside PostgreSQL (ADR-0003).

**Harder**
- The sealer serializes appends to the tree. Spike S3 measured it on a laptop: at 2,000 events per second it was busy 18% of the time, with a p99 sealing delay of 341 ms, and it kept up at 10,000 per second.
- Storage: about 2.2 KB per retained event in PostgreSQL, of which about 370 bytes of tree data outlive retention (spike S3).
- Protection against a privileged insider depends on checkpoints actually being stored outside. The deployment guide makes it an explicit step.
- If the checkpoint signing key leaks, forged checkpoints become possible. The key is separate from the database, rotatable, and its public half is published.

## Alternatives considered

- **A plain hash chain.** Simpler, but proofs are linear and there is no efficient consistency proof between two checkpoints. It was kept as the fallback in case the Merkle tree proved too costly; spike S3 found it costs about the same to compute and two stored hashes per event, so the fallback is no longer needed.
- **immudb.** A tamper-evident database, but another stateful dependency (ADR-0003).
- **Trillian or Tessera.** Production-grade transparency logs, but heavier to operate and without a PostgreSQL backend fitting this design. Worth revisiting if the log must scale far beyond the MVP.
- **WORM storage only** (S3 Object Lock). Prevents deletion but proves little about ordering or completeness; kept as an optional archive (AUD-08).
