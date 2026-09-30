# ADR-0003: PostgreSQL as the only stateful dependency of the MVP

- **Status:** Accepted for the MVP, by the maintainer on 2026-09-30. The database may be revisited once the MVP runs; a change would come as a new ADR.
- **Date:** 2026-09-28
- **Related:** CON-07, AUD-01, NFR-06, NFR-14, OPS-07; ADR-0005, ADR-0006

## Context

White Tower must be easy to run self-hosted and air-gapped. Every extra stateful component (broker, cache, dedicated log store) is something operators must deploy, secure, back up and upgrade. At the same time, the core needs strong transactions (a state change and its audit event must commit together, AUD-01), change notification across replicas (to push halts from whichever replica received them), and leader election for background jobs.

## Decision

**PostgreSQL 16 or later holds all core state, including the audit log.** The MVP adds no Redis, NATS or Kafka.

- **Access:** `pgx` v5 with `sqlc` (SQL written by hand, type-safe Go generated from it). No ORM.
- **Migrations:** `goose`, embedded in the binary, forward-only, applied at startup under an advisory lock (OPS-07).
- **Notifications across replicas:** `LISTEN/NOTIFY` carrying only identifiers and versions (payloads are limited to 8 KB); listeners re-read the data. Wrapped in an internal interface so a broker can replace it.
- **Leader election for background jobs:** PostgreSQL advisory locks.
- **Events:** transactional outbox table for events produced by the core.
- **Privileges:** separate roles for migrations (schema owner) and runtime. The runtime role has INSERT-only rights on audit tables (ADR-0006).
- **High availability and backups:** delegated to the PostgreSQL operator of the organization's choice; the Helm chart documents CloudNativePG as the reference.

## Consequences

**Easier**
- A deployment is one binary plus PostgreSQL, the simplest possible air-gapped story.
- State and audit commit atomically.
- PostgreSQL is familiar to operators, with mature backup, point-in-time recovery and HA tooling.

**Harder**
- Audit ingestion has a throughput ceiling, well above the MVP target (NFR-07). Audit tables are partitioned by month; if the ceiling is reached, a broker can be introduced behind the event interface.
- `LISTEN/NOTIFY` does not guarantee delivery to disconnected listeners; watch streams therefore resynchronize from versions stored in tables on reconnect instead of trusting notifications alone.

## Alternatives considered

- **NATS JetStream** (streams and key-value watches). A strong candidate if module-to-module events grow in Phase 2 or later; the event interface keeps that door open. Not needed for the MVP.
- **Kafka.** Too heavy for the target deployments.
- **SQLite for single-node installs.** Rejected: two database dialects would diverge between development and production.
- **immudb for the audit log.** A tamper-evident database, but one more stateful dependency; ADR-0006 gets tamper evidence inside PostgreSQL.
