# P1-12: Packaging and deployment

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | In progress (2 of 5 pull requests) |
| **Size** | XL, split into two parts: **P1-12.1** (steps 1 to 3, about 3 weeks, right after P1-01) and **P1-12.2** (steps 4 to 10, about 4 weeks: step 4 depends on no feature plan and can run early; steps 5 to 10 run once the feature plans are nearly done) |
| **Depends on** | P1-01 for P1-12.1; P1-07 and P1-08 for the high-availability and upgrade tests of P1-12.2, P1-15 for its offline bundle and compatibility matrix, and P1-09 and P1-16 for its catalog flows (steps 5, 6 and 9), which therefore come last: steps 7, 8 and 10 run first |
| **Unblocks** | P1-13, P1-14 |
| **Requirements** | OPS-01 to OPS-07, NFR-06, NFR-14, NFR-15, NFR-16 |
| **Decisions** | ADR-0001, ADR-0003, ADR-0007 |

## Goal

White Tower can be evaluated on a laptop in fifteen minutes, deployed on Kubernetes with high availability, installed in a site without Internet access, upgraded without stopping agents, and restored from backup with its evidence still verifiable.

## Scope

**In:** hardened images, Compose profiles, the Helm chart, the PostgreSQL reference setup, the air-gapped bundle, the egress-denied test, upgrade and rollback, backup and restore, operations documentation, the CI compatibility matrix.

**Out:** the release process itself (P0-01 and P1-13).

## Deliverables

- Hardened images for the core, the mock module and the demo agent (the network quarantine module's image comes from P1-15).
- `deploy/compose/` profiles `dev` and `eval`, with seed data.
- `deploy/helm/whitetower/`, with a values schema and tests.
- The offline bundle build.
- Operations documentation and runbooks.

## Steps

### 1. Images

The core image:

- a distroless, non-root base without a shell;
- a read-only root filesystem, no added capabilities;
- OCI annotations;
- multi-architecture (amd64 and arm64).

The mock module and the demo agent get images too; the demo agent uses a minimal Python base.

**Done when:** image scans report no critical or high vulnerabilities, and the containers run with a read-only root filesystem.

### 2. Compose profiles

- `dev`, from P0-01.
- `eval`: core, PostgreSQL, Keycloak, mock module, demo agent and an OpenTelemetry collector. A seed script creates roles, sample agents in several lifecycle states, and policies.
- A "fifteen-minute demo" guide: onboard an agent, watch decisions arrive, halt it, verify the audit log.

The `eval` profile grows with the project: P1-12.1 ships it with the core, PostgreSQL and Keycloak; the mock module (P1-07) and the demo agent (P1-09) join as they become available, and P1-12.2 finalizes the guide.

**Done when:** someone who has never seen the project completes the guide in fifteen minutes (OPS-01).

### 3. Helm chart (subplan candidate)

- **Deployment:** at least two replicas, anti-affinity, a pod disruption budget, and a rolling update strategy aligned with the lease TTL (one pod at a time; termination grace period longer than the drain deadline).
- **Networking:** one Service per listener; Ingress or Gateway API routes for the console listener, exposed separately from the machine listener; network policies.
- **Security:** the restricted Pod Security Standard.
- **Configuration and secrets:** ConfigMap, and Secrets for the three signing keys and the database credentials, with support for existing Secrets. An optional ServiceMonitor.
- **Values schema:** in JSON Schema, with its documentation.
- **Migrations:** `whitetower migrate` in an init container, under an advisory lock, with the migration role's credentials mounted there only; the server container gets the runtime role's ([threat model](../../security/threat-model.md), DC-3). No Helm hooks are needed.
- **Tests:** `helm test`, chart-testing (`ct`) and `kubeconform` in CI.

**Done when:** `helm install` on kind passes the smoke and end-to-end tests.

### 4. PostgreSQL reference setup

- CloudNativePG example manifests: three instances, backups with point-in-time recovery to S3-compatible storage (MinIO for air-gapped sites).
- Creation of the migration and runtime roles.
- Connection pooling guidance, including the gotcha that `LISTEN/NOTIFY` and session advisory locks do not work through PgBouncer in transaction mode: each replica's two sessions outside its pool, the notification listener and the job locks, must go direct, or through session mode.
- Sizing guidance ([spike S3](../../spikes/S3-audit-throughput.md)): the database's disk follows from the average audit rate and the retention period. Count about 2.2 KB per retained event, plus about 370 bytes per event that outlive retention. For example, an average of 10 events per second kept for six months takes about 350 GB.

**Done when:** the reference setup is used by the Kubernetes end-to-end tests.

### 5. Air-gapped bundle (Should)

A build job produces `whitetower-offline-<version>.tar` containing:

- OCI image archives: core, mock module, demo agent and network quarantine module;
- the enforcement point wheel and the Helm charts (core and network quarantine);
- SBOMs, cosign bundles for offline signature verification, and checksums;
- the documentation.

The demo agent's image holds its MCP server (a local `stdio` server) and a stub model, so it downloads nothing when it starts (no `npx` or `uvx`) and needs no provider key: the catalog flows of step 6 need no other image.

Instructions cover loading the images into a private registry and verifying everything offline.

**Done when:** a CI job installs from the bundle into a kind cluster with egress blocked, and the smoke test passes.

### 6. Egress-denied test (NFR-14)

Block all egress except cluster-internal traffic, run the full end-to-end suite, and assert that nothing tried to leave: neither the core nor the console assets in the browser. The suite includes the catalog flows of RFC-0002 (a tooling report, an approval, an enabling, a denial by a usage rule, a block), with the demo agent's MCP server and model inside the cluster.

**Done when:** the test runs in CI on every release branch.

### 7. Upgrades (OPS-07, NFR-06)

- An upgrade test from version N-1 to N with data (`helm upgrade`).
- Documentation that migrations are forward-only, so a rollback means restoring a backup.
- A rolling upgrade with 500 mock instances connected must cause no lease expiry and lose no state: halts, active blocks and enablement still hold on every instance afterwards (the mock module of P1-07 applies catalogs and blocks).

**Done when:** both tests run in CI for release candidates.

### 8. Backup and restore (Should, OPS-06)

- A runbook covering point-in-time recovery of the database, backup of the signing keys (offline, sealed) and of the configuration.
- A scripted restore drill.
- After a restore, the audit log still verifies, and a consistency check against a checkpoint exported before the backup passes.
- A restore to an earlier point loses the halts, blocks and disables issued after it. The runbook shows how to find them in the SIEM (`whitetower.halt.issued.v1`, `whitetower.catalog.blocked.v1`, `whitetower.tooling.disabled.v1`) and issue them again. A block names the key of what it covers, or its hash, which is matched against the restored catalog's references; a block of a reference the restored catalog never had cannot be rebuilt from events.
- A key compromise procedure.

**Done when:** the drill passes once and is documented.

### 9. Operations documentation (NFR-16)

- Installation: Compose, Helm, air-gapped.
- TLS and certificates.
- IdP guides: Keycloak, Entra ID, Okta.
- SIEM export guides: OpenTelemetry collector configurations for Splunk, Elastic and Microsoft Sentinel, with example alerts on `whitetower.catalog.definition_changed.v1` and `whitetower.catalog.blocked.v1`.
- Key rotation, scaling and troubleshooting.
- A security configuration guide for what the [threat model](../../security/threat-model.md) assumes: MFA at the IdP; checkpoints exported to the SIEM, with a scheduled consistency check against its latest one that alerts on failure (DC-8); the database's own audit log sent to the SIEM; production resources that accept White Tower tokens requiring `wt_env=production` (R-14); agents' MCP clients that verify TLS, and local MCP servers launched through `npx`, `uvx`, `pipx run` or `bunx` pinned to exact versions, which the catalog flags otherwise (A-6, T-77).
- Time synchronization: every host that runs the core, a module or an agent keeps its clock within a few seconds of the others. An enforcement point whose clock is more than 5 seconds off ignores lease renewals and fails closed (contracts section 5.3).
- The halting runbooks of P1-08.
- The catalog runbooks: blocking a server, a tool, a model, or every model of a provider or an endpoint, effective at once, following the block's spread, and lifting it with a second person; handling a tool denied as `catalog.definition_changed`.
- The fifteen-minute demo, finalized (step 2): onboard an agent and enable its tooling, watch decisions arrive, including one denied by a usage rule, halt the agent, verify the audit log. The seed approves the seeded `wt-catalog` policy and enables no tooling, because enablement comes only from an approved request: the demo agent's report fills the catalog, the advisory committee approves its entries, the owner requests enabling them, and the advisory committee approves the request.

**Done when:** an operator from the pilot organization reviews the documentation.

### 10. Compatibility matrix in CI (NFR-15)

The three latest Kubernetes minor versions (kind, with Cilium as the CNI so the network quarantine tests of P1-15 run in the same clusters), PostgreSQL 16 and 17, and amd64 and arm64 image builds.

**Done when:** the matrix is green for the release candidate.

## Acceptance criteria

- `helm install` on kind passes the smoke and end-to-end tests on three Kubernetes versions.
- The air-gapped installation succeeds with egress blocked.
- A rolling upgrade with 500 mock instances causes no lease expiry and loses no state.
- The restore drill passes, with the audit log verifiable afterwards.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-12-packaging-and-deployment) pass: ST-60 to ST-64.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Ingress controllers cut the machine listener's HTTP/2 streams | Document supported controllers and timeouts; allow a separate LoadBalancer Service for the machine listener |
| The pilot organization cannot run Kubernetes | Compose profile hardened for a single host, with documented limits (no high availability) |

## Notes for implementers

- Keep chart defaults production-safe; development conveniences go in a separate values file.
- Never template secrets into ConfigMaps; mount them as files, as the core expects (OPS-04).

## Progress notes

The plan lands in five pull requests across its two parts (P1-12.1: packaging foundations and Compose/Helm; P1-12.2: production HA, air-gap, and upgrades).

| Pull request | Steps | Status |
| --- | --- | --- |
| 1. Hardened images and evaluation Compose profile | 1, 2, OPS-01 | Done |
| 2. Production Helm chart | 3, ST-61, ST-62, ST-63 | Done |
| 3. PostgreSQL reference setup with CloudNativePG and pooling | 4 | Not started |
| 4. Air-gapped bundle and egress-denied CI test | 5, 6, ST-60, NFR-14 | Not started |
| 5. Upgrades, backup/restore and operations documentation | 7, 8, 9, 10, ST-64, OPS-06, OPS-07 | Not started |

### 2026-10-16: production Helm chart (PR 2)

- Production Helm chart in `deploy/helm/whitetower/` (step 3, ST-61, ST-62, ST-63):
  - `Chart.yaml`: Helm v2 application chart for White Tower `v0.1.0`.
  - `values.yaml` and `values.schema.json`: production-safe defaults with strict JSON Schema (draft-07) validation.
  - High availability & resilience: `replicaCount: 2` minimum, pod anti-affinity across node hostnames, `PodDisruptionBudget` (`minAvailable: 1`), rolling updates (`maxSurge: 1, maxUnavailable: 0`), and `terminationGracePeriodSeconds: 70` (longer than the 60s drain deadline).
  - Restricted Pod Security Standard: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities: { drop: ["ALL"] }`, `seccompProfile: { type: RuntimeDefault }`, user/group/fsGroup 65532, and memory tmpfs mounted at `/tmp`.
  - Three distinct Services and Ingress: dedicated ClusterIP services for console (`8443`), machine (`9443`), and operations (`9090`), with ingress configuration keeping console separate from machine.
  - Credential separation (ST-62, DC-3): database migrations execute in an init container (`migrate`) with only `db-migrator-secret` mounted; the core application container (`whitetower`) mounts runtime `db-app-secret` only and has no access to migration credentials or env vars.
  - File-based secrets (ST-61, OPS-04): key secrets mounted under `/run/secrets/` with strict `0400` permissions; no sensitive secrets or credentials passed via environment variables.
  - Network isolation (ST-63): NetworkPolicy enforcing separate ingress rules for console (`8443` from ingress controllers), machine (`9443` from modules and enforcement points), and operations (`9090` from monitoring and Prometheus), with restricted egress (DNS, PostgreSQL).
  - Observability & test hook: optional `ServiceMonitor` for Prometheus Operator scraping `/metrics`, and `helm test` connection hook executing native `whitetower healthcheck`.
- Documentation & Tests:
  - Chart documentation and installation guide in `deploy/helm/whitetower/README.md`.
  - Automated tests in `test/packaging/helm_test.go` verifying chart metadata, values schema validation, template rendering, HA/resilience configuration, Restricted PSS compliance, distinct services, and security tests ST-61, ST-62, and ST-63.

### 2026-10-16: images and evaluation Compose profile (PR 1)

- Hardened Docker images (step 1, OPS-01):
  - Updated `deploy/docker/Dockerfile` and `deploy/docker/goreleaser.Dockerfile` with standard OCI image annotations (`org.opencontainers.image.title`, `org.opencontainers.image.description`, `org.opencontainers.image.url`, `org.opencontainers.image.source`, `org.opencontainers.image.documentation`, `org.opencontainers.image.licenses`, `org.opencontainers.image.vendor`).
  - Core runs as `USER nonroot:nonroot` on distroless Debian 13 with dropped capabilities (`cap_drop: [ALL]`), `no-new-privileges:true`, and a read-only root filesystem with tmpfs mounted at `/tmp`.
  - Added `deploy/docker/mock-module.Dockerfile` (distroless, non-root) and `deploy/docker/demo-agent.Dockerfile` (minimal non-root Python base) for Step 1 multi-architecture builds.
- Hardening of development Compose profile:
  - Updated `deploy/compose/dev/compose.yaml` to enforce `read_only: true`, `tmpfs: [/tmp:rw,noexec,nosuid]`, `security_opt: [no-new-privileges:true]`, and `cap_drop: [ALL]`.
- Evaluation Compose profile (step 2, OPS-01):
  - Created `deploy/compose/eval/`: complete self-contained stack containing PostgreSQL 17, Keycloak 26 (with pre-imported realm and governance test users), OpenTelemetry collector, migration service, automated database seed service, and the White Tower core.
  - Automated evaluation seed in `deploy/compose/eval/seed/seed.sql`: populates initial principals, role bindings, validated/submitted use cases, sample agents in multiple lifecycle states (`active`, `proposed`, `suspended`), and primary agent ownerships.
  - Tasks in `Taskfile.yml`: `task eval` and `task eval:down`.
- Documentation:
  - Added "The fifteen-minute demo" walkthrough guide in `docs/guides/fifteen-minute-demo.md`.
- Tests:
  - Added `test/packaging/packaging_test.go` verifying Dockerfile OCI labels and non-root execution, Compose profile hardening (read-only rootfs, tmpfs, capabilities, file-based secrets), and verifying that `seed.sql` executes cleanly on a migrated PostgreSQL database without constraint violations.

