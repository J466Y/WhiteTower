# P1-12: Packaging and deployment

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | XL, split into two parts: **P1-12.1** (steps 1 to 3, about 3 weeks, right after P1-01) and **P1-12.2** (steps 4 to 10, about 4 weeks, once the feature plans are nearly done) |
| **Depends on** | P1-01 for P1-12.1; P1-07 and P1-08 for the high-availability and upgrade tests of P1-12.2 |
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
- **Migrations:** run by the core at startup under an advisory lock, so no Helm hooks are needed.
- **Tests:** `helm test`, chart-testing (`ct`) and `kubeconform` in CI.

**Done when:** `helm install` on kind passes the smoke and end-to-end tests.

### 4. PostgreSQL reference setup

- CloudNativePG example manifests: three instances, backups with point-in-time recovery to S3-compatible storage (MinIO for air-gapped sites).
- Creation of the migration and runtime roles.
- Connection pooling guidance, including the gotcha that `LISTEN/NOTIFY` does not work through PgBouncer in transaction mode: the core's listener connection must go direct, or through session mode.

**Done when:** the reference setup is used by the Kubernetes end-to-end tests.

### 5. Air-gapped bundle (Should)

A build job produces `whitetower-offline-<version>.tar` containing:

- OCI image archives: core, mock module, demo agent and network quarantine module;
- the enforcement point wheel and the Helm charts (core and network quarantine);
- SBOMs, cosign bundles for offline signature verification, and checksums;
- the documentation.

Instructions cover loading the images into a private registry and verifying everything offline.

**Done when:** a CI job installs from the bundle into a kind cluster with egress blocked, and the smoke test passes.

### 6. Egress-denied test (NFR-14)

Block all egress except cluster-internal traffic, run the full end-to-end suite, and assert that nothing tried to leave: neither the core nor the console assets in the browser.

**Done when:** the test runs in CI on every release branch.

### 7. Upgrades (OPS-07, NFR-06)

- An upgrade test from version N-1 to N with data (`helm upgrade`).
- Documentation that migrations are forward-only, so a rollback means restoring a backup.
- A rolling upgrade with 500 mock instances connected must cause no lease expiry and lose no state.

**Done when:** both tests run in CI for release candidates.

### 8. Backup and restore (Should, OPS-06)

- A runbook covering point-in-time recovery of the database, backup of the signing keys (offline, sealed) and of the configuration.
- A scripted restore drill.
- After a restore, the audit log still verifies, and a consistency check against a checkpoint exported before the backup passes.
- A key compromise procedure.

**Done when:** the drill passes once and is documented.

### 9. Operations documentation (NFR-16)

- Installation: Compose, Helm, air-gapped.
- TLS and certificates.
- IdP guides: Keycloak, Entra ID, Okta.
- SIEM export guides: OpenTelemetry collector configurations for Splunk, Elastic and Microsoft Sentinel.
- Key rotation, scaling and troubleshooting.
- The halting runbooks of P1-08.

**Done when:** an operator from the pilot organization reviews the documentation.

### 10. Compatibility matrix in CI (NFR-15)

The three latest Kubernetes minor versions (kind, with Cilium as the CNI so the network quarantine tests of P1-15 run in the same clusters), PostgreSQL 16 and 17, and amd64 and arm64 image builds.

**Done when:** the matrix is green for the release candidate.

## Acceptance criteria

- `helm install` on kind passes the smoke and end-to-end tests on three Kubernetes versions.
- The air-gapped installation succeeds with egress blocked.
- A rolling upgrade with 500 mock instances causes no lease expiry and loses no state.
- The restore drill passes, with the audit log verifiable afterwards.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Ingress controllers cut the machine listener's HTTP/2 streams | Document supported controllers and timeouts; allow a separate LoadBalancer Service for the machine listener |
| The pilot organization cannot run Kubernetes | Compose profile hardened for a single host, with documented limits (no high availability) |

## Notes for implementers

- Keep chart defaults production-safe; development conveniences go in a separate values file.
- Never template secrets into ConfigMaps; mount them as files, as the core expects (OPS-04).
