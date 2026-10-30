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
- Synchronous replication to any one of the two standbys (a quorum of one), with CloudNativePG's synchronous replicas and preferred data durability, so that a failover keeps committed halts (the halt path's [design note](P1-08-kill-switch.md#progress-notes), section 10). One standby that stops answering never makes a commit wait. If both stop, commits wait until CloudNativePG drops them from the synchronous standbys, then go on without one, and a failover in that window can lose committed halts, which the note's rule on version regression covers; measure how long commits wait then. Each commit waits for one standby's flush, a round trip that the note's budget allows (section 11).
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

- The core is upgraded before its modules: a module's release is never newer than its core's, because the core reads the closed documents that modules send (contracts, section 10).
- An upgrade test from version N-1 to N with data (`helm upgrade`).
- Documentation that migrations are forward-only, so a rollback means restoring a backup.
- A rolling upgrade with 500 mock instances connected must cause no lease expiry and lose no state: halts, active blocks and enablement still hold on every instance afterwards (the mock module of P1-07 applies catalogs and blocks).

**Done when:** both tests run in CI for release candidates.

### 8. Backup and restore (Should, OPS-06)

- A runbook covering point-in-time recovery of the database, backup of the signing keys (offline, sealed) and of the configuration.
- A scripted restore drill.
- After a restore, the audit log still verifies, and a consistency check against a checkpoint exported before the backup passes.
- A restore to an earlier point loses the halts, blocks and disables issued after it. The runbook shows how to find them in the SIEM (`whitetower.halt.issued.v1`, `whitetower.catalog.blocked.v1`, `whitetower.tooling.disabled.v1`) and issue them again. A block names the key of what it covers, or its hash, which is matched against the restored catalog's references; a block of a reference the restored catalog never had cannot be rebuilt from events.
- After a restore, the runbook re-issues every agent's bundle at a higher version, even when its content is unchanged, so that no enforcement point that kept running holds a bundle the restored core no longer names (contracts, CORE-18; P1-06 step 6).
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
- Intermediaries on the machine listener's path: each supported proxy and ingress controller passes every `Watch` message as it arrives, with the settings that it takes; one that buffers the stream makes every lease renewal stale and every lease run out (contracts, section 4.1).
- Evidence buffers: enforcement points and runtime-control modules keep theirs on storage that outlives their containers, such as a volume; a buffer that lives only as long as its pod loses what it has not delivered when the pod is deleted (contracts, I-5 and section 8.4).
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
| Ingress controllers cut the machine listener's HTTP/2 streams, or buffer them | Document supported controllers, their timeouts, and their settings to pass `Watch` messages unbuffered (step 9); allow a separate LoadBalancer Service for the machine listener |
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

### 2026-10-30: signing in from a browser (fix)

A fix outside the five pull requests, from the reviewer's finding of 2026-10-29 ([AGENTS.md](../../../AGENTS.md), work queue), with the decisions that the maintainer and the reviewer took on 2026-10-30. No stack let a person sign in from a browser, which milestone M1 asks for, so the guide of pull request 1 could not be followed (step 2, OPS-01).

- **Keycloak's two addresses.** Browsers reach Keycloak at `http://127.0.0.1:8180`, and a core in a container at `http://keycloak:8080`. Keycloak named its issuer after the host of each request, and the evaluation core's issuer was `http://keycloak:8080/realms/whitetower`, which browsers cannot resolve. In both stacks, Keycloak now names itself after the browsers' URL (`KC_HOSTNAME`, `http://127.0.0.1:${WT_KEYCLOAK_PORT:-8180}`) and keeps a dynamic back channel (`KC_HOSTNAME_BACKCHANNEL_DYNAMIC`). Tokens carry the browsers' issuer, the endpoints that browsers use are on it, and the token, key and user info endpoints follow the address of each request. A realm's `frontendUrl` alone would move those to `127.0.0.1` too, which a container cannot reach, as a spike of the review measured.
- **A discovery URL.** The setting `auth.oidc.discovery_url` (`WT_AUTH_OIDC_DISCOVERY_URL`) is the base URL that the core fetches `/.well-known/openid-configuration` from when it reaches the provider at another address than browsers do. go-oidc compares the document's issuer with the URL it fetched the document from; the core turns that comparison off in every case, with go-oidc's issuer URL context, and compares the document's issuer with `auth.oidc.issuer` itself, so that one tested path decides. ID tokens are verified against `auth.oidc.issuer`, and principals keep it as their issuer. Validation refuses the setting without an issuer, outside http and https, with user info, a query or a fragment, over http when the issuer is https, equal to the issuer, or as the document's own URL. A failed discovery stops the core and names the document's URL. The callback no longer shows the browser the errors of the token exchange and of the key fetch, which can name the back channel, and the exchange of an ID token for the CLI (`/api/v1/tokens/exchange`) no longer repeats the verifier's error to its client: the log keeps both.
- **Both stacks and `task run`.** The Compose cores take the browsers' issuer and the discovery URL `http://keycloak:8080/realms/whitetower`, receive the client secret, and wait for a healthy Keycloak, since discovery runs once, at start. The core of the development stack's `core` profile had no OIDC settings, and neither had `task run`, which now signs in with the issuer alone: the host reaches Keycloak there. CI's End-to-end job therefore starts Keycloak too.
- **Scopes (the maintainer's decision).** The stacks and `task run` ask for `openid`, `profile` and `email`. Keycloak defines no `groups` client scope and answers `invalid_scope` to the core's default scopes, while the client's group-membership mapper already puts `groups` in the ID token. The core's defaults and the realms' client scopes do not change.
- **Logout (the maintainer's decision).** The core sent `post_logout_redirect_uri` alone, pointing at its callback: Keycloak 26 answers 400 without `id_token_hint` or `client_id`, and kept its session. The core now sends `client_id`, and the console's root on the origin of `auth.oidc.redirect_url`, which both realms register as exact post-logout URIs instead of wildcards. Keycloak asks the person to confirm, then ends its session. The logout criterion of P1-03 step 1, login and logout against the development Keycloak, now holds.
- **Realms.** The development realm registered callbacks on `http://localhost:8080` and `http://127.0.0.1:8080`; it now registers those of `https://127.0.0.1:8443` and `https://localhost:8443`, as the evaluation realm does. Every user has a fixed ID, the same in both realms, which Keycloak puts in `sub`: a user stays the same principal when Keycloak imports the realm again.
- **The evaluation seed (the maintainer's decision).** Its principals take the core's issuer, the users' IDs as subjects, and their groups as ID tokens carry them, without a leading slash. Signing in as `owner` therefore finds the seeded Olivia Owner, with her agents and role bindings, matched on issuer and subject. The seed runs with `ON_ERROR_STOP`, so a failed statement keeps the core from starting instead of passing unnoticed, and every insert still skips the rows it wrote before. A stack whose data predates the fix keeps principals that sign-in does not match: `task eval:down -- -v` deletes them.
- **`inactive` (the reviewer's decision).** It stays an account that Keycloak disables: Keycloak refuses it at its form, and the core never sees the sign-in nor creates its principal.
- **Ports.** A `WT_CONSOLE_PORT` other than 8443 breaks sign-in, since the realms register that port only. Another `WT_KEYCLOAK_PORT` keeps sign-in working, but the evaluation seed's principals no longer match. The stacks' READMEs say so, rather than templating the realms and the seed.
- **The fifteen-minute demo.** The reader signs in at the core's `/auth/login` and reads the API in the same browser, as a user whose roles allow each step. The guide no longer offers a button "Log in with Keycloak", which the console does not have, nor `curl` calls without a session, which answer 401. It also corrects what the documents' review found false: `/healthz` answers `ok`, not JSON; the roles table lacked `user`; a fresh stack's audit log is empty; checkpoints and keys need `audit.verify`, which `owner`, `admin` and `user` lack; its `grep` for an event's ID took `data.actor.id`; and the newest event has no proof until a checkpoint covers it.
- Tests:
  - ST-16, in `internal/authn`: a provider discovered through a back channel sends browsers to the issuer's endpoints, keeps the issuer for principals and for logout, and refuses an ID token issued at the back channel, at the callback and in `ExchangeIDToken`; a document that names another issuer is refused, at a discovery URL and at the issuer; a failed token exchange or key fetch names nothing of the back channel to the browser, nor does a refused exchange for the CLI; a failed discovery names the document's URL; the service refuses to start without an issuer or with a relative redirect URL; the logout's parameters.
  - `internal/platform/config`: each refusal of `auth.oidc.discovery_url`, and the values that the stacks use.
  - `web/e2e/sign-in.spec.ts`, in CI's End-to-end job: every enabled user of the realm signs in through Keycloak's form and holds the roles of their groups; `inactive` is refused before the core's callback; signing out goes through Keycloak's confirmation, and the next sign-in asks for the password. A browser test rather than a Go one, because the fault and its fix are in what a browser does: Keycloak's form, its cookies on `http://127.0.0.1`, the redirects between the two origins and Keycloak's logout page.
  - `test/packaging`, since CI never starts the evaluation stack: both stacks and `task run` against their realm (Keycloak's hostname, the issuer, the discovery URL, the redirect and post-logout URIs, the secret, the scopes and the wait for Keycloak); both realms give each user the same fixed ID; the evaluation seed's principals have the core's issuer and the users' IDs, and a second run changes nothing.
- Follow-ups: the Helm chart, which has the same fault and no discovery URL; a timeout on the core's calls to the identity provider; a successful sign-in does not revoke a session that the browser already holds, which ST-14 asks (sessions rotated at login); and the operations guide (step 9), which tells an operator of Keycloak to set the scopes too, or to add a `groups` client scope.

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

