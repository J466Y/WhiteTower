# White Tower: MVP architecture

| | |
| --- | --- |
| **Status** | Draft v0.1, open for review |
| **Date** | 2026-09-28; updated 2026-09-29 (ADR-0011, network quarantine) and 2026-09-30 (threat model) |
| **Related** | [Requirements](../requirements/mvp-requirements.md), [ADRs](../adr/README.md), [Implementation plans](../plans/README.md), [Threat model](../security/threat-model.md) |

This document describes how the MVP is built: its components, the interfaces between them, the flows that matter most, and how it is deployed. The reasons behind each choice are in the ADRs; this document only links to them. Normative details (exact schemas, messages and states) are produced by the Phase 0 plans and will replace the sketches marked as such here.

---

## 1. Architectural drivers

| Driver | Requirements | Answer |
| --- | --- | --- |
| Fail closed without putting the core in the latency path of agent actions | NFR-01, NFR-02 | Decisions at the edge; governance state pushed to enforcement points, which hold leases ([ADR-0005](../adr/0005-edge-enforcement-with-leases.md)) |
| Stop running agents within seconds, with a bounded worst case | KIL-01 to KIL-07, KIL-10, NFR-03 to NFR-05 | Halts are pushed state changes, acknowledged per instance; lease expiry is the backstop ([ADR-0005](../adr/0005-edge-enforcement-with-leases.md)); on Kubernetes, network quarantine does not depend on the agent's process (section 6.2) |
| Evidence that holds up even against a privileged insider | AUD-01 to AUD-06 | Merkle tree log with signed checkpoints anchored outside ([ADR-0006](../adr/0006-tamper-evident-audit-log.md)) |
| Governance rules that are enforced, not just documented | AID-04, KIL-06, POL-04 | Token issuance gated by lifecycle and run state in the same transaction ([ADR-0010](../adr/0010-built-in-agent-token-issuer.md)) |
| Self-hosted, air-gapped, few moving parts | CON-02, NFR-14 | One Go binary with the console embedded, plus PostgreSQL ([ADR-0001](../adr/0001-backend-language-go.md), [ADR-0002](../adr/0002-frontend-typescript-react.md), [ADR-0003](../adr/0003-postgresql-only-stateful-dependency.md)) |
| Interchangeable modules | MOD-01 to MOD-08 | Versioned contracts in standard formats, conformance kit ([ADR-0004](../adr/0004-api-and-contract-formats.md)) |
| A small core | CON-05 | Five functions in the core; everything else behind the module contract |

## 2. System context

```mermaid
flowchart TB
    subgraph people[People]
        direction LR
        SC[Steering committee]
        AC[Advisory committee]
        OW[Agent owners]
        OP[Platform operators]
        AU[Auditors]
    end

    UI[Web console]
    CLI[wtctl CLI]

    subgraph core[White Tower core: one Go binary]
        API[Public REST API]
        MAPI[Module API and token endpoint]
    end

    PG[(PostgreSQL)]
    IDP[Organization IdP, OIDC]
    SIEM[SIEM or OpenTelemetry collector]

    subgraph runtime[Agent runtime]
        AG[AI agent] --- EP[White Tower enforcement point, in the agent's process]
    end

    QM[Network quarantine module, one per Kubernetes cluster]
    CNI[Cluster network, CNI with deny rules]

    TP[Third-party agent without runtime integration, coverage C0]

    people --> UI
    people --> CLI
    UI --> API
    CLI --> API
    API -- login --> IDP
    EP -- token, watch, events --> MAPI
    QM -- token, watch, acknowledgements --> MAPI
    QM -- isolates halted agents --> CNI
    core --> PG
    core -- audit export and checkpoints --> SIEM
    OW -. registers .-> TP
```

Third-party agents that cannot be integrated at runtime still get an inventory record, an owner, a use case and a policy (coverage C0). Governed agents run with an enforcement point in their process that talks to the core. On Kubernetes, the network quarantine module isolates halted agents without relying on that process.

## 3. The core

The core is one process with two network listeners, a set of domain packages and background jobs. All replicas are identical and stateless; state lives in PostgreSQL.

```mermaid
flowchart LR
    subgraph transport[Transport, thin]
        REST[REST handlers, OpenAPI]
        BFF[OIDC login and sessions]
        TOK[OAuth token endpoint, JWKS]
        CONNECT[Module API handlers, ConnectRPC]
        WEB[Embedded console assets]
    end

    subgraph domain[Domain packages]
        AUTHZ[authz: roles, permissions, separation of duties]
        INV[inventory: agents, owners, use cases, lifecycle, reviews]
        AID[agentid: credentials, tokens, signing keys]
        POL[policy: versions, approvals, bundles]
        KS[killswitch: halts, releases, acknowledgements, drills]
        GS[govstate: state versions, leases, watch fan-out]
        MOD[modules: manifests, instances, capabilities]
        AUD[audit: writer, ingestion, sealer, export]
    end

    subgraph platform[Platform]
        CFG[config, logging, telemetry]
        DB[database, migrations, transactions]
        JOBS[leader-elected jobs]
        BUS[change notifications across replicas]
    end

    transport --> domain
    domain --> platform
```

| Package | Responsibility | Main requirements |
| --- | --- | --- |
| `internal/platform` | Configuration, logging, telemetry, HTTP servers, database access, migrations, background jobs, notifications across replicas | OPS-04, OPS-05, OPS-07 |
| `internal/authn` | OIDC backend-for-frontend, sessions, API tokens, break-glass | HUM-01, HUM-06, HUM-07 |
| `internal/authz` | Role mapping, permission matrix, relationship checks, separation of duties | HUM-02 to HUM-04 |
| `internal/inventory` | Agents, owners, use cases, reviews, lifecycle state machine, coverage | INV-01 to INV-10 |
| `internal/agentid` | Agent and module credentials, token endpoint, JWKS, key rotation | AID-01 to AID-07 |
| `internal/policy` | Policies, versions, approvals, effective sets, signed bundles | POL-01 to POL-08 |
| `internal/killswitch` | Halts, releases, acknowledgements, propagation metrics, drills | KIL-01 to KIL-09 |
| `internal/govstate` | Governance state per agent, versions, leases, watch fan-out | MOD-04, NFR-03, NFR-05 |
| `internal/modules` | Manifests, registrations, instances, capability index | MOD-01 to MOD-03 |
| `internal/audit` | In-transaction writer, ingestion, sealer, checkpoints, query, export | AUD-01 to AUD-10 |
| `internal/api/rest`, `internal/api/moduleapi` | Generated server interfaces and thin handlers | API-01 to API-03 |

**Rules for the code:**

- Domain packages never import transport packages.
- Every state-changing domain operation runs in a database transaction and writes its audit events in that same transaction (AUD-01).
- Every state change that affects enforcement points bumps the governance state version in that transaction and notifies the other replicas after commit.
- Authorization is checked in the domain layer, not only in handlers, so the REST API, the CLI and future interfaces share one enforcement point.

### 3.1 Background jobs

Jobs run on every replica but acquire a PostgreSQL advisory lock, so only one replica (the leader) runs each job.

| Job | Purpose | Requirement |
| --- | --- | --- |
| Audit sealer | Appends ingested events to the Merkle tree and signs checkpoints | AUD-03, NFR-09 |
| Audit exporter | Streams sealed events and checkpoints to OTLP, JSON Lines and syslog, with a persisted cursor | AUD-06, AUD-07 |
| Lifecycle guard | Suspends agents whose owner is inactive or whose review is overdue; sends reminders | INV-05, INV-06 |
| Lease watchdog | Marks instances as lost when their lease expires; raises alerts for unconfirmed halts | KIL-03, KIL-04 |
| Retention | Drops expired audit partitions while keeping tree hashes | AUD-08 |
| Key rotation | Rotates token, bundle and checkpoint signing keys on schedule | AID-05 |

## 4. Interfaces

### 4.1 Listeners

| Listener | Default | Serves | Clients | Authentication |
| --- | --- | --- | --- | --- |
| Console and API | `:8443`, HTTPS | Console assets, `/api/v1`, `/auth/*`, `/.well-known/*` | Browsers, CLI, the organization's tools | Session cookie with CSRF token; API tokens |
| Machine | `:9443`, HTTPS with HTTP/2 | Module API (ConnectRPC), `/oauth2/token`, `/.well-known/jwks.json`, `/.well-known/oauth-authorization-server` | Enforcement points, module instances, agents | `private_key_jwt` at the token endpoint; bearer access tokens on the module API; mutual TLS optional |
| Operations | `:9090`, HTTP, cluster-internal | `/metrics`, `/healthz`, `/readyz` | Prometheus, Kubernetes probes | Network policy |

Separating the human-facing and machine-facing listeners lets operators expose them to different networks.

### 4.2 Public REST API (sketch; defined in `api/openapi`)

| Resource | Operations |
| --- | --- |
| `/api/v1/me` | Current principal, roles and permissions |
| `/api/v1/agents` | List, filter, export, create a proposal |
| `/api/v1/agents/{id}` | Read, update metadata (ETag and If-Match) |
| `/api/v1/agents/{id}/transitions` | Lifecycle actions: submit, validate, activate, suspend, reinstate, retire |
| `/api/v1/agents/{id}/credentials` | Register, rotate and revoke public keys |
| `/api/v1/agents/{id}/instances` | Running instances reported by enforcement points |
| `/api/v1/agents/{id}/reviews` | Periodic reviews |
| `/api/v1/use-cases` | Create, validate, reject, request changes |
| `/api/v1/policies`, `/api/v1/policies/{id}/versions` | Author, validate, diff, submit, approve, activate, roll back |
| `/api/v1/halts` | Issue a halt (agent, fleet or selector); list; per-instance status |
| `/api/v1/halts/{id}/release-requests` | Request and approve a release (two people) |
| `/api/v1/audit/events`, `/api/v1/audit/checkpoints` | Search; event detail with inclusion proof; checkpoints and keys |
| `/api/v1/modules` | Register a manifest, approve, list instances and health |
| `/api/v1/principals`, `/api/v1/role-bindings`, `/api/v1/settings` | Administration |

### 4.3 Module API

Defined in `api/proto`, package `whitetower.module.v1alpha1`, and specified in the [module contracts](../contracts/module-contract-v0.1.md#4-module-api).

| Service and method | Direction | Purpose |
| --- | --- | --- |
| `RegistryService.RegisterInstance` | Module → core | Announce an instance: module, manifest hash, version, supported contract versions, agents served |
| `RegistryService.Heartbeat`, `DeregisterInstance` | Module → core | Report health and the agents served; leave cleanly |
| `GovernanceService.Watch` | Core → module (server stream) | Snapshot, then changes: agent state, halts, bundle reference, fleet state, lease renewals |
| `GovernanceService.Acknowledge` | Module → core | Report halt layers, bundle activations and the state version applied |
| `PolicyService.GetBundle`, `GetBundleKeys` | Module → core | Download a signed policy bundle by reference; list the bundle signing keys |
| `EventService.Publish` | Module → core | Send a batch of CloudEvents: decisions, actions, instance events |
| `MetaService.GetServerInfo` | Module → core | The core's version and supported contract versions |

### 4.4 Events

The catalog is in `api/events`, specified in the [module contracts](../contracts/module-contract-v0.1.md#8-events).

| Emitted by | Types |
| --- | --- |
| Enforcement points | `whitetower.decision.made.v1`, `whitetower.action.executed.v1`, `whitetower.instance.started.v1`, `whitetower.instance.halted.v1`, `whitetower.bundle.activated.v1`, `whitetower.bundle.rejected.v1`, `whitetower.lease.expired.v1` |
| Network quarantine module | `whitetower.quarantine.applied.v1`, `whitetower.quarantine.lifted.v1` |
| Core | `whitetower.agent.created.v1`, `whitetower.agent.lifecycle_changed.v1`, `whitetower.policy.version_approved.v1`, `whitetower.halt.issued.v1`, `whitetower.halt.released.v1`, `whitetower.audit.checkpoint.v1`, and one type for every other state change (AUD-01) |

Every event carries the W3C trace context (CloudEvents distributed tracing extension), so a decision can be followed from the agent to the audit log.

## 5. Key flows

### 5.1 From proposal to production

1. An owner proposes the agent with its metadata and use case (`draft`, then `proposed`).
2. The advisory committee validates the use case (`validated`). The owner may now register non-production credentials and test.
3. The agent-specific policy is written, validated and approved by the advisory committee; the harness is declared (`ready`).
4. The owner or an operator activates the agent (`active`). The core checks the invariant: active owner, validated use case, approved agent-specific policy.
5. The core builds and signs the agent's bundle and publishes its governance state. Production tokens can now be issued.
6. Reviews come due by risk tier; overdue reviews and inactive owners lead to automatic suspension.

### 5.2 A governed agent action

```mermaid
sequenceDiagram
    participant A as Agent
    participant EP as Enforcement point
    participant C as White Tower core
    Note over EP,C: Beforehand: valid lease, run state RUNNING, verified bundle
    A->>EP: tool call or other action
    EP->>EP: evaluate global and agent-specific policies locally
    alt allowed
        EP-->>A: proceed
    else denied, lease expired, no valid bundle or halted
        EP-->>A: blocked
    end
    EP-)C: Publish decision event (asynchronous, buffered on disk)
    C->>C: store, then seal into the audit log
```

The core is not in the synchronous path. If it is unreachable, the EP keeps deciding with its last state until the lease expires, then fails closed.

### 5.3 Halting an agent

```mermaid
sequenceDiagram
    actor O as Operator
    participant C1 as Core replica 1
    participant DB as PostgreSQL
    participant C2 as Core replica 2
    participant EP as Enforcement points
    participant QM as Network quarantine module
    O->>C1: POST /api/v1/halts {target, reason}
    C1->>DB: one transaction: halt, agent suspended, state version +1, audit event
    C1->>DB: NOTIFY state change
    DB-->>C2: notification
    C1-)EP: Watch: run state HALTED (streams on replica 1)
    C2-)EP: Watch: run state HALTED (streams on replica 2)
    C1-)QM: Watch: run state HALTED
    EP->>EP: close the gate, interrupt the current action if possible
    EP->>C1: Acknowledge(halt, layers and times)
    QM->>QM: apply a deny rule to the agent's pods
    QM->>C1: Acknowledge(halt, network quarantined at)
    C1->>DB: record acknowledgements and propagation time
    Note over EP: If the stream is lost, the lease expires after its TTL and the EP halts anyway
```

In the same transaction, token issuance for the agent stops, except for the module API tokens its enforcement point needs to acknowledge, deliver its evidence and learn of the release (DC-1 of the [threat model](../security/threat-model.md)). A fleet halt works the same way through a fleet-wide state, which also covers agents registered afterwards and leaves individual lifecycle states unchanged. Releasing a halt needs a request and an approval by two different people.

### 5.4 Publishing a policy change

1. A new policy version is written and validated (syntax, and tests if provided).
2. It is submitted and approved by the right committee, never by its author.
3. On activation, the core recomputes the effective set of every affected agent (all agents for a global policy), builds and signs new bundles, and bumps their governance state.
4. EPs receive the new bundle reference, download and verify the bundle, activate it and acknowledge. The console shows which bundle each instance runs and flags drift.

### 5.5 Audit evidence

1. Core events are written in the transaction of the change; EP events arrive in batches and are de-duplicated by source and ID, with per-source sequence numbers so gaps are detected.
2. The sealer appends new events to the Merkle tree within seconds and signs a checkpoint at least every minute.
3. The exporter streams events and checkpoints to the SIEM. Checkpoints stored outside are later used to prove that the log was not rewritten.
4. `wtctl audit verify` recomputes the tree and checks signatures; `wtctl audit prove` checks single events and consistency between checkpoints.

## 6. Governance state and leases

For every agent, the core maintains a governance state record: lifecycle state, halts, the effective bundle reference (version, manifest hash and size), the lease TTL, the halt mode, the attributes policies may use, and a version number taken from a global sequence. The fleet state, with its active fleet halts, is one more record.

- **Watch protocol.** An EP opens `Watch` with the last version it applied. The core replies with a snapshot if the EP is new or too far behind, then streams changes in version order. Lease renewals come at a third of the TTL, and at least every 30 seconds, only when the stream is current. The [module contracts](../contracts/module-contract-v0.1.md#5-governance-state-leases-and-halts) specify it.
- **Lease expiry is computed by the EP** from its own monotonic clock at the moment it receives a renewal, so it does not depend on clocks being synchronized between hosts.
- **Obligations of an EP**, numbered EP-1 to EP-12 in the [contracts](../contracts/module-contract-v0.1.md#57-obligations-of-enforcement-points):
  - allow nothing until it has a current state, a lease and a verified bundle;
  - deny everything and halt the agent when the lease expires or the agent is halted;
  - acknowledge halts, layer by layer, and bundle activations;
  - record every decision durably before the action proceeds, and fail closed when the buffer is full;
  - reconnect with jittered exponential backoff.

### 6.1 The MVP enforcement point: White Tower's package in the agent's process

Agent frameworks run tool and model calls inside the agent's process, so that is where an enforcement point sees every action. The MVP's enforcement point is a **Python package**, `whitetower-ep` (`modules/ep-python/`), loaded in the agent's process ([ADR-0011](../adr/0011-own-python-enforcement-point.md)). Spike S1 evaluated Microsoft AGT as its foundation, and found that White Tower had to build the gate, the halt, the Cedar evaluation and the evidence buffer anyway, with weaker guarantees ([S1](../spikes/S1-agt.md)).

```mermaid
flowchart LR
    subgraph proc[Agent process]
        FW[Agent framework] -- tool, model, input and output hooks --> EP[White Tower enforcement point]
        EP --- CEDAR[Cedar evaluation, cedarpy]
        EP --- BUF[(Durable evidence buffer)]
    end
    EP -- token, Watch, GetBundle, Acknowledge, Publish --> CORE[White Tower core]
```

| Part | What it does |
| --- | --- |
| Framework hooks | Route every governed call and interaction (tool calls, model calls, inputs and outputs) through the gate and the policies. LangGraph 1.x first; other frameworks as the pilot needs them |
| Gate | Evaluated before the policies; denies everything while there is no current state, the lease has expired, the bundle is missing or invalid, the agent is halted, or the evidence buffer is full |
| Policy evaluation | Verifies the signed bundle, parses its Cedar policy set once, and swaps it atomically. Global and agent-specific policies form one set, so Cedar's "forbid overrides permit" gives the combination semantics of POL-03 |
| Evidence | Writes each decision to a durable local buffer before the action proceeds, then ships the buffer in batches; no governed action without evidence |
| Halt | Applies the halt layers below and acknowledges each one |

**Halt layers in the enforcement point.** A halt blocks and denies everything the agent tries afterwards, rather than killing the process: this is the guarantee (requirement KIL-01). The further layers only deal with work already in flight.

1. Close the gate: every governed call and interaction is denied from this moment. Effective within microseconds of receipt (spike S1).
2. Interrupt the work in flight where the framework allows it, through the framework's own cancellation. Asynchronous work stops within milliseconds; blocking calls cannot be stopped from inside the process (S1).
3. Terminate the agent process only when the agent's halt mode is `terminate`, chosen by its owner. Otherwise the in-flight action is left to finish, and the gate denies whatever the agent tries next.
4. Report in the acknowledgement what happened at each layer, including "in-flight action not interrupted".

**Microsoft AGT and other in-process toolkits.** An interoperability adapter for organizations that already run AGT is a Phase 2 candidate: White Tower as an external backend of AGT's policy evaluator, AGT's events forwarded as supplementary evidence, and halts relayed to AGT's kill switch callbacks. AGT is re-tested live during the pilot (P1-14).

### 6.2 Network quarantine on Kubernetes

The gate lives in the agent's process, so it depends on that process behaving. For agents running on Kubernetes, the **network quarantine module** adds a layer that does not (requirement KIL-10, plan P1-15):

- **What it is.** A small Go controller, deployed once per cluster, with the `runtime-control` capability. Like an enforcement point, it watches the governance state of the agents it covers and acknowledges halts; unlike one, it evaluates no policy.
- **How it isolates.** Agents' pods carry the label `whitetower.io/agent-id`. When an agent is halted, by an agent, selector or fleet halt, the controller creates a cluster-wide deny rule selecting that label. Pods lose all traffic except what the halt needs: egress to the core's machine listener, so the in-process enforcement point can still acknowledge, deliver its evidence and learn of the release, and the node's health probes, so the pod is not restarted.
- **No race with new pods.** The rule selects on the agent's label, not on individual pods, so a pod started later for a halted agent is isolated from its start.
- **Reporting.** The controller acknowledges the halt with the layer `network_quarantined` and the number of pods covered. Releasing the halt removes the rule. The controller never lifts a quarantine without fresh state from the core, even after a restart or a lost connection.
- **Keeps the evidence.** The workload keeps running, isolated, so it can be investigated. Stopping workloads arrives with the harness module in Phase 2.
- **Requires a CNI that enforces deny rules** above ordinary network policies: Cilium (the reference, tested in CI), Calico, Antrea, or a CNI implementing AdminNetworkPolicy. Standard Kubernetes network policies can only add permissions, so they cannot quarantine.
- **Limits.** Pods without the agent label are not covered; the console shows the pods found per agent. On some CNIs, connections opened before the rule may survive until they close; the gate still denies whatever the agent does through them.

## 7. Data model overview

Sketch of the main entities. The full model is in the [domain model](domain-model.md), and the lifecycle in [lifecycle](lifecycle.md) (plan P0-02).

```mermaid
erDiagram
    PRINCIPAL ||--o{ AGENT_OWNERSHIP : holds
    AGENT ||--|{ AGENT_OWNERSHIP : "owned by"
    USE_CASE ||--o{ AGENT : justifies
    AGENT ||--o{ LIFECYCLE_TRANSITION : "history of"
    AGENT ||--o{ REVIEW : "reviewed in"
    AGENT ||--o{ CREDENTIAL : "authenticates with"
    POLICY ||--|{ POLICY_VERSION : has
    POLICY_VERSION ||--o{ APPROVAL : "approved by"
    AGENT ||--o{ POLICY : "scoped to (agent-specific)"
    AGENT ||--o{ BUNDLE : "effective set"
    AGENT ||--|| GOVERNANCE_STATE : "published as"
    MODULE ||--o{ MODULE_INSTANCE : runs
    MODULE_INSTANCE }o--o{ AGENT : enforces
    HALT ||--o{ HALT_ACK : "confirmed by"
    MODULE_INSTANCE ||--o{ HALT_ACK : sends
    AUDIT_EVENT }o--|| CHECKPOINT : "covered by"
```

Identifiers are UUIDv7. Governance records are never deleted; they are retired. Every table that the console edits has a version column for optimistic concurrency.

## 8. Deployment

### 8.1 Development and evaluation (Docker Compose)

| Service | Purpose |
| --- | --- |
| `whitetower` | The core, with the console embedded |
| `postgres` | Database |
| `keycloak` | Development IdP with one test user per role (never used in production) |
| `mock-module` | Reference enforcement point for tests and demos |
| `demo-agent` | A sample agent governed by White Tower's enforcement point |
| `otel-collector` (optional) | Receives the audit export to show the SIEM path |

The goal is a working demo within fifteen minutes of cloning the repository (OPS-01).

### 8.2 Kubernetes (Helm)

- Core `Deployment` with at least two replicas, a pod disruption budget, restricted security context, read-only root filesystem, and a non-root distroless image.
- External PostgreSQL; CloudNativePG documented as the reference operator.
- Signing keys (tokens, bundles, checkpoints) as three separate Secrets mounted as files.
- Network policies: the console listener reachable from the corporate network, the machine listener from agent networks, the operations listener from the cluster only.
- Database migrations run by `whitetower migrate` in an init container, with the migration role's credentials, under an advisory lock; the serving container holds only the runtime role's (threat model, DC-3).
- The network quarantine module: a separate chart, one `Deployment` per cluster with two replicas and leader election, allowed to manage only its deny rules and to read pods; plus the deny rule template for the cluster's CNI.

### 8.3 Air-gapped installation

An offline bundle contains the images as OCI archives, the Helm chart, SBOMs, signatures, checksums and documentation. Signatures can be verified offline with cosign. The core makes no outbound connection unless configured, and the console loads no external resource (NFR-14).

## 9. Cross-cutting concerns

| Concern | Approach |
| --- | --- |
| Transport security | TLS 1.2 or later on every listener except the cluster-internal operations one; HTTP Strict Transport Security; mutual TLS optional on the machine listener |
| Keys | Three separate signing keys: tokens (ES256), bundles (Ed25519), audit checkpoints (Ed25519). Read from files, rotated with overlap, public halves published. KMS and HSM backends later. |
| Console security | Strict Content Security Policy, `__Host-` session cookie, CSRF token, no tokens in JavaScript ([ADR-0009](../adr/0009-human-auth-bff-sessions.md)) |
| Abuse protection | Rate limits on login, token endpoint and event ingestion; request size limits; backpressure on ingestion |
| Observability | Prometheus metrics prefixed `whitetower_`; OpenTelemetry traces, exported only if configured; JSON logs with request and trace IDs |
| Configuration | One YAML file plus `WT_`-prefixed environment variables; secrets always from files |
| High availability | Stateless replicas; jobs elected through advisory locks; watch streams served by any replica and fed through `LISTEN/NOTIFY` |
| Time | UTC everywhere; the server stamps ingestion time; leases use monotonic clocks |
| Errors | RFC 9457 problem details on the REST API; ConnectRPC error codes on the module API |
| Localization | Console only (English and Spanish at MVP); the API returns stable error codes with English messages |

## 10. Technology summary

| Area | Choice | Decided in |
| --- | --- | --- |
| Backend language | Go (latest stable) | ADR-0001 |
| REST API | OpenAPI 3.1, `oapi-codegen`, standard library `net/http` | ADR-0004 |
| Module API | Protocol Buffers, ConnectRPC, Buf | ADR-0004 |
| Events and manifests | CloudEvents 1.0 and JSON Schema | ADR-0004 |
| Database | PostgreSQL 16 or later, `pgx`, `sqlc`, `goose` | ADR-0003 |
| Audit log | RFC 6962 Merkle tree (`golang.org/x/mod/sumdb/tlog`), C2SP signed checkpoints | ADR-0006 |
| Human authentication | OIDC through a backend-for-frontend, server-side sessions | ADR-0009 |
| Machine authentication | OAuth 2.0 client credentials with `private_key_jwt`, RFC 9068 JWTs | ADR-0010 |
| Frontend | TypeScript, React, Vite, TanStack, shadcn/ui, Tailwind CSS, Monaco | ADR-0002 |
| CLI | Go with `cobra` | ADR-0001 |
| Telemetry | OpenTelemetry, Prometheus | ADR-0004 |
| Build and release | Taskfile, GoReleaser, distroless images, Syft SBOMs, cosign signatures | ADR-0007, plan P0-01 |
| Enforcement point | Python package on `cedarpy`, with framework hooks | ADR-0011, plan P1-09 |
| Network quarantine | Go controller with `client-go`; CNI deny rules, Cilium as the reference | Plan P1-15 |
| Deployment | Docker Compose, Helm | Plan P1-12 |

## 11. Build or integrate

White Tower invents no new security mechanism. Its value is the coordinating layer that no open-source project provides: one inventory, one governance model and one place to stop agents, across tools that already exist. The rule is to integrate existing tools and standards, and to build only the coordination, or what no integrable component can guarantee.

| White Tower integrates | For |
| --- | --- |
| The organization's IdP (OIDC; SAML through a broker such as Keycloak) | Human identities and roles |
| PostgreSQL | All state |
| Cedar and OPA engines | Policy evaluation |
| OpenTelemetry collectors and the organization's SIEM | Telemetry and evidence export |
| Sigstore, SPDX and CycloneDX tooling | Signed, verifiable releases |
| Kubernetes, container runtimes and CNIs (Cilium, Calico, Antrea) | Running and isolating workloads; the CNI enforces the network quarantine |
| LLM and MCP gateways (Phase 2) | Choke points for model and tool calls |
| Agent frameworks, through their own hooks | Enforcement inside the agent |

| White Tower builds: the coordinating layer | Why no existing tool covers it |
| --- | --- |
| Inventory, ownership and lifecycle | Commercial platforms only govern their own ecosystem; nothing open covers all agents |
| Policy model: two levels, approvals, signed bundles | Engines evaluate policies; none manages who approves them and where they apply |
| Governance state distribution with fail-closed leases | Each tool has its own control loop; none gives one enforcement model across them |
| Halt orchestration with layered confirmation | Toolkits stop agents inside their own process; none stops and confirms across layers |
| Evidence across every tool, verifiable by third parties | Each tool keeps its own logs; none anchors them together |
| Module contracts and the conformance kit | The standards exist; the contract that binds them does not |

| White Tower builds, because nothing integrable gives the guarantee | Recorded in |
| --- | --- |
| A narrow OAuth token issuer for machines | [ADR-0010](../adr/0010-built-in-agent-token-issuer.md): issuance must see halts and lifecycle states atomically |
| The tamper-evident audit log, on a standard transparency-log library | [ADR-0006](../adr/0006-tamper-evident-audit-log.md): evidence must stay verifiable against a privileged insider without another stateful component |
| A small enforcement point in Python | [ADR-0011](../adr/0011-own-python-enforcement-point.md), after [spike S1](../spikes/S1-agt.md): the existing toolkit offers no gate, no loss-free evidence and no honest halt confirmation |

Anything added to the "builds" tables needs an ADR explaining why integration was not enough.

## 12. Prepared for later phases

| Later capability | Hook in the MVP |
| --- | --- |
| MCP and LLM gateways (Phase 2) | They become enforcement points using the same watch contract, and call a decision point through AuthZEN; agent tokens are already audience-bound |
| Second policy engine (Phase 2) | Combination semantics and test vectors are part of the contract, not of any engine |
| Harness module (Phase 2) | Stopping or restarting workloads (scale to zero, container kill), on top of the MVP's network quarantine; both act outside the agent's process |
| Microsoft AGT and other toolkits (Phase 2) | Interoperability adapters that plug into the same contracts ([ADR-0011](../adr/0011-own-python-enforcement-point.md)) |
| Strict mode for critical agents (Phase 2) | Synchronous decision per action, as an option of the watch contract |
| Message broker (if needed) | Events and notifications sit behind interfaces |
| External identity sources | SPIRE, Kubernetes workload identity and external issuers plug into the token endpoint |
| Discovery (Phase 3) | Inventory accepts agents with a `discovered` source |

## 13. Architecture risks

| Risk | Mitigation |
| --- | --- |
| White Tower's own enforcement point runs inside other people's agents and must follow each framework's releases ([ADR-0011](../adr/0011-own-python-enforcement-point.md)) | Small scope on a proven evaluator (`cedarpy`); conformance kit; weekly CI against the frameworks' latest releases; network quarantine as an independent layer on Kubernetes |
| The contracts end up shaped like White Tower's own enforcement point | P0-03 maps them onto AGT, OPA, Cedar and an AuthZEN engine before the RFC |
| A candidate engine changes hands (Galileo Agent Control, named in the charter, was acquired by Cisco in 2026) | Engine-neutral contracts and standard policy languages (Cedar, Rego), as the charter's risk table foresaw |
| A compromised enforcement point fakes acknowledgements | Halts also stop token issuance for every audience but the module API; the console flags instances that keep acting after a halt; on Kubernetes, network quarantine isolates the agent regardless (KIL-10); the Phase 2 harness module adds another independent stop |
| Network quarantine depends on the cluster's CNI | Cilium as the reference, tested in CI; templates for Calico, Antrea and AdminNetworkPolicy; the console shows the layer as unavailable where the CNI cannot deny |
| The sealer limits audit throughput | Spike S3: at 2,000 events per second the sealer was busy 18% of the time, with a p99 sealing delay of 341 ms, and it kept up at 10,000 per second ([S3](../spikes/S3-audit-throughput.md)) |
| Fail-closed turns core outages into fleet outages | High availability, TTL tuned per risk tier, alerting on lease health; documented as an accepted trade-off (ADR-0005) |
| Contracts change often during the alpha | `v1alpha1` label, RFC process, breaking-change checks in CI |
