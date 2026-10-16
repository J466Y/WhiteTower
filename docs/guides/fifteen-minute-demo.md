# The fifteen-minute demo (OPS-01)

| | |
| --- | --- |
| **Status** | Implementation guide for Phase 1 MVP (P1-12.1) |
| **Requirements** | OPS-01, AUD-04, AUD-06, AUD-09 |
| **Compose profile** | [`deploy/compose/eval`](../../deploy/compose/eval/) |

This guide walks through evaluating White Tower on a laptop in fifteen minutes: starting the stack, authenticating with governance roles, inspecting the pre-seeded inventory across lifecycle states, querying the tamper-evident audit log, and verifying cryptographic Merkle tree inclusion proofs.

As the project grows, this guide expands: P1-12.1 ships it with the core, PostgreSQL, Keycloak, OpenTelemetry and seed data; the mock module (P1-07) and the demo agent (P1-09) join as they become available, and P1-12.2 finalizes runtime control and halt drills.

---

## 1. Prerequisites

- Docker and Docker Compose (v2.20+)
- [Task](https://taskfile.dev) (or run commands via `go tool -modfile=hack/tools/go.mod task <cmd>`)
- `curl` (or your browser)

---

## 2. Start the evaluation stack

From the root of the repository:

```sh
task eval
```

Or using Docker Compose directly:

```sh
docker compose -f deploy/compose/eval/compose.yaml up -d --wait
```

Docker Compose spins up:
1. **PostgreSQL 17** (`127.0.0.1:5432`): database with migrated schema.
2. **Keycloak 26** (`127.0.0.1:8180`): OpenID Connect IdP pre-configured with realm `whitetower` and governance users.
3. **OpenTelemetry Collector** (`127.0.0.1:4317` gRPC, `4318` HTTP): captures traces and telemetry.
4. **White Tower Core** (`https://127.0.0.1:8443` console, `https://127.0.0.1:9443` module API, `http://127.0.0.1:9090` operations): running with a read-only root filesystem and dropped capabilities.
5. **Seed Service**: populates initial evaluation principals, use cases, agents, and ownerships.

Verify the core is ready:

```sh
curl -s http://127.0.0.1:9090/healthz
# Output: {"status":"ok"}
```

---

## 3. Governance roles and credentials

The evaluation realm provides pre-configured users for each role of the White Tower governance matrix. Every user's password is `whitetower`:

| Username | Role | Primary Responsibility |
| --- | --- | --- |
| `owner` | Agent Owner | Proposes agents, assigns metadata, monitors owned agents |
| `advisory` | AI Advisory Committee | Validates use cases, approves policies, reviews high-risk agents |
| `steering` | AI Steering Committee | Approves global policies, issues fleet-wide halts |
| `operator` | Platform Operator | Activates agents, manages modules, emergency response |
| `auditor` | Auditor | Inspects inventory, verifies cryptographic proofs and export |
| `admin` | Administrator | System configuration and role mappings |

You can log in to the web console by opening `https://127.0.0.1:8443` in your browser (accept the self-signed evaluation certificate) and clicking **Log in with Keycloak**.

---

## 4. Explore pre-seeded inventory and lifecycle

The evaluation seed initializes sample agents across lifecycle states:

1. **`support-bot-alpha` (State: `active`)**:
   - Primary owner: `Olivia Owner`
   - Use case: *Customer Support Triage* (validated)
   - Risk tier: `low` (EU AI Act classification: `limited`)
   - Framework: `langgraph`, deployed in `k8s-prod-eu`
2. **`portfolio-analyst-v1` (State: `proposed`)**:
   - Primary owner: `Olivia Owner`
   - Use case: *Financial Portfolio Risk Analyzer* (submitted, pending validation)
   - Risk tier: `high` (EU AI Act classification: `high_risk`)
3. **`doc-indexer` (State: `suspended`)**:
   - Primary owner: `Olivia Owner`
   - State: `suspended` (suspended from `active`, reason: `manual`)

---

## 5. Query the tamper-evident audit log

White Tower maintains an append-only, tamper-evident audit log structured in RFC 8785 canonical JSON and indexed into a Merkle tree.

Query recent audit events via the REST API:

```sh
curl -k -s "https://127.0.0.1:8443/api/v1/audit/events?limit=5"
```

Notice that reading the audit log is itself audited (**AUD-09**): every read emits a `whitetower.audit.read.v1` event recording who read the log and what query parameters were used.

---

## 6. Cryptographic verification

White Tower periodically seals events into a Merkle tree and signs C2SP checkpoints with Ed25519 keys.

### 6.1 Inspect signed checkpoints

```sh
curl -k -s "https://127.0.0.1:8443/api/v1/audit/checkpoints"
```

Each checkpoint contains:
- `treeSize`: number of leaves committed.
- `rootHash`: base64 SHA-256 root hash of the log.
- `note`: complete signed note in C2SP format.

### 6.2 Inspect public verification keys

```sh
curl -k -s "https://127.0.0.1:8443/api/v1/audit/keys"
```

Returns the public halves of the checkpoint signing keys as standard RFC 7517 JWKs (`kty: OKP`, `crv: Ed25519`).

### 6.3 Inclusion proof of an audit event

Retrieve an event detail with its mathematical proof:

```sh
# Fetch the ID of the first event
EVENT_ID=$(curl -k -s "https://127.0.0.1:8443/api/v1/audit/events?limit=1" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)

curl -k -s "https://127.0.0.1:8443/api/v1/audit/events/${EVENT_ID}"
```

The response includes the event along with:
- `proof.leafIndex`: position in the Merkle tree.
- `proof.hashes`: audit path of sibling hashes.
- `proof.checkpoint`: signed checkpoint note against which the proof holds.

The proof can be verified offline by external verifiers (or via `pkg/auditverify.CheckInclusion`) without trusting the database.

---

## 7. Teardown

Stop all containers while keeping data:

```sh
task eval:down
```

To clean up all evaluation volumes and reset data:

```sh
task eval:down -- -v
```
