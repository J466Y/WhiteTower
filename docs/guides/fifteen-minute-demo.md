# The fifteen-minute demo (OPS-01)

| | |
| --- | --- |
| **Status** | Implementation guide for Phase 1 MVP (P1-12.1) |
| **Requirements** | OPS-01, AUD-04, AUD-06, AUD-09 |
| **Compose profile** | [`deploy/compose/eval`](../../deploy/compose/eval/) |

This guide walks through evaluating White Tower on a laptop in fifteen minutes: starting the stack, signing in with governance roles, inspecting the pre-seeded inventory across lifecycle states, querying the tamper-evident audit log, and verifying cryptographic Merkle tree inclusion proofs.

As the project grows, this guide expands: P1-12.1 ships it with the core, PostgreSQL, Keycloak, OpenTelemetry and seed data; the mock module (P1-07) and the demo agent (P1-09) join as they become available, and P1-12.2 finalizes runtime control and halt drills.

Until the console is built (plan P1-10), its page shows only the server's version. The guide reads the API in the browser instead: you sign in once, and the browser sends your session with every page you open. Every step of the guide is a `GET`.

---

## 1. Prerequisites

- Docker and Docker Compose (v2.20+)
- [Task](https://taskfile.dev) (or run commands via `go tool -modfile=hack/tools/go.mod task <cmd>`)
- A web browser
- `curl`, for the health check only

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
2. **Keycloak 26** (`http://127.0.0.1:8180`): OpenID Connect IdP pre-configured with realm `whitetower` and governance users.
3. **OpenTelemetry Collector** (`127.0.0.1:4317` gRPC, `4318` HTTP): captures traces and telemetry.
4. **White Tower Core** (`https://127.0.0.1:8443` console, `https://127.0.0.1:9443` module API, `http://127.0.0.1:9090` operations): running with a read-only root filesystem and dropped capabilities.
5. **Seed Service**: populates initial evaluation principals, use cases, agents, and ownerships.

Verify the core is ready:

```sh
curl -s http://127.0.0.1:9090/healthz
# Output: ok
```

Use `127.0.0.1` in every address of this guide, never `localhost`: the cookies of a sign-in belong to one host name, and Keycloak names itself `http://127.0.0.1:8180`. Signing in also needs the stack's default ports, which the realm and the seed name ([the stack's README](../../deploy/compose/eval/README.md#ports)).

---

## 3. Sign in

The stack's Keycloak imports the realm [`deploy/compose/eval/keycloak/whitetower-realm.json`](../../deploy/compose/eval/keycloak/whitetower-realm.json), with one user per role of the White Tower governance matrix. Every user's password is `whitetower`. The seed gives seven of them a principal in White Tower, and signing in as one of them finds that principal: Olivia Owner, signed in as `owner`, owns the sample agents.

| Username | Role | Primary responsibility | In this guide |
| --- | --- | --- | --- |
| `owner` | Agent Owner | Proposes agents, assigns metadata, monitors owned agents | Section 4: Olivia Owner owns the sample agents |
| `auditor` | Auditor | Inspects inventory, verifies cryptographic proofs and export | Sections 5 and 6: the audit log, its checkpoints and its keys |
| `advisory` | AI Advisory Committee | Validates use cases, approves policies, reviews high-risk agents | |
| `steering` | AI Steering Committee | Approves global policies, issues fleet-wide halts | |
| `operator` | Platform Operator | Activates agents, manages modules, emergency response | |
| `user` | User | Uses the agents that the organization offers | |
| `admin` | Administrator | System configuration and role mappings | |
| `multirole` | Agent Owner and Platform Operator | A person with two roles | |
| `inactive` | none | An account that Keycloak disables: it cannot sign in | |

To sign in:

1. Open <https://127.0.0.1:8443/auth/login?return_url=/api/v1/me> and accept the self-signed evaluation certificate.
2. The core sends you to Keycloak's sign-in page. Sign in as `owner`, with the password `whitetower`.
3. Keycloak sends you back to the core, which opens your session and shows `/api/v1/me`: your principal, with its roles and permissions. As `owner`, it is Olivia Owner, the seeded principal `00000000-0000-7000-8000-000000000001`.

To change user, sign out first:

1. Open <https://127.0.0.1:8443/auth/logout>. The core ends its session, and Keycloak asks whether you want to log out of it too: choose **Logout**.
2. Keycloak sends you back to the console, at `https://127.0.0.1:8443/`. Sign in again as another user.

A terminal has no session to send: reading the API from a terminal waits for `wtctl login` (plan P1-11).

---

## 4. Explore pre-seeded inventory and lifecycle

Signed in as `owner`, open <https://127.0.0.1:8443/api/v1/agents>. The evaluation seed initializes sample agents across lifecycle states (`lifecycleState`):

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

The use cases are at <https://127.0.0.1:8443/api/v1/use-cases>. Every role may read the inventory, and `user` sees only the active agents.

---

## 5. Query the tamper-evident audit log

White Tower maintains an append-only, tamper-evident audit log structured in RFC 8785 canonical JSON and indexed into a Merkle tree.

Sign out, then sign in as `auditor`: an owner reads only the events of their own agents, and `admin` and `user` read no audit data. Open <https://127.0.0.1:8443/api/v1/audit/events?limit=5>, the most recent events first.

On a fresh stack the first query can answer `{"events":[]}`: signing in records no event, and a read records itself once it has run. Reload the page. The log now shows the record of your first read: reading the audit log is itself audited (**AUD-09**), and every read emits a `whitetower.audit.read.v1` event that records who read the log, how, and with which filters. Once a checkpoint is signed, its `whitetower.audit.checkpoint.v1` event joins the list.

---

## 6. Cryptographic verification

White Tower periodically seals events into a Merkle tree and signs C2SP checkpoints with Ed25519 keys. The first checkpoint follows the first event; the next ones come about once a minute while the log grows. Stay signed in as `auditor` for this section.

### 6.1 Inspect signed checkpoints

Open <https://127.0.0.1:8443/api/v1/audit/checkpoints>. Each checkpoint contains:
- `treeSize`: number of leaves committed.
- `rootHash`: base64 SHA-256 root hash of the log.
- `note`: complete signed note in C2SP format.

### 6.2 Inspect public verification keys

Open <https://127.0.0.1:8443/api/v1/audit/keys>. It returns the public halves of the checkpoint signing keys as standard RFC 7517 JWKs (`kty: OKP`, `crv: Ed25519`).

### 6.3 Inclusion proof of an audit event

1. In the list of section 5, take the last event, the oldest, and copy the event's own `id`, which follows its `data` in the raw JSON: not its `actorId`, nor the `id` of `data.actor`.
2. Open `https://127.0.0.1:8443/api/v1/audit/events/<id>`, with the ID in place of `<id>`.

The response holds the `event` and, once a signed checkpoint covers it, its `proof`:
- `proof.leafIndex`: position in the Merkle tree.
- `proof.hashes`: audit path of sibling hashes.
- `proof.checkpoint`: signed checkpoint note against which the proof holds.

An event newer than the last checkpoint has no `proof` yet: wait a minute and reload.

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
