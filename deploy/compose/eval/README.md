# Evaluation stack

Local demonstration and evaluation environment for White Tower (OPS-01, P1-12.1).

It runs the core control plane together with PostgreSQL, Keycloak (OIDC IdP with test governance roles), an OpenTelemetry collector, and automatically seeds sample agents, use cases, and principals across different governance lifecycle states.

## Quick start

To start the full evaluation stack:

```sh
task eval
```

Or using Docker Compose directly:

```sh
docker compose -f deploy/compose/eval/compose.yaml up -d --wait
```

Once running:
- **Console & API:** `https://127.0.0.1:8443`
- **Module API:** `https://127.0.0.1:9443`
- **Health & Prometheus metrics:** `http://127.0.0.1:9090`
- **Keycloak Admin:** `http://127.0.0.1:8180` (admin / `admin-dev-only`)
- **OpenTelemetry Collector:** `127.0.0.1:4317` (gRPC), `127.0.0.1:4318` (HTTP)

To follow the guided walkthrough, see [Fifteen-minute demo](../../../docs/guides/fifteen-minute-demo.md).

## Test users

Realm `whitetower` comes pre-configured with users for each governance role. All test user passwords are `whitetower`:

| Username | Role | Access |
| --- | --- | --- |
| `owner` | Agent Owner | Propose agents, manage owned agents and view audit events |
| `advisory` | AI Advisory Committee | Validate use cases, approve agent-specific policies, suspend agents |
| `steering` | AI Steering Committee | Approve global policies, issue fleet-wide halts |
| `operator` | Platform Operator | Activate agents, register modules, issue halts |
| `auditor` | Auditor | Read-only inspection of inventory, signed checkpoints and audit log |
| `admin` | Administrator | System settings and user role bindings |

## Stopping the stack

```sh
task eval:down
```

To delete the evaluation database and reset all data:

```sh
task eval:down -- -v
```
