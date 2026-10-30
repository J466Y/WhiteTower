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

## Signing in

Open <https://127.0.0.1:8443/auth/login> and sign in at Keycloak as one of the test users below; <https://127.0.0.1:8443/auth/logout> signs out of the core and of Keycloak. Use `127.0.0.1`, never `localhost`: the cookies of a sign-in belong to one host name.

Browsers reach Keycloak at `http://127.0.0.1:8180`, the issuer of its tokens (`KC_HOSTNAME`), while the core reaches it inside Docker's network at `http://keycloak:8080`, its discovery URL (`WT_AUTH_OIDC_DISCOVERY_URL`). The core asks for the scopes `openid`, `profile` and `email` only: Keycloak defines no `groups` scope and refuses a request for one, while the client's own mapper already puts the groups in the ID token.

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
| `user` | User | Use the agents that the organization offers |
| `multirole` | Agent Owner and Platform Operator | A person with two roles |
| `inactive` | none | An account that Keycloak disables: it cannot sign in |

Each user has a fixed ID in the realm, which Keycloak puts in the `sub` of its tokens. The seed (`seed/seed.sql`) gives the first seven users a principal whose issuer is the core's and whose subject is that ID, so signing in as `owner` is the seeded Olivia Owner, with her agents and role bindings.

## Ports

The stack takes the host port variables of the [development services](../dev/README.md#ports-already-in-use), such as `WT_POSTGRES_PORT`, but sign-in depends on two of them:

- **`WT_CONSOLE_PORT`** must stay at 8443: the realm registers the core's callback on that port only, and Keycloak refuses another.
- **`WT_KEYCLOAK_PORT`** may change, and the issuer follows it, but the seed's principals keep the issuer of port 8180: the people who sign in then become new principals, without the seeded agents and role bindings.

## Stopping the stack

```sh
task eval:down
```

To delete the evaluation database and reset all data:

```sh
task eval:down -- -v
```
