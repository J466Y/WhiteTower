# Development services

Local services for development and evaluation, started with `task dev` (see [docs/development.md](../../../docs/development.md)). **Every credential here is for local development only**; none of them may be reused anywhere else.

| Service | Address | Credentials |
| --- | --- | --- |
| PostgreSQL | `127.0.0.1:5432`, database `whitetower` | `whitetower` / `whitetower-dev-only` |
| Keycloak | `http://127.0.0.1:8180`, realm `whitetower` | Administration console: `admin` / `admin-dev-only` |
| Core (profile `core`) | Console and API `https://127.0.0.1:8443`; module API `https://127.0.0.1:9443`; health and metrics `http://127.0.0.1:9090` | none yet. The certificate is self-signed, made at startup |
| OpenTelemetry collector (profile `otel`) | OTLP gRPC `127.0.0.1:4317`, HTTP `127.0.0.1:4318` | none |

## Ports already in use

Each host port can be changed without editing the Compose file: create a `.env` file next to `compose.yaml` (it is ignored by Git) with the variables you need.

```sh
# deploy/compose/dev/.env
WT_POSTGRES_PORT=15432
WT_KEYCLOAK_PORT=8180
WT_CONSOLE_PORT=8443
WT_MACHINE_PORT=9443
WT_OPERATIONS_PORT=9090
WT_OTLP_GRPC_PORT=4317
WT_OTLP_HTTP_PORT=4318
```

## Test users

Realm `whitetower` has one user per role of the [permission matrix](../../../docs/requirements/mvp-requirements.md#521-permission-matrix-initial-refined-in-plan-p1-03), each in the matching group. The password of every user is `whitetower`.

| User | Group | Role |
| --- | --- | --- |
| `steering` | `wt-steering` | AI steering committee |
| `advisory` | `wt-advisory` | AI advisory committee |
| `owner` | `wt-owners` | Agent owner |
| `user` | `wt-users` | User |
| `operator` | `wt-operators` | Platform operator |
| `auditor` | `wt-auditors` | Auditor |
| `admin` | `wt-admins` | Platform administrator |

Tokens carry the groups in a `groups` claim, which plan P1-03 maps to roles.

## OIDC clients

| Client | Type | Used by |
| --- | --- | --- |
| `whitetower-console` | Confidential, authorization code with PKCE; secret `whitetower-console-dev-only` | The core's backend-for-frontend login (plan P1-03) |
| `wtctl` | Public, authorization code with PKCE and loopback redirect | The CLI login (plan P1-11) |
