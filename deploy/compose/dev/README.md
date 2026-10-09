# Development services

Local services for development and evaluation, started with `task dev` (see [docs/development.md](../../../docs/development.md)). **Every credential here is for local development only**; none of them may be reused anywhere else.

| Service | Address | Credentials |
| --- | --- | --- |
| PostgreSQL | `127.0.0.1:5432`, database `whitetower` | Superuser, for administration: `whitetower` / `whitetower-dev-only`. Roles of the deployment: see below |
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

## Database roles

[`postgres/roles.sql`](postgres/roles.sql) creates the roles of a deployment when PostgreSQL starts on an empty volume. Their passwords are in `secrets/`, mounted as files under `/run/secrets` as a Kubernetes Secret would be.

| Role | Password | Used by |
| --- | --- | --- |
| `whitetower_migrator` | `whitetower-migrator-dev-only` | `whitetower migrate`: the one-off `migrate` service of the `core` profile, and `task migrate`. It owns the schema |
| `whitetower_app` | `whitetower-app-dev-only` | The core. It belongs to `whitetower_runtime`, which may read and write data but never change the schema |

A volume created before these roles existed lacks them: `docker compose down --volumes` deletes it, with the development data, and the next start creates the roles.

## Audit checkpoint key

The core signs the checkpoints of its audit log with the Ed25519 key in `secrets/audit-checkpoint-key`, under the origin `whitetower.localhost/audit`. The key is public and for development only. A deployment makes its own, and keeps it apart from the database's backups:

```sh
openssl genpkey -algorithm ed25519 -out audit-checkpoint-key.pem
```

## Traces from the core

The core exports no trace by default. To send them to the collector, which prints what it receives, add `WT_TRACING_OTLP_ENDPOINT=http://otel-collector:4318` to `.env` and start both profiles:

```sh
docker compose --profile core --profile otel up -d --build
docker compose logs -f otel-collector
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
