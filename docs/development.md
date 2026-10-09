# Development guide

How to build, run and test White Tower on Windows, macOS and Linux.

## Prerequisites

| Tool | Version | Used for | Notes |
| --- | --- | --- | --- |
| [Go](https://go.dev/dl/) | Any release from 1.21 | Core, CLI, code generation | The repository pins its toolchain (`toolchain` in `go.mod`). Go downloads that exact version automatically on first use, into the module cache (`go env GOMODCACHE`); nothing is installed system-wide. |
| [Node.js](https://nodejs.org/) | 22.12 or later | Console | `.nvmrc` holds the major version for nvm users. |
| [pnpm](https://pnpm.io/) | 12 | Console packages | `npm install --global pnpm@12`. Old standalone pnpm executables cannot switch to the pinned version; update them, or pass `PNPM="npx --yes pnpm@12.6.0"` to Task. |
| [Docker](https://docs.docker.com/get-docker/) | Docker Desktop, or Docker Engine with Compose v2 | Development services, end-to-end tests | On Windows, use the WSL 2 backend. |
| [Task](https://taskfile.dev/) | Optional | Task runner | Without it, run `go tool -modfile=hack/tools/go.mod task <name>`. |
| [golangci-lint](https://golangci-lint.run/welcome/install/) | v2.14 | `task lint:go` | Install the binary; do not use `go install`. |

**Pinned tools.** These need no installation: Task, Buf, `protoc-gen-go`, `protoc-gen-connect-go`, `oapi-codegen` and `govulncheck` are pinned in `hack/tools/go.mod`. They are compiled on first use and cached, and the Taskfile calls them through `go tool`.

**Running White Tower needs none of this.** A release is one binary, or one container image, with the console embedded.

## First run

```sh
git clone https://github.com/J466Y/WhiteTower.git
cd WhiteTower
task setup    # Go modules, pinned tools, console packages
task dev      # PostgreSQL and Keycloak, in Docker
task run      # migrates the database, then runs the core from source
```

The core serves a self-signed certificate made at startup, which is for development only. Open <https://127.0.0.1:8443> and accept the browser's warning: the page shows the server's version. Check it from the CLI too:

```sh
go run ./cmd/wtctl version --insecure-skip-tls-verify --server https://127.0.0.1:8443
```

`task run` serves a placeholder page; [Working on the console](#working-on-the-console) shows how to run the real console. `task build` builds both into `bin/whitetower`, with the CLI next to it.

The core has three listeners: the console and public API on `127.0.0.1:8443`, the module API on `127.0.0.1:9443`, and operations on `http://127.0.0.1:9090`, with `/healthz`, `/readyz` and `/metrics`. Its settings are in the [configuration reference](reference/configuration.md); `whitetower config print` shows the effective values.

## Everyday tasks

| Task | What it does |
| --- | --- |
| `task gen` | Regenerates code from the contracts in `api/` |
| `task build` | Builds the console and the binaries into `bin/` |
| `task test` | Runs the Go and console unit tests |
| `task lint` | Runs `go vet`, golangci-lint, Biome, the TypeScript compiler and `buf lint` |
| `task fmt` | Formats Go and console code |
| `task vuln` | Checks Go dependencies for reachable known vulnerabilities |
| `task run` | Migrates the development database, then runs the core from source with a development certificate and a placeholder console |
| `task migrate` | Applies the database migrations to the development database |
| `task dev` | Starts PostgreSQL and Keycloak in Docker |
| `task dev:web` | Runs the console with live reload |
| `task dev:down` | Stops the development services |
| `task e2e` | Runs the end-to-end tests against a running core |

`task --list` shows them all.

## Working on the console

Use two terminals:

```sh
task run       # core on https://127.0.0.1:8443
task dev:web   # console on http://localhost:5173, with live reload
```

Vite forwards `/api` and `/auth` to the core, accepting its development certificate. The console's API types come from the OpenAPI document: after changing `api/openapi/openapi.yaml`, run `task gen`.

## Development services

`task dev` starts PostgreSQL and Keycloak. Keycloak comes with one test user per role. Addresses, users and credentials, all for local use only, are in [deploy/compose/dev/README.md](../deploy/compose/dev/README.md).

PostgreSQL has the roles of a deployment. `whitetower_migrator` owns the schema, and only `whitetower migrate` uses it. The core connects as `whitetower_app`, which may read and write data but never change the schema ([threat model](security/threat-model.md), DC-3). The roles are created when the database starts on an empty volume. A volume from before October 2026 lacks them: recreate it with `docker compose -f deploy/compose/dev/compose.yaml down --volumes`, which deletes the development data.

To run the core in Docker as well, built from source, after a one-off `migrate` service:

```sh
docker compose -f deploy/compose/dev/compose.yaml --profile core up -d --build
```

## Logs, metrics and traces

- **Logs** are JSON lines on standard output. The records of a request carry its `request_id`, which the response returns in `X-Request-Id`, and its `trace_id`.
- **Metrics** are at <http://127.0.0.1:9090/metrics>. White Tower's own are prefixed `whitetower_`.
- **Traces** stay in the process unless `tracing.otlp.endpoint` names an OTLP/HTTP receiver. To see them, start the development collector, which prints what it receives, and point the core at it:

  ```sh
  docker compose -f deploy/compose/dev/compose.yaml --profile otel up -d
  WT_TRACING_OTLP_ENDPOINT=http://127.0.0.1:4318 task run
  docker compose -f deploy/compose/dev/compose.yaml logs -f otel-collector
  ```

  On Windows, set the variable first: `$env:WT_TRACING_OTLP_ENDPOINT = "http://127.0.0.1:4318"`. For the core in Docker, start both profiles with `WT_TRACING_OTLP_ENDPOINT=http://otel-collector:4318` in `deploy/compose/dev/.env`.

## Generated code

The contracts in `api/` are the source of truth ([ADR-0004](adr/0004-api-and-contract-formats.md)). `task gen` writes:

| Contract | Generated code |
| --- | --- |
| `api/openapi/openapi.yaml` | `internal/api/rest/gen` (Go server), `pkg/apiclient` (Go client), `web/src/api/schema.gen.ts` (console types) |
| `api/proto/**` | `pkg/moduleapi` (Go messages and ConnectRPC services) |

Commit the generated code with the contract change. Never edit it by hand: CI regenerates it and fails on any difference.

The server serves the OpenAPI document at `/api/v1/openapi.json`. The API's errors, and the conventions for lists and updates, are in the [errors reference](reference/api-errors.md).

## Tests

The test helpers, and how a package writes its tests, are in [internals](development/internals.md#writing-tests).

- **Unit tests:** `task test`.
- **Database tests:** they start PostgreSQL in Docker with testcontainers, through `internal/platform/db/dbtest`, which gives each test a fresh database with the roles of a deployment. Without Docker they are skipped, except in CI, where they fail. `WT_TEST_POSTGRES_IMAGE` picks another PostgreSQL version, for example `postgres:16-alpine`.
- **End-to-end tests:** start a core that serves the built console (`task build` then `./bin/whitetower serve` with a development certificate, or the Compose `core` profile), then run `task e2e`. The browser test needs Chromium, installed once with `pnpm --dir web exec playwright install chromium`. Set `WT_E2E_URL`, `WT_E2E_MACHINE_URL` and `WT_E2E_OPERATIONS_URL` to test another deployment.
- **Race detector:** `go test -race ./...` needs cgo (a C compiler). CI runs it on Linux.

## Repository layout

| Directory | Content |
| --- | --- |
| `api/` | Contracts: OpenAPI, protobuf, event catalog, manifest schema |
| `cmd/` | Entry points: `whitetower` (core), `wtctl` (CLI) |
| `internal/` | Core packages, not importable by other modules |
| `pkg/` | Public Go packages: API client, module API code |
| `web/` | Console (React, Vite, pnpm) |
| `deploy/` | Dockerfiles and Docker Compose setups; the Helm chart comes in plan P1-12 |
| `test/` | End-to-end tests |
| `hack/` | Pinned development tools and throwaway spikes |
| `docs/` | Requirements, architecture, ADRs, plans, RFCs |

The reasoning behind the layout is in [ADR-0007](adr/0007-monorepo-layout.md). The packages of the core, and the rules they follow, are in [internals](development/internals.md).

## Windows notes

- `.gitattributes` keeps LF line endings on every platform. Use an editor that honors `.editorconfig`.
- Binaries get the `.exe` suffix; Task adds it for you.
- Docker Desktop must be running for `task dev` and the end-to-end tests.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `go: ... requires go >= 1.27.1; switching to go1.27.1` | Expected: Go is fetching the pinned toolchain. It happens once. |
| `ERR_PNPM_... Command "...\pnpm.cjs" not found` | An old standalone pnpm failed to switch to pnpm 12. Install pnpm 12 with npm, or pass `PNPM="npx --yes pnpm@12.6.0"` to Task. |
| `corepack` fails with a signature or key error | The corepack bundled with Node.js 22.12 has outdated signing keys. Install pnpm with npm instead. |
| `The console is not built` when running `task build:go` | Run `task build`, which builds the console first. |
| `bind: An attempt was made to access a socket in a way forbidden by its access permissions` | Windows reserves port ranges for Hyper-V, and they can change after a restart: `netsh interface ipv4 show excludedportrange protocol=tcp` lists them. Choose a port outside them: `WT_CONSOLE_PORT` and the like in `deploy/compose/dev/.env` for Compose, or `WT_LISTENERS_CONSOLE_ADDRESS` for the binary. |
