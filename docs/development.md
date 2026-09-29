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
task build    # console, then bin/whitetower and bin/wtctl
./bin/whitetower
```

On Windows, run `.\bin\whitetower.exe`. Open <http://127.0.0.1:8080>: the console shows the server's version. Check it from the CLI too:

```sh
./bin/wtctl version --server http://127.0.0.1:8080
```

## Everyday tasks

| Task | What it does |
| --- | --- |
| `task gen` | Regenerates code from the contracts in `api/` |
| `task build` | Builds the console and the binaries into `bin/` |
| `task test` | Runs the Go and console unit tests |
| `task lint` | Runs `go vet`, golangci-lint, Biome, the TypeScript compiler and `buf lint` |
| `task fmt` | Formats Go and console code |
| `task vuln` | Checks Go dependencies for reachable known vulnerabilities |
| `task run` | Runs the core from source, with a placeholder console |
| `task dev` | Starts PostgreSQL and Keycloak in Docker |
| `task dev:web` | Runs the console with live reload |
| `task dev:down` | Stops the development services |
| `task e2e` | Runs the end-to-end tests against a running core |

`task --list` shows them all.

## Working on the console

Use two terminals:

```sh
task run       # core on http://127.0.0.1:8080
task dev:web   # console on http://localhost:5173, with live reload
```

Vite forwards `/api`, `/auth` and `/healthz` to the core. The console's API types come from the OpenAPI document: after changing `api/openapi/openapi.yaml`, run `task gen`.

## Development services

`task dev` starts PostgreSQL and Keycloak. Keycloak comes with one test user per role. Addresses, users and credentials, all for local use only, are in [deploy/compose/dev/README.md](../deploy/compose/dev/README.md).

To run the core in Docker as well, built from source:

```sh
docker compose -f deploy/compose/dev/compose.yaml --profile core up -d --build
```

## Generated code

The contracts in `api/` are the source of truth ([ADR-0004](adr/0004-api-and-contract-formats.md)). `task gen` writes:

| Contract | Generated code |
| --- | --- |
| `api/openapi/openapi.yaml` | `internal/api/rest/gen` (Go server), `pkg/apiclient` (Go client), `web/src/api/schema.gen.ts` (console types) |
| `api/proto/**` | `pkg/moduleapi` (Go messages and ConnectRPC services) |

Commit the generated code with the contract change. Never edit it by hand: CI regenerates it and fails on any difference.

## Tests

- **Unit tests:** `task test`.
- **End-to-end tests:** start a core that serves the built console (`task build` then `./bin/whitetower`, or the Compose `core` profile), then run `task e2e`. The browser test needs Chromium, installed once with `pnpm --dir web exec playwright install chromium`. Set `WT_E2E_URL` to test another deployment.
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

The reasoning behind the layout is in [ADR-0007](adr/0007-monorepo-layout.md).

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
