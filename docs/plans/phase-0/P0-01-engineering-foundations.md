# P0-01: Engineering foundations

| | |
| --- | --- |
| **Phase** | 0 Foundations |
| **Status** | In progress (see [progress notes](#progress-notes)) |
| **Size** | M |
| **Depends on** | none |
| **Unblocks** | Every other plan; directly P1-01 and P1-12 |
| **Requirements** | NFR-13, NFR-18, NFR-21, CON-01, OPS-01 (development setup) |
| **Decisions** | ADR-0001, ADR-0002, ADR-0007, ADR-0008 |

## Goal

A repository where anyone can build, test, lint and release White Tower on Windows, macOS and Linux from the first day, with the project's governance documents in place. Feature work should never have to stop for tooling.

## Scope

**In:** repository layout, pinned toolchains, task runner, code generation pipeline, CI, dependency hygiene, a release pipeline that already signs artifacts and produces SBOMs, a Docker Compose development environment, community and governance files, repository settings.

**Out:** application features (Phase 1 plans), the Helm chart and air-gapped bundle (P1-12), security hardening of the product (P1-13).

## Deliverables

- Repository skeleton following ADR-0007, with a server that answers `/healthz` and a CLI that prints its version.
- `Taskfile.yml` with `setup`, `gen`, `build`, `test`, `lint`, `dev`, `e2e` and `release:snapshot`.
- CI workflows in `.github/workflows/`.
- Release configuration (GoReleaser) producing signed binaries and images with SBOMs and provenance.
- `deploy/compose/dev/` with PostgreSQL and Keycloak.
- `CONTRIBUTING.md`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `NOTICE`, `docs/rfcs/0000-template.md`, issue and pull request templates, `CODEOWNERS`.
- README updated: license section and links to the design documents.

## Steps

### 1. Fix the project identifiers

Decide and write down:

- the Go module path: a vanity path on a project domain, recommended because it survives a move to a foundation, or `github.com/J466Y/WhiteTower` (open question Q6);
- binary names (`whitetower`, `wtctl`), the protobuf package root (`whitetower.module.v1alpha1`), the CloudEvents type prefix (`whitetower.`), the manifest `apiVersion` and the container image names and registry (GitHub Container Registry by default).

If a domain is chosen, record it in an ADR, because changing the module path later breaks every importer.

**Done when:** the identifiers are listed in `CONTRIBUTING.md`.

### 2. Community and governance files

- `CONTRIBUTING.md`: development setup, workflow, Conventional Commits, DCO sign-off (`git commit -s`), pull request checklist (the definition of done in the plans index), where decisions go (ADR, RFC, requirements), dependency policy.
- `GOVERNANCE.md`: maintainer-led governance, roles, how maintainers are added and removed, decision making, and the RFC process for contract changes (a minimum review period of two weeks and approval by two maintainers).
- `CODE_OF_CONDUCT.md`: Contributor Covenant 2.1, with a contact address.
- `SECURITY.md`: private vulnerability reporting through GitHub, supported versions, response targets (acknowledgement within three working days).
- `NOTICE`, `docs/rfcs/0000-template.md`, issue templates (bug, feature, RFC proposal), pull request template, `CODEOWNERS` (two maintainer approvals for `api/**`).
- README: set the license section to Apache-2.0 and link the design documents.

**Done when:** the files are merged and linked from the README.

### 3. Repository skeleton

Create the layout of ADR-0007: `go.mod` with a `toolchain` line, `cmd/whitetower` serving `/healthz`, `cmd/wtctl` with a `version` command, empty `internal/` and `pkg/`, placeholder specifications under `api/`, `web/` from the Vite React TypeScript template reduced to a blank page, `deploy/compose/`, `test/` and `hack/`. Add `.gitattributes` (LF line endings, so Windows checkouts do not break generated files and scripts) and `.editorconfig`.

**Done when:** `go build ./...` and `pnpm -C web build` succeed on all three operating systems.

### 4. Toolchains and task runner

- Pin Go through the `toolchain` directive, Node.js LTS through `.nvmrc`, and pnpm through the `packageManager` field (installed by Corepack).
- Pin Go-based tools (oapi-codegen, sqlc, goose, buf) with `tool` directives in `go.mod`, so `go tool <name>` always runs the reviewed version. Install golangci-lint and GoReleaser as pinned binaries.
- Write `Taskfile.yml` with the tasks listed in the deliverables. Every task must work in PowerShell and in POSIX shells.

**Done when:** a new contributor runs `task setup` and then `task test` without installing anything else by hand, besides Go, Node.js, Docker and Task.

### 5. Code generation pipeline

`task gen` runs every generator: `oapi-codegen` (Go server interfaces in strict mode and a Go client), `openapi-typescript` (console types), `buf generate` (Go, plus Python for the enforcement point of ADR-0011, and TypeScript if needed) and `sqlc`. Generated code is committed. CI regenerates it and fails on any difference.

**Done when:** changing a placeholder operation in the OpenAPI document and running `task gen` updates Go and TypeScript code, and CI catches a forgotten regeneration.

### 6. Console skeleton

Vite with React and TypeScript in strict mode, Biome, Vitest and Playwright. Configure pnpm for supply-chain safety: a minimum release age for new versions (for example three days), dependency build scripts blocked unless allow-listed, and a frozen lockfile in CI. The Go binary embeds `web/dist` with `go:embed` and serves it with a strict Content Security Policy (`default-src 'self'`, no inline scripts or styles).

**Done when:** the embedded placeholder page loads from the Go binary with the CSP enforced and no external request in the browser's network panel.

### 7. Continuous integration

Workflows, each with path filters so a change only runs what it affects:

- **Go:** golangci-lint, tests with the race detector and coverage.
- **Console:** Biome, type check, Vitest, build.
- **Code generation:** drift check (step 5).
- **Contracts:** `buf lint`, and `buf breaking` against the latest `contracts/v*` tag (P0-03 changed it from `main`, following its versioning policy); Spectral and `oasdiff` for OpenAPI; JSON Schema validation of manifest and event examples (`test/contracts`, added in P0-03).
- **Security:** `govulncheck`, OSV-Scanner on the pnpm lockfile, CodeQL for Go and TypeScript, dependency review on pull requests, license checks (`go-licenses` and a pnpm license checker, following ADR-0008), secret scanning.
- **End to end:** Docker Compose smoke test.

Harden the workflows: actions pinned by commit SHA, read-only default permissions, no `pull_request_target` that checks out untrusted code, concurrency groups.

**Done when:** CI runs in under 15 minutes (NFR-18), and a deliberately breaking change in `api/proto` fails `buf breaking`.

### 8. Dependency hygiene

Configure Renovate (or Dependabot) with grouped updates, a minimum release age of three to seven days, and automatic merge only for patch updates of development dependencies. Builds use `-mod=readonly`. `CONTRIBUTING.md` states that a new runtime dependency needs a justification in its pull request.

**Done when:** the first batch of update pull requests arrives grouped and delayed as configured.

### 9. Release pipeline

GoReleaser builds:

- `wtctl` for Linux, macOS and Windows (amd64 and arm64), and `whitetower` for Linux (amd64 and arm64);
- multi-architecture images on a distroless, non-root base;
- checksums and SBOMs (Syft, in SPDX and CycloneDX);
- keyless cosign signatures and GitHub artifact attestations for build provenance (SLSA).

A nightly job produces snapshot builds; tags produce pre-releases. `docs/verify-release.md` explains how to verify a signature and an SBOM, including offline.

**Done when:** a snapshot release can be verified with the documented commands.

### 10. Development environment

`deploy/compose/dev/` starts PostgreSQL (16 and 17 selectable), Keycloak with a realm export containing one test user per role and a groups claim, the core built from source and an optional OpenTelemetry collector. `task dev` starts it all, and the Vite development server proxies `/api` and `/auth` to the core. `docs/development.md` covers Windows (Docker Desktop with WSL 2, line endings), macOS and Linux.

**Done when:** a contributor on each operating system reaches the placeholder console through `task dev` within fifteen minutes of cloning.

### 11. Repository settings

A maintainer with administrator rights sets branch protection on `main` (required checks, one approving review, two for `api/**` through `CODEOWNERS`, squash merges), secret scanning with push protection, private vulnerability reporting, security alerts and the OpenSSF Scorecard workflow.

**Done when:** the settings are applied and listed in `GOVERNANCE.md`.

## Acceptance criteria

- On fresh Windows, macOS and Linux machines, `task setup` followed by `task dev` starts the stack; `/healthz` returns 200 and the console placeholder loads without external requests. Verified by three contributors or CI runners.
- CI passes on `main` in under 15 minutes; the breaking-change checks demonstrably fail on a breaking edit.
- A snapshot release produces signed images and binaries with SBOMs and provenance, verified with the documented commands.
- Governance and community files are merged, and the README states the Apache-2.0 license.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| No project domain yet, so the Go module path may change later (Q6) | Decide in step 1; if no domain, accept the GitHub path and plan the move for the foundation transfer |
| Tooling friction on Windows | Test every task on Windows in CI from the start (a Windows runner for `wtctl` and the task runner) |
| GitHub-specific features (attestations, private reporting) tie the project to GitHub | Acceptable for now; keep release verification based on open tools (cosign, SPDX, CycloneDX) |

## Notes for implementers

- Keep the skeleton minimal: no framework or abstraction until a Phase 1 plan needs it.
- Go `tool` directives (Go 1.24 and later) remove the need for `tools.go` files and install scripts.
- Pin third-party GitHub Actions by full commit SHA and let Renovate update the pins.
- Generated code goes in clearly named directories (`gen/` or `*_gen.go`) so linters and reviewers can skip it.

## Progress notes

### 2026-09-29: first implementation

| Step | Status | Notes |
| --- | --- | --- |
| 1. Identifiers | Done | Listed in `CONTRIBUTING.md`. The Go module path is `github.com/J466Y/WhiteTower` until the project has a domain (Q6 stays open). |
| 2. Community files | Done | `CONTRIBUTING.md`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `NOTICE`, RFC template, issue and pull request templates, `CODEOWNERS`; README updated. The code of conduct still needs a private contact address before the first public release. |
| 3. Skeleton | Done | Server with `/healthz`, `/api/v1/version`, a placeholder module API service and the embedded console; `wtctl version`. |
| 4. Toolchains and Taskfile | Done | Go toolchain 1.27.1 (oldest supported 1.26); Node.js 22; pnpm 12. |
| 5. Code generation | Done | OpenAPI (Go server, Go client, TypeScript types) and protobuf (Go, ConnectRPC); `task verify:gen` in CI. |
| 6. Console skeleton | Done | React 19, Vite 8, TypeScript 5.9, Biome, Vitest, Playwright. The browser test proves the strict CSP holds and no request leaves the deployment. |
| 7. Continuous integration | Written, not yet run on GitHub | `ci.yml` and `codeql.yml` run on every push and pull request; `scorecard.yml` on `main`; actions pinned by SHA and checked with actionlint. |
| 8. Dependency hygiene | Done | `renovate.json`; pnpm refuses versions younger than three days; OSV-Scanner and license checks in CI. |
| 9. Release pipeline | Written, not yet run on GitHub | `.goreleaser.yaml` validated with `goreleaser check`; `release.yml` for tags and manual snapshots (the nightly snapshot waits until releases start); `docs/verify-release.md`. |
| 10. Development environment | Done | Compose with PostgreSQL, Keycloak (one user per role) and an OpenTelemetry collector, with host ports configurable through a local `.env`. Verified with Docker: services healthy, realm imported with the `groups` claim in tokens, core image built from source and healthy, end-to-end tests green against it, collector receiving OTLP. |
| 11. Repository settings | Rulesets written, not yet imported | `.github/rulesets/` holds importable rulesets for `main` and release tags; `GOVERNANCE.md` lists the other settings and the working rules. Importing them needs a maintainer with administrator rights. |

**Verified locally on Windows:**

- builds and unit tests (Go 1.27.1 and 1.26.8);
- golangci-lint, `go vet`, Biome, the TypeScript compiler, `buf lint` and Spectral;
- `govulncheck`, OSV-Scanner and go-licenses;
- the binary with the embedded console, checked with curl, the Go end-to-end test and the Playwright browser test.

**Deviations from the plan, and why:**

- **Go tools live in `hack/tools/go.mod`,** a separate module file, instead of `tool` directives in the main `go.mod`. The product's dependency list stays limited to what ships, and tool updates cannot move the versions of runtime dependencies.
- **`sqlc` and `goose` are not pinned yet.** They arrive with P1-01, which is the first plan with a schema; `sqlc` also needs cgo or a container on Windows, a choice P1-01 must make.
- **The OpenAPI spec is not embedded in the server** (`embedded-spec: false`). Embedding it pulled `kin-openapi` and five more modules into the binary. P1-01 decides whether to bring it back for request validation.
- **TypeScript stays on 5.9.** `openapi-typescript` 7 requires TypeScript 5; Renovate is told not to propose 6 or 7.
- **Images use distroless Debian 13,** because Debian 12 ended regular security support in June 2026.

### 2026-09-30: before the Phase 0 gate

| Step | Status | Notes |
| --- | --- | --- |
| 7. Continuous integration | Done | CI and CodeQL run on every pull request since the first ones were merged |
| 9. Release pipeline | Deferred to the MVP | The maintainer decided that no release is published before the MVP; the pipeline is exercised at the first release (P1-13) |
| 11. Repository settings | Done | The maintainer imported the rulesets and enabled the settings of `GOVERNANCE.md` |

**What remains:** testing the development environment on macOS and Linux; it is verified on Windows only. The code of conduct's private contact address is still needed before the first public release.
