# Contributing to White Tower

Thank you for your interest. White Tower is in its design phase, which is the best time to shape it. Read the [README](README.md) and the [design documents](docs/README.md) first.

Please follow the [code of conduct](CODE_OF_CONDUCT.md). **Never report security vulnerabilities in public issues**: see [SECURITY.md](SECURITY.md).

## Where decisions go

| What you want to change | Where it goes |
| --- | --- |
| What the MVP must do, or how well | A pull request to the [requirements](docs/requirements/mvp-requirements.md) |
| An architectural decision | An [ADR](docs/adr/README.md) |
| A module contract (`api/proto`, `api/events`, `api/manifest`) | An [RFC](docs/rfcs/README.md), before any code |
| The public REST API (`api/openapi`) | A pull request that updates the OpenAPI document first |
| How work is planned | The [implementation plans](docs/plans/README.md) |

How decisions are made, and who makes them, is described in [GOVERNANCE.md](GOVERNANCE.md).

## Getting started

Follow [docs/development.md](docs/development.md) to set up Go, Node.js, pnpm and Docker. Then:

```sh
task setup   # download dependencies and tools
task test    # unit tests of Go and the console
task lint    # linters
```

Without Task installed, run the pinned copy: `go tool -modfile=hack/tools/go.mod task <name>`.

## Project identifiers

| Identifier | Value |
| --- | --- |
| Go module path | `github.com/J466Y/WhiteTower` (may move to a vanity path if the project gets its own domain; open question Q6) |
| Binaries | `whitetower` (core), `wtctl` (CLI) |
| Protobuf package of the module API | `whitetower.module.v1alpha1` |
| CloudEvents type prefix | `whitetower.` (for example `whitetower.halt.issued.v1`) |
| Module manifest `apiVersion` | `whitetower/v1alpha1` |
| Container images | `ghcr.io/j466y/whitetower` |

## Pull requests

1. Open an issue first for anything larger than a small fix, so the approach can be agreed before you write code.
2. Keep pull requests small and focused. One plan step, or one part of it, is a good size.
3. Write commit messages following [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `ci:`).
4. **Sign off every commit** under the [Developer Certificate of Origin](https://developercertificate.org/) with `git commit -s`. By signing off, you certify that you wrote the change or have the right to submit it under the project's license ([ADR-0008](docs/adr/0008-license-apache-2.md)).
5. Make sure the pull request meets the [definition of done](docs/plans/README.md#definition-of-done-every-plan). The pull request template has the checklist.
6. Reference the plan step and requirement IDs the change implements, for example `P1-04 step 5, INV-04`.

## Generated code

Code under `internal/api/rest/gen`, `pkg/apiclient`, `pkg/moduleapi` and `web/src/api/schema.gen.ts` is generated from `api/`. Never edit it by hand: change the contract, run `task gen` and commit the result. CI fails when the generated code is out of date.

## Dependencies

Every dependency is attack surface for a security product.

- **A new runtime dependency needs a justification** in its pull request: what it does, why the standard library or an existing dependency is not enough, and how well it is maintained.
- **Licenses must be compatible with Apache-2.0** ([ADR-0008](docs/adr/0008-license-apache-2.md)). CI checks them.
- **Versions are pinned.** Go modules through `go.sum`, console packages exactly in `web/package.json`, GitHub Actions by commit SHA. pnpm refuses versions published less than three days ago.
- **Updates come through Renovate**, grouped and delayed.

## Tests

- Every behavior change comes with tests, including negative tests for authorization and input validation.
- `task test` runs the unit tests; `task e2e` runs the end-to-end tests against a running core.
- Tests must pass on Linux, macOS and Windows.
