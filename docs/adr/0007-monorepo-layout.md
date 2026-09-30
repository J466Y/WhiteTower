# ADR-0007: Monorepo layout

- **Status:** Accepted, by the maintainer on 2026-09-30
- **Date:** 2026-09-28
- **Related:** ADR-0001, ADR-0002, ADR-0004; plan P0-01

## Context

During the alpha, contracts, core, adapters, console and deployment files change together: a contract change touches the protobuf definitions, the core, the mock module, the enforcement point and the conformance kit at once. Separate repositories would turn each of those changes into several coordinated pull requests.

## Decision

A single repository with this layout:

```text
api/
  openapi/        public REST API (OpenAPI 3.1), source of truth
  proto/          module API (protobuf, Buf), whitetower/module/v1alpha1
  events/         CloudEvents catalog and JSON Schemas of event data
  manifest/       JSON Schema of module manifests, with examples
cmd/
  whitetower/     core server
  wtctl/          CLI
internal/         core packages, not importable by third parties
pkg/              public Go packages: module SDK, API client
modules/
  mock/           reference and test module (Go)
  ep-python/      White Tower enforcement point for Python agents (ADR-0011)
  k8s-quarantine/ Network quarantine controller for Kubernetes (Go, plan P1-15)
web/              console (React, Vite, pnpm)
deploy/
  compose/        Docker Compose for development and evaluation
  helm/           Helm chart
test/
  e2e/            end-to-end tests
  conformance/    conformance kit and language-neutral test vectors
  load/           load tests
docs/             requirements, architecture, ADRs, plans, RFCs, security
hack/             development scripts and throwaway spikes
```

- One Go module at the root in the MVP. Adapters in other languages live under `modules/<name>` with their own toolchain.
- A single `Taskfile.yml` at the root exposes the common tasks (`build`, `test`, `lint`, `gen`, `dev`, `e2e`) on Windows, macOS and Linux.
- Generated code is committed, and CI fails if it is out of date.

## Consequences

**Easier:** atomic changes across contracts and implementations, one CI, one place to look, and simple cross-cutting refactoring during the alpha.

**Harder:** CI must only run what a change affects (path filters), and independent versioning of the public SDK and of adapters is not possible yet. When the SDK is published (Phase 3), `pkg/` can become its own Go module or repository.

## Alternatives considered

- **Several repositories (core, contracts, SDK, console, adapters).** Clean ownership boundaries, but coordinated changes are costly while contracts are still moving. Revisit in Phase 3.
- **A Go multi-module workspace from day one.** Premature; it complicates tooling without a consumer that needs independent versions yet.
