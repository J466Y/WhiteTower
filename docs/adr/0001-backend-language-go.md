# ADR-0001: Go for the backend

- **Status:** Proposed
- **Date:** 2026-09-28
- **Related:** CON-06, NFR-02, NFR-03, NFR-13, NFR-14; ADR-0003, ADR-0004

## Context

The backend is the governance core of White Tower, a control plane. The charter and the requirements ask it to:

- stay out of the latency path of agent actions, yet fail closed (NFR-01, NFR-02);
- push a halt to hundreds of connected enforcement points within seconds and hold long-lived streams with leases (NFR-03, NFR-05, NFR-07);
- run self-hosted and air-gapped, on containers and Kubernetes (CON-02, CON-04, NFR-14);
- be trustworthy as a security product: small dependency tree, reproducible and signed builds, SBOMs (NFR-13);
- integrate with a cloud-native and security ecosystem: Kubernetes, OPA, Cedar, SPIFFE/SPIRE, OpenTelemetry, Sigstore;
- be approachable for an open-source community that will review contract changes through RFCs.

## Decision

The core server (`whitetower`), the CLI (`wtctl`), the conformance kit, the internal module SDK and in-tree adapters (when the wrapped product allows it) are written in **Go**, using the latest stable release and supporting the two most recent ones.

Initial library choices, which can change through normal review: standard library `net/http` and `log/slog`; `oapi-codegen` for the REST API; `connect-go` for the module API; `pgx`, `sqlc` and `goose` for PostgreSQL; `go-jose` for JWT and JWKS; `coreos/go-oidc` for OIDC; the OpenTelemetry Go SDK; `cobra` for the CLI; `testcontainers-go` for integration tests.

## Consequences

**Easier**
- Ecosystem fit. Most tools White Tower integrates or embeds are written in Go (Kubernetes client libraries, OPA, cedar-go, go-spiffe, OpenTelemetry, Sigstore, the Go checksum database's transparency log packages). They can be embedded as libraries instead of wrapped as processes.
- Operations. One static binary, small distroless images, fast startup and cross-compilation to amd64 and arm64 make air-gapped delivery simple.
- Concurrency. Goroutines suit thousands of long-lived streams, and latency is predictable.
- Security. Memory safety, a strong standard library for cryptography, TLS and HTTP, `govulncheck` with reachability analysis, and mature release tooling (GoReleaser, Syft, cosign).
- Community. Go is widely known in cloud-native and security circles, and its simplicity makes reviews easier.

**Harder**
- The AI agent ecosystem is mostly Python and TypeScript. Mitigation: all contracts are language-neutral (OpenAPI, protobuf, CloudEvents, JSON Schema), so modules can be written in any language, and agent-side components (such as the in-process enforcement point of ADR-0011) use the agent's language.
- Go's type system is less expressive than Rust's and error handling is verbose. Accepted.

## Alternatives considered

- **Python (FastAPI).** The language of most agent frameworks and quick to prototype. Rejected for the core: a weaker fit for a latency-sensitive, fail-closed control plane; heavier packaging for air-gapped installs; dynamic typing in security-critical code; a larger dependency surface. Still the natural choice for agent-side components.
- **Rust.** The strongest safety and performance guarantees. Rejected for the core: slower iteration and a smaller contributor pool, and a less mature ecosystem for Kubernetes control planes. It stays an option for isolated components, such as a future harness.
- **TypeScript on Node.js.** One language for front and back. Rejected: npm supply-chain exposure is hard to justify in a security product, and it is a weaker fit for single-binary, air-gapped delivery.
- **Java or Kotlin.** A mature enterprise ecosystem (Keycloak is Java). Rejected: heavier runtime and images, slower startup, and a smaller cloud-native contributor pool.
