# ADR-0004: API and contract formats

- **Status:** Proposed
- **Date:** 2026-09-28
- **Related:** API-01 to API-03, MOD-01 to MOD-05, POL-06, AID-03, CON-03; ADR-0001, ADR-0005

## Context

White Tower exposes three kinds of interfaces with different audiences:

1. **The public API**, used by the console, the CLI and the organization's tools (ITSM, GRC, SIEM, scripts). Its readers expect resource-oriented REST and OpenAPI.
2. **The module contracts**, implemented by adapters from any vendor, in any language. They need streaming (governance state and halts, ADR-0005), strong typing and strict compatibility rules, because the charter wants modules to be swappable and contract changes to go through RFCs.
3. **Standard protocols** where a standard already exists: agent authentication, events, telemetry and authorization decisions. The charter asks for standards over custom formats.

## Decision

| Interface | Format | Tooling |
| --- | --- | --- |
| Public API | REST and JSON, described by **OpenAPI 3.1**, written spec-first under `/api/v1`. Errors as RFC 9457 problem details; cursor pagination; ETag and If-Match. | `oapi-codegen` (Go server and client), `openapi-typescript` (console), Spectral (lint), `oasdiff` (breaking-change check in CI) |
| Module API | **Protocol Buffers**, package `whitetower.module.v1alpha1`, served with **ConnectRPC**: the same handlers speak gRPC, gRPC-Web and the Connect protocol (plain HTTP with JSON), so a module can use a gRPC library or just an HTTP client. | Buf (lint, `buf breaking` in CI, code generation) |
| Events | **CloudEvents 1.0** in JSON. Types named `whitetower.<area>.<event>.v<N>`; the `data` of each type described by a JSON Schema in an event catalog. In v0.1 events travel inside the module API; other bindings (NATS, Kafka, HTTP webhooks) can be added without changing the catalog. | JSON Schema validation in the core and in the conformance kit |
| Module manifest | **YAML validated by JSON Schema** (`api/manifest/`), with `apiVersion`, `kind`, `metadata` and `spec`, in the style of Kubernetes resources. | JSON Schema |
| Decision model | Requests shaped as **OpenID AuthZEN Authorization API 1.0** evaluations (subject, action, resource, context), a Final Specification since January 2026, with a White Tower profile for agents. AuthZEN decisions are booleans; reasons and policy references travel in the response `context`. A policy-engine module may expose the AuthZEN endpoints (`/access/v1/evaluation`, `/access/v1/evaluations`, discovery at `/.well-known/authzen-configuration`) so gateways (Phase 2) can use any compliant decision point. | Profile and test vectors in the contracts |
| Agent and module authentication | **OAuth 2.0** client credentials with `private_key_jwt` (RFC 7523), JWT access tokens (RFC 9068), JWKS, and authorization server metadata (RFC 8414). | ADR-0010 |
| Platform telemetry and audit export | **OpenTelemetry** (OTLP) | OpenTelemetry Go SDK |

Contract versions follow `v1alpha1` → `v1beta1` → `v1`. Alpha versions may break between minor releases with notice; from beta onward, breaking changes need a new version. Every change to `api/proto`, `api/events` or `api/manifest` needs an RFC.

## Consequences

**Easier**
- Enterprise integrators get idiomatic REST; module authors get typed, streaming, versioned contracts.
- `buf breaking` and `oasdiff` turn "do not break the contract" into a CI check, which the RFC process relies on.
- ConnectRPC keeps a plain HTTP and JSON path, so a quick adapter needs no gRPC stack.
- AuthZEN alignment lets existing policy decision points plug in with little translation. Some implement it natively (Cerbos, Topaz, OpenFGA behind an experimental flag); OPA and Cedar need a thin adapter, since OPA declined native support in 2026.

**Harder**
- Two definition languages (OpenAPI and protobuf) with two generation pipelines. Shared concepts (agent, halt, policy) are defined once in the data model (P0-02) and mapped in both.
- Contributors must learn Buf and ConnectRPC. The conformance kit and examples lower the barrier.

## Alternatives considered

- **Protobuf for everything, with REST transcoding** (for example ConnectRPC Vanguard). One definition language, but less idiomatic REST for integrators and more machinery. Revisit if keeping two definitions in sync becomes painful.
- **OpenAPI for everything, with Server-Sent Events or long polling for streams.** Maximum accessibility, but weaker typing for streams and no mature tool for breaking-change detection of streaming contracts.
- **GraphQL for the public API.** Flexible for the console, but less familiar to the integration tools the public API targets, and harder to authorize field by field.
- **A custom decision format.** Rejected in favor of AuthZEN, following the charter's "standards over custom formats" principle.
