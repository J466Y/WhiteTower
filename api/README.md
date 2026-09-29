# Contracts

This directory is the source of truth for every interface of White Tower. Code is generated from it with `task gen`, and CI fails when the generated code is out of date. See [ADR-0004](../docs/adr/0004-api-and-contract-formats.md).

| Directory | Contract | Format |
| --- | --- | --- |
| [`openapi/`](openapi/) | Public REST API, used by the console, the CLI and the organization's tools | OpenAPI 3.1 |
| [`proto/`](proto/) | Module API, used by enforcement points and modules | Protocol Buffers, served with ConnectRPC |
| [`events/`](events/README.md) | Event catalog | CloudEvents 1.0 with JSON Schema |
| [`manifest/`](manifest/README.md) | Module manifest | JSON Schema |
| [`policy/`](policy/README.md) | Decision profile and policy bundles | Cedar schema, JSON Schema, Rego |

The module contracts (`proto/`, `events/`, `manifest/` and `policy/`) are specified in [module-contract-v0.1.md](../docs/contracts/module-contract-v0.1.md) and proposed in [RFC-0001](../docs/rfcs/0001-module-contracts-v0.1.md). Changes to them go through the RFC process described in [CONTRIBUTING.md](../CONTRIBUTING.md). The public REST API is still a placeholder that exercises the code generation pipeline; the Phase 1 plans define it.

`go test ./test/contracts ./test/conformance` checks every schema, example and test vector in these directories.
