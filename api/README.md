# Contracts

This directory is the source of truth for every interface of White Tower. Code is generated from it with `task gen`, and CI fails when the generated code is out of date. See [ADR-0004](../docs/adr/0004-api-and-contract-formats.md).

| Directory | Contract | Format |
| --- | --- | --- |
| [`openapi/`](openapi/) | Public REST API, used by the console, the CLI and the organization's tools | OpenAPI 3.1 |
| [`proto/`](proto/) | Module API, used by enforcement points and modules | Protocol Buffers, served with ConnectRPC |
| [`events/`](events/) | Event catalog | CloudEvents 1.0 with JSON Schema |
| [`manifest/`](manifest/) | Module manifest | JSON Schema |

Changes to `proto/`, `events/` and `manifest/` go through the RFC process described in [CONTRIBUTING.md](../CONTRIBUTING.md). The module contracts themselves are defined by RFC-0001 (plan [P0-03](../docs/plans/phase-0/P0-03-module-contracts.md)); until then, these directories only hold placeholders that exercise the code generation pipeline.
