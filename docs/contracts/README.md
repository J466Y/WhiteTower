# Module contracts

What a module must implement to plug into White Tower, and what the core guarantees in return.

| Document | Content |
| --- | --- |
| [module-contract-v0.1.md](module-contract-v0.1.md) | The normative specification of contract version `v1alpha1`: capabilities, manifest, module API, governance state and leases, halts, decision profile, bundles, events, conformance, versioning, security |
| [engine-mappings.md](engine-mappings.md) | The contracts mapped onto Microsoft AGT, OPA, Cedar and engines with native AuthZEN |

The machine-readable parts live in [`api/`](../../api/README.md), and the conformance kit and test vectors in [`test/conformance/`](../../test/conformance/README.md). Changes go through the RFC process: the contracts are proposed in [RFC-0001](../rfcs/0001-module-contracts-v0.1.md).
