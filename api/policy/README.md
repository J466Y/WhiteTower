# Decision profile and policy bundles

The parts of the module contracts that concern policies ([specification, sections 6 and 7](../../docs/contracts/module-contract-v0.1.md#6-decision-profile)).

| File | Content |
| --- | --- |
| [`whitetower.cedarschema`](whitetower.cedarschema) | The Cedar schema of White Tower's entities and actions. The core generates each bundle's schema from it, declaring in `ToolArgs` the arguments of the bundle's catalog, and validates policies against that schema before approval |
| [`decision-request.schema.json`](decision-request.schema.json) | An AuthZEN evaluation request, restricted to the profile |
| [`decision-response.schema.json`](decision-response.schema.json) | An AuthZEN evaluation response, with the profile's reason codes |
| [`bundle-manifest.schema.json`](bundle-manifest.schema.json) | The signed manifest of a policy bundle, format `whitetower.bundle.v1` |
| [`catalog.schema.json`](catalog.schema.json) | An agent's catalog file, `catalog.json` in each bundle, format `whitetower.catalog.v1` |

The test vectors that exercise these files are in [`test/conformance/vectors/`](../../test/conformance/README.md).
