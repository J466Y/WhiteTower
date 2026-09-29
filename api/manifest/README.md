# Module manifest

The manifest every module declares: capabilities, contract versions, identity, the agents it serves, events, permissions and its configuration schema ([specification, section 3](../../docs/contracts/module-contract-v0.1.md#3-module-manifest)).

| File | Content |
| --- | --- |
| [`module-manifest.schema.json`](module-manifest.schema.json) | JSON Schema (draft 2020-12) for `apiVersion: whitetower/v1alpha1`, `kind: ModuleManifest` |
| [`examples/`](examples/) | Valid manifests: the mock module, the Python enforcement point and the Kubernetes network quarantine module |
| [`testdata/invalid/`](testdata/invalid/) | Manifests the schema must refuse, each with the reason in its first line |
