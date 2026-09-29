# Event catalog

CloudEvents 1.0 types emitted by White Tower's core and modules, contract version `v1alpha1` ([specification, section 8](../../docs/contracts/module-contract-v0.1.md#8-events)).

| File | Content |
| --- | --- |
| [`catalog.json`](catalog.json) | Every type: who emits it, whether the envelope's subject is required, its schema and its example |
| [`cloudevent.schema.json`](cloudevent.schema.json) | The envelope: CloudEvents attributes with White Tower's rules (`source` forms, `wtseq`, trace context) |
| [`schemas/`](schemas/) | One JSON Schema per type for its `data`, and the shared definitions |
| [`examples/`](examples/) | One complete, valid event per type |

Schemas have no `$id` yet: stable URLs depend on the project's domain (open question Q6). They reference each other by relative path.
