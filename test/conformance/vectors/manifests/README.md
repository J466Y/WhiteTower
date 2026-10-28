# Manifest vectors

Module manifests written in YAML, and what the core reads in them ([sections 1, 3.1 and 3.2](../../../../docs/contracts/module-contract-v0.1.md#31-format)). Every directory is one case:

| File | Content |
| --- | --- |
| `case.json` | What the case checks, the obligation, and the expected outcome: `accepted`, with the SHA-256 of the canonical JSON, or `refused` |
| `manifest.yaml` | The manifest, as a module ships it |
| `canonical.json` | For an accepted manifest, its canonical JSON (RFC 8785): the bytes whose SHA-256 an instance presents when it registers (MAN-2) |

The accepted cases are the three examples of [`api/manifest/examples`](../../../../api/manifest/examples/). Each refused case is one of them with one scalar replaced, so that the replacement alone is why MAN-1 refuses it:

| Case | Replacement | Why it is refused |
| --- | --- | --- |
| `boolean-enumeration` | `enum: [on, off]` | Booleans in YAML 1.1, strings in YAML 1.2 |
| `date` | `versions: 2026-10-28` | A timestamp in YAML 1.1, a string in YAML 1.2 |
| `integer-beyond-2-53` | `minimum: 9007199254740993` | 2^53 + 1, which a double cannot hold: the manifest is not I-JSON |

To check a case: read `manifest.yaml` under the YAML 1.2 Core schema, refusing what MAN-1 refuses (section 3.1) and input that is not I-JSON (section 1); then compare the outcome with `expected`, and an accepted manifest's canonical JSON with `canonical.json` and its SHA-256 with `expected.sha256`. The schema of the manifest is checked apart.

The files are generated from the examples by the tests of [`test/conformance/manifest`](../../manifest/); never edit them by hand. After an example changes, run `go test ./test/conformance/manifest -run TestManifestVectorsAreCurrent -update`.
