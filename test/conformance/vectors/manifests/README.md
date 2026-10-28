# Manifest vectors

Module manifests written in YAML, and what the core reads in them ([sections 1, 3.1 and 3.2](../../../../docs/contracts/module-contract-v0.1.md#31-format)). Every directory is one case:

| File | Content |
| --- | --- |
| `case.json` | What the case checks, the obligation, and the expected outcome: `accepted`, with the SHA-256 of the canonical JSON, or `refused` |
| `manifest.yaml` | The manifest, as a module ships it |
| `canonical.json` | For an accepted manifest, its canonical JSON (RFC 8785): the bytes whose SHA-256 an instance presents when it registers (MAN-2) |

Three cases are the examples of [`api/manifest/examples`](../../../../api/manifest/examples/), as they are. Each of the others is one of them with one replacement, so that the replacement alone is why MAN-1 refuses it, or what its canonical JSON shows:

| Case | Replacement | Outcome |
| --- | --- | --- |
| `boolean-enumeration` | `enum: [on, off]` | Refused: booleans in YAML 1.1, strings in YAML 1.2 |
| `date` | `versions: 2026-10-28` | Refused: a timestamp in YAML 1.1, a string in YAML 1.2 |
| `integer-beyond-2-53` | `minimum: 9007199254740993` | Refused: 2^53 + 1, which a double cannot hold, so the manifest is not I-JSON |
| `not-utf-8` | A display name whose é is the byte E9, as Windows-1252 writes it | Refused: the manifest is not UTF-8 |
| `utf-16-key-order` | Two properties of the configuration schema, `｡` (U+FF61) and `😀` (U+1F600) | Accepted: RFC 8785 sorts them by UTF-16 code units, `😀` first, where code points would put `｡` first |

`documents.json` holds shorter YAML documents, each with its expected outcome and, when it is accepted, its canonical JSON: documents that MAN-1 refuses, at least one for each of its rules and of I-JSON's, and documents that it accepts. Its strings escape every character beyond ASCII, so that invisible ones, such as a byte order mark, show.

To check a case or a document: read the YAML under the YAML 1.2 Core schema, refusing what MAN-1 refuses (section 3.1) and input that is not I-JSON (section 1). Then compare the outcome with `expected`; for an accepted case, its canonical JSON with `canonical.json` and its SHA-256 with `expected.sha256`; for an accepted document, its canonical JSON with `expected.canonical_json`. The schema of the manifest is checked apart.

The files are generated from the examples and the tests of [`test/conformance/manifest`](../../manifest/); never edit them by hand. After an example or a test document changes, run `go test ./test/conformance/manifest -run TestManifestVectorsAreCurrent -update`.
