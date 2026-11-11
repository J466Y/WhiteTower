# Bundle vectors

Signed policy bundles for the verification steps of the specification ([section 7.4](../../../../docs/contracts/module-contract-v0.1.md#74-verification)). Every directory is one case:

| File | Content |
| --- | --- |
| `case.json` | What the enforcement point knows: the agent, the bundle reference from its governance state, the active version; and the expected outcome, `activated` or `rejected` with a reason |
| `manifest.json` | The manifest, exactly as signed: RFC 8785 canonical JSON, except where a case changes its bytes |
| `manifest.jws` | The detached JWS, absent in the `unsigned` case |
| `schema.cedarschema`, `catalog.json`, `policies/...` | The bundle's files: the Cedar schema, the catalog file (section 7.7) and the policies |

## Keys

`trusted-keys.json` holds the bundle keys that a module under test trusts: a JWK Set (RFC 7517) of `OKP` keys on the `Ed25519` curve (RFC 8037), the form in which section 7.3 has enforcement points take their keys, and the file that the [driver protocol](../../driver-protocol.md) passes to a module. `untrusted-keys.json` holds, in the same form, a key that nothing trusts: it signs the `unknown-key` case, and the `forged-key-id` case under the trusted key's ID.

**These keys are for tests only.** Their seeds are public: each is the SHA-256 of `White Tower conformance test key: <name>. Never trust it outside tests.`, where `<name>` is `trusted` or `untrusted`, so anyone can sign with them. Never configure them anywhere else.

## Cases

Each case expects the outcome that steps V1 to V7 give it, in their order. A case that breaks two rules, as those that check the order of step V4 do, gets the reason of the rule checked first. Every bundle carries the catalog file of `valid` unless its case says otherwise. Manifests and catalog files are their own canonical JSON (section 7.2), but those of the cases that test their form or a check before it.

| Step | Case | Expected | What the bundle holds |
| --- | --- | --- | --- |
| All | `valid` | `activated` | A valid bundle newer than the active one, with a catalog file: a tool of each kind but `http` and `other`, approved and discovered, enabled and not, arguments of each type and two transforms, a model with its digest, and the deployment's redaction rules |
| All | `first-bundle` | `activated` | A valid bundle when none is active |
| V1 | `oversized` | `oversized` | Governance state announces a bundle larger than the limit |
| V2 | `tampered-manifest` | `signature` | The manifest was changed after signing, and governance state refers to the changed one |
| V2 | `unsigned` | `signature` | No signature |
| V2 | `unknown-key` | `unknown_key` | A signature by a key the enforcement point does not trust |
| V2 | `forged-key-id` | `signature` | A signature by another key, under a trusted key ID |
| V2 | `header-alg-none` | `signature` | A JWS header that names the algorithm `none`, and an empty signature |
| V2 | `header-hs256` | `signature` | A JWS header that names `HS256`, and an HMAC keyed with the 32 bytes of the trusted public key |
| V2 | `header-alg-ed25519` | `signature` | A signature by the trusted key, under a JWS header that names the algorithm `Ed25519` rather than `EdDSA` |
| V2 | `header-other-typ` | `signature` | A signature by the trusted key, under a JWS header whose `typ` is `JWT` |
| V2 | `header-b64-crit` | `signature` | A signature by the trusted key over the encoded manifest, under a JWS header that also carries `b64` set to `true`, listed in `crit` (RFC 7797). Since `true` keeps the payload encoded, a verifier that lets the extra members through activates it, whether it reads them or not |
| V2 | `header-no-kid` | `signature` | A signature by the trusted key, under a JWS header without `kid` |
| V2 | `header-any-order` | `activated` | A JWS header with its three members in another order |
| V2 | `header-duplicate-alg` | `signature` | A signature by the trusted key, under a JWS header that gives `alg` twice, `none` and then `EdDSA`: not I-JSON (section 7.2), whichever of them a reader keeps |
| V2 | `header-jku-instead-of-kid` | `signature` | A signature by the trusted key, under a JWS header with `jku` in place of `kid`: three members, but not the three of section 7.2 |
| V2 | `header-line-break` | `signature` | A JWS header whose base64url has a line break, signed by the trusted key as it travels: RFC 7515's base64url has none |
| V2 | `signature-padding` | `signature` | A signature whose base64url ends with the `=` padding that RFC 7515 leaves out |
| V2 | `header-byte-order-mark` | `signature` | A JWS header whose JSON starts with a byte order mark, signed by the trusted key |
| V2 | `header-invalid-utf8` | `signature` | A JWS header whose key ID ends with a byte that is not UTF-8, signed by the trusted key |
| V3 | `ref-mismatch` | `manifest_mismatch` | A valid bundle, but not the one governance state refers to |
| V4 | `byte-order-mark` | `invalid_manifest` | A manifest that starts with a byte order mark, which JSON in UTF-8 never carries (section 1) |
| V4 | `invalid-utf8` | `invalid_manifest` | A manifest in which a policy's name ends with a byte that is not UTF-8 (section 1) |
| V4 | `not-an-object` | `invalid_manifest` | A manifest that is an array holding a valid manifest |
| V4 | `unknown-member` | `invalid_manifest` | A manifest member that the format does not define |
| V4 | `unknown-policy-member` | `invalid_manifest` | A policy entry's member that the format does not define |
| V4 | `missing-member` | `invalid_manifest` | A manifest without `combining_algorithm`: a missing member is invalid, not unsupported |
| V4 | `missing-policy-member` | `invalid_manifest` | A policy entry without `name` |
| V4 | `no-schema` | `invalid_manifest` | A manifest without `cedar_schema`, in a bundle without a Cedar schema |
| V4 | `wrong-type` | `invalid_manifest` | A policy entry whose `version` is a string |
| V4 | `null-member` | `invalid_manifest` | A manifest whose `language` is `null`, of no type the format allows: invalid, not unsupported |
| V4 | `malformed-time` | `invalid_manifest` | A manifest whose `created_at` has no milliseconds |
| V4 | `unsupported-format` | `unsupported` | The format `whitetower.bundle.v2` |
| V4 | `unsupported-algorithm` | `unsupported` | A combining algorithm the contract does not define |
| V4 | `unsupported-language` | `unsupported` | The language `rego`, which `v1alpha1` does not have and which the schema's constant refuses too; nothing else differs from `valid` |
| V4 | `unsupported-and-unknown-member` | `invalid_manifest` | An unsupported format and an unknown member: the structure is checked first |
| V4 | `unsupported-and-wrong-agent` | `unsupported` | An unsupported combining algorithm, for another agent: the values are checked before the agent |
| V4 | `wrong-agent` | `invalid_manifest` | A valid bundle for another agent |
| V4 | `wrong-version` | `invalid_manifest` | A valid bundle at version 43, which governance state names as version 42 |
| V4 | `duplicate-member` | `invalid_manifest` | A manifest that gives `agent_id` twice, with the same value: a member name twice is not I-JSON (section 1), whichever of them a reader keeps |
| V4 | `duplicate-format` | `invalid_manifest` | A manifest that gives its format twice, `whitetower.bundle.v1` and then `whitetower.bundle.v2`: not I-JSON, which is checked before the format is unsupported |
| V4 | `duplicate-policy-member` | `invalid_manifest` | A policy entry that gives its `scope` twice, with the same value |
| V4 | `version-beyond-max` | `invalid_manifest` | A manifest at version 2^53, beyond the 2^53 - 1 of I-JSON, which governance state names |
| V4 | `version-beyond-max-with-exponent` | `invalid_manifest` | The same version, written `9.007199254740992e15`: a number is read by its value, whatever its spelling |
| V4 | `version-beyond-max-with-fraction` | `invalid_manifest` | The same version, written `9007199254740992.0` |
| V4 | `policy-version-beyond-max` | `invalid_manifest` | A policy entry at version 2^53 |
| V4 | `negative-version-beyond-max` | `invalid_manifest` | A policy entry at version -2^53 |
| V4 | `max-version` | `activated` | A manifest at version 2^53 - 1, the largest integer of I-JSON, which governance state names |
| V4 | `version-rounded-by-a-double` | `invalid_manifest` | A manifest whose version is `42.000000000000001`, which a double rounds to 42: no double holds it as written, and it is no integer |
| V4 | `lone-surrogate` | `invalid_manifest` | A policy's name that ends with the escape of a lone surrogate, which I-JSON's strings never hold (RFC 7493) |
| V4 | `noncharacter` | `invalid_manifest` | A policy's name that ends with the noncharacter U+FDD0, which I-JSON's strings never hold either |
| V4 | `version-with-exponent` | `invalid_manifest` | A manifest whose version is written `4.2e1`, the integer 42, which canonical JSON writes `42`: not the manifest's canonical JSON (section 7.2) |
| V4 | `version-with-zero-fraction` | `invalid_manifest` | A manifest whose version is written `42.0`, which canonical JSON writes `42` |
| V4 | `manifest-with-spaces` | `invalid_manifest` | An indented manifest, with spaces and line breaks between its members |
| V4 | `members-out-of-order` | `invalid_manifest` | A manifest that gives its version first, where canonical JSON sorts it last |
| V4 | `escaped-character` | `invalid_manifest` | A policy's name with its `e` written as a JSON escape of six characters, where canonical JSON writes the character itself: the same name, in another form |
| V4 | `unsupported-and-not-canonical` | `invalid_manifest` | An unsupported format, in a manifest with spaces: the canonical form is checked before the format |
| V4 | `no-catalog` | `activated` | A bundle without a catalog file, on which an enforcement point decides as with an empty catalog (section 7.7) |
| V4 | `null-catalog` | `invalid_manifest` | A manifest whose `catalog` is `null`, which is not a manifest without a catalog |
| V4 | `unknown-catalog-member` | `invalid_manifest` | A catalog file's entry with a member that the format does not define |
| V4 | `missing-catalog-member` | `invalid_manifest` | A catalog file's entry without `sha256` |
| V5 | `malformed-path` | `invalid_manifest` | A policy's path without the directory of its scope |
| V5 | `mismatched-path` | `invalid_manifest` | A policy's path that names the ID of another policy |
| V5 | `mismatched-scope` | `invalid_manifest` | A global policy's path in the directory of agent-specific policies |
| V5 | `duplicate-path` | `invalid_manifest` | The global policy listed twice, in two versions, at the same path |
| V5 | `misplaced-schema` | `invalid_manifest` | A Cedar schema that is not at `schema.cedarschema` |
| V5 | `misplaced-catalog` | `invalid_manifest` | A catalog file that is not at `catalog.json` |
| V5 | `missing-catalog` | `missing_file` | A catalog file that the manifest names and the bundle does not carry |
| V5 | `tampered-catalog` | `file_hash` | A catalog file changed after signing |
| V5 | `unlisted-catalog` | `extra_file` | A catalog file that the manifest does not name |
| V5 | `missing-file` | `missing_file` | A listed policy file is missing |
| V5 | `tampered-policy` | `file_hash` | A policy file was changed after signing |
| V5 | `extra-file` | `extra_file` | A file the manifest does not list |
| V6 | `older-version` | `older_version` | A valid bundle older than the active one |
| V7 | `parse-error` | `parse_error` | A policy that does not parse |
| V7 | `template` | `parse_error` | A policy that is a template, with a slot for its principal |
| V7 | `fails-validation` | `activated` | A policy that parses, but fails validation against the bundle's Cedar schema, which is the core's job only |
| V7 | `empty-catalog` | `activated` | A catalog file with no entries and no redaction rules |
| V7 | `catalog-not-json` | `parse_error` | A catalog file that is not JSON |
| V7 | `catalog-byte-order-mark` | `parse_error` | A catalog file that starts with a byte order mark |
| V7 | `catalog-duplicate-member` | `parse_error` | A catalog file in which an MCP tool gives `enabled` twice, `false` and then `true`: not I-JSON, as a manifest would not be, whichever of them a reader keeps |
| V7 | `catalog-unknown-member` | `parse_error` | A tool with a member that `whitetower.catalog.v1` does not define |
| V7 | `catalog-other-format` | `parse_error` | A catalog file of the format `whitetower.catalog.v2` |
| V7 | `catalog-unknown-type` | `parse_error` | An argument of the type `Set<Bool>`, none of the five of section 7.7 |
| V7 | `catalog-missing-definition` | `parse_error` | An approved function without its definition, which approval pins |
| V7 | `catalog-not-canonical` | `parse_error` | The valid catalog file as `bundle_vectors_test.go` writes it, indented and with its members in another order: not its own canonical JSON, which the core writes |
| V7 | `catalog-duplicate-server-key` | `parse_error` | Two servers that share the key `github`, with other references |
| V7 | `catalog-duplicate-server-reference` | `parse_error` | Two servers, `github` and `github-copy`, that share a reference |
| V7 | `catalog-duplicate-tool-key` | `parse_error` | Two tools, `send_email` and `send_mail`, that share the key `agent/send_email` |
| V7 | `catalog-duplicate-tool-reference` | `parse_error` | Two functions, `agent/send_email` and `agent/send_email_v2`, both named `send_email`: one reference |
| V7 | `catalog-duplicate-model-key` | `parse_error` | Two models that share the key `gpu-01/llama3.1-8b` |
| V7 | `catalog-duplicate-model-reference` | `parse_error` | Two models with the same provider and name, and endpoints written otherwise that section 4.10 normalizes alike: one reference |
| V7 | `catalog-unreadable-endpoint` | `parse_error` | A model whose endpoint has no scheme, so that its reference cannot be computed |
| V7 | `catalog-unknown-server` | `parse_error` | An MCP tool whose server is no server of the file |
| V7 | `catalog-server-not-approved` | `parse_error` | An approved MCP tool whose server is discovered |
| V7 | `catalog-argument-name` | `parse_error` | An argument at the path `options.amount` named `amount` |
| V7 | `catalog-argument-name-transform` | `parse_error` | An argument under the transform `email_domain` named `to`, without `:email_domain` |
| V7 | `catalog-argument-twice` | `parse_error` | A tool that declares the argument `base` twice |

## Using them

To verify a case as an enforcement point would: trust the keys of `trusted-keys.json`, build the expectation from `case.json`, run the steps of section 7.4, and compare with `expected`. The files are generated by `bundle_vectors_test.go`; never edit them by hand, since any change breaks their signatures.

The same test file checks every manifest against [`bundle-manifest.schema.json`](../../../../api/policy/bundle-manifest.schema.json): a manifest that step V4 refuses on its own fails the schema, one that is not I-JSON included, and the manifest of every activated bundle passes it. The schema reads values, not their spelling, so it cannot express the canonical form: for a manifest that is not its own canonical JSON, the test compares the schema with V4 on that canonical JSON. The catalog file's schema is [`catalog.schema.json`](../../../../api/policy/catalog.schema.json), against which step V7 parses it, before it checks what no schema can: keys, references, servers and argument names.
