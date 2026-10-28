# Bundle vectors

Signed policy bundles for the verification steps of the specification ([section 7.4](../../../../docs/contracts/module-contract-v0.1.md#74-verification)). Every directory is one case:

| File | Content |
| --- | --- |
| `case.json` | What the enforcement point knows: the agent, the bundle reference from its governance state, the active version; and the expected outcome, `activated` or `rejected` with a reason |
| `manifest.json` | The manifest, exactly as signed: RFC 8785 canonical JSON |
| `manifest.jws` | The detached JWS, absent in the `unsigned` case |
| `schema.cedarschema`, `policies/...` | The bundle's files |

## Keys

`trusted-keys.json` holds the bundle keys that a module under test trusts: a JWK Set (RFC 7517) of `OKP` keys on the `Ed25519` curve (RFC 8037), the form in which section 7.3 has enforcement points take their keys, and the file that the [driver protocol](../../driver-protocol.md) passes to a module. `untrusted-keys.json` holds, in the same form, a key that nothing trusts: it signs the `unknown-key` case, and the `forged-key-id` case under the trusted key's ID.

**These keys are for tests only.** Their seeds are public: each is the SHA-256 of `White Tower conformance test key: <name>. Never trust it outside tests.`, where `<name>` is `trusted` or `untrusted`, so anyone can sign with them. Never configure them anywhere else.

## Cases

Each case expects the outcome that steps V1 to V7 give it, in their order. A case that breaks two rules, as those that check the order of step V4 do, gets the reason of the rule checked first.

| Step | Case | Expected | What the bundle holds |
| --- | --- | --- | --- |
| All | `valid` | `activated` | A valid bundle newer than the active one |
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
| V5 | `malformed-path` | `invalid_manifest` | A policy's path without the directory of its scope |
| V5 | `mismatched-path` | `invalid_manifest` | A policy's path that names the ID of another policy |
| V5 | `mismatched-scope` | `invalid_manifest` | A global policy's path in the directory of agent-specific policies |
| V5 | `duplicate-path` | `invalid_manifest` | The global policy listed twice, in two versions, at the same path |
| V5 | `misplaced-schema` | `invalid_manifest` | A Cedar schema that is not at `schema.cedarschema` |
| V5 | `missing-file` | `missing_file` | A listed policy file is missing |
| V5 | `tampered-policy` | `file_hash` | A policy file was changed after signing |
| V5 | `extra-file` | `extra_file` | A file the manifest does not list |
| V6 | `older-version` | `older_version` | A valid bundle older than the active one |
| V7 | `parse-error` | `parse_error` | A policy that does not parse |
| V7 | `template` | `parse_error` | A policy that is a template, with a slot for its principal |
| V7 | `fails-validation` | `activated` | A policy that parses, but fails validation against the bundle's Cedar schema, which is the core's job only |

## Using them

To verify a case as an enforcement point would: trust the keys of `trusted-keys.json`, build the expectation from `case.json`, run the steps of section 7.4, and compare with `expected`. The files are generated by `bundle_vectors_test.go`; never edit them by hand, since any change breaks their signatures.

The same test file checks every manifest against [`bundle-manifest.schema.json`](../../../../api/policy/bundle-manifest.schema.json): a manifest that step V4 refuses on its own fails the schema, one that is not JSON in UTF-8 included, and the manifest of every activated bundle passes it.
