# Conformance kit

Checks that a module implements the module contracts ([specification, section 9](../../docs/contracts/module-contract-v0.1.md#9-conformance)). This is the skeleton built in plan P0-03; plan P1-07 completes it.

## What is here

| Path | Content |
| --- | --- |
| [`vectors/`](vectors/) | Language-neutral test vectors: combination semantics, the gate, signed bundles, module manifests |
| [`profile/`](profile/) | Reference implementation of the decision profile on `cedar-go`: the check of requests against the profile, request mapping, combining algorithm, gate |
| [`bundle/`](bundle/) | Reference implementation of the bundle format: canonical manifests, signatures, verification |
| [`manifest/`](manifest/) | Reference reader of module manifests written in YAML: MAN-1's refusals, I-JSON, canonical JSON |
| [`kit/`](kit/) | The kit: a fake core that speaks the module API, the driver client, and the scenarios |
| [`stubep/`](stubep/) | A minimal enforcement point in Go, enough to run the scenarios end to end. Not a product |
| [`python/check_vectors.py`](python/check_vectors.py) | The vectors checked with Python: `cedarpy`, `cryptography`, PyYAML and `jsonschema` |
| [`driver-protocol.md`](driver-protocol.md) | How the kit tells a module under test what to do |

## How the kit works

The kit plays the core. It serves the module API (registry, watch with scripted state and leases, bundles, acknowledgements, events) over HTTP/2 with TLS, and drives the module under test through a small HTTP protocol, the driver. Because both sides are network protocols, the kit tests a module written in any language.

A scenario scripts the core's side, then checks what the module decides and what reaches the core: registrations, acknowledgements and events. Scenarios never trust what a module says about its own state.

Scenarios S-01, "start closed", and S-17, "stale renewals", run today against the stub enforcement point. The other thirty scenarios of the specification are designed and are implemented in P1-07, each tied to the obligations it checks.

## Running it

```sh
go test ./test/conformance/...                 # vectors (Go, cedar-go, yaml.v3), the stub's own tests, and scenarios S-01 and S-17 against the stub
python test/conformance/python/check_vectors.py  # the same vectors with cedarpy, cryptography, PyYAML and jsonschema
```

The Python check needs `cedarpy`, `cryptography`, PyYAML and `jsonschema`; the virtual environment of `hack/spikes/agt` has all four. It reads manifests from PyYAML's events, never its types, since PyYAML reads YAML 1.1. It reads the `$` that ends the request schema's patterns at the end of the string only, as ECMA-262 does, where Python's regular expressions also match it before a final line break.

## Changing the vectors

- `combination.json` and `fail-closed.json` are edited by hand. Both implementations must still pass.
- The bundle vectors are generated, because their signatures must match their bytes: change `bundle_vectors_test.go`, then run `go test ./test/conformance -run TestBundleVectorsAreCurrent -update`.
- The manifest vectors are generated from the examples of `api/manifest` and the documents of the reader's tests, so that they follow both: after either changes, run `go test ./test/conformance/manifest -run TestManifestVectorsAreCurrent -update`.
- Vectors are part of the contract: changing their meaning needs an RFC.
