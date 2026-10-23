# RFC-0001: Module contracts v0.1

| | |
| --- | --- |
| **Status** | In review, provisionally ([GOVERNANCE.md](../../GOVERNANCE.md#rfc-process)): approved by the maintainer on 2026-09-30, and every point of the maintainer's review decided on 2026-10-22. It is accepted once the corrections are in the specification and `api/` |
| **Authors** | @J466Y |
| **Review period** | 2026-10-21 to 2026-10-22: the maintainer's provisional review, with no external reviewer. A review of at least two weeks, with an external reviewer, follows before the contracts leave alpha (`v1beta1`) |
| **Related** | Plan [P0-03](../plans/phase-0/P0-03-module-contracts.md); MOD-01 to MOD-05, MOD-08, POL-03, POL-05, POL-06, KIL-01 to KIL-04, KIL-07, KIL-10, AUD-02, NFR-20; [ADR-0004](../adr/0004-api-and-contract-formats.md), [ADR-0005](../adr/0005-edge-enforcement-with-leases.md), [ADR-0006](../adr/0006-tamper-evident-audit-log.md), [ADR-0010](../adr/0010-built-in-agent-token-issuer.md), [ADR-0011](../adr/0011-own-python-enforcement-point.md) |

## Summary

This RFC proposes the first version of the module contracts, `v1alpha1`: what an enforcement point, a policy engine, a runtime-control module or an event source must implement to plug into White Tower, and what the core guarantees in return. If you plan to build or wrap a module, this RFC affects you.

## Motivation

White Tower's value is a coordinating layer across tools that already exist (architecture, section 11). That layer is only as good as its contracts: they decide whether a policy engine can be replaced without touching the core (MOD-08), whether a halt stops an agent whatever enforcement point it runs with, and whether evidence from any module can be trusted. The Phase 0 gate is "Contracts v0.1 reviewed", and every Phase 1 plan that talks to modules (P1-06, P1-07, P1-08, P1-09, P1-15) builds on them.

## Proposal

The normative text is [module-contract-v0.1.md](../contracts/module-contract-v0.1.md); its syntax is in `api/`: the [protobuf services](../../api/proto/whitetower/module/v1alpha1/), the [manifest schema](../../api/manifest/module-manifest.schema.json), the [event catalog](../../api/events/catalog.json) and the [decision profile](../../api/policy/README.md). The specification changed after the maintainer approved this RFC on 2026-09-30: its Date row and the [progress notes of P0-03](../plans/phase-0/P0-03-module-contracts.md#progress-notes) list each change, and the review covers them all. The main choices:

1. **Four services on ConnectRPC** (registry, governance, policy, events), plus server information. A module can use a gRPC library or plain HTTP with JSON, over HTTP/2 for `Watch`, and gets its tokens through one profile of the OAuth client credentials grant.
2. **Governance state is pushed, with leases.** A snapshot, then changes in version order; renewals only when the stream is current. When the lease expires, the enforcement point denies everything and halts the agent. Reconnection backoff is bounded by a third of the lease TTL, so a returning core has every instance back within one renewal interval; spike S2 measured the difference on 1,000 enforcement points. A lease belongs to the instance and outlives a reconnection, and the version an instance applied never goes back, whichever stream brings a message. This is how the contract reads decision 6 of [ADR-0005](../adr/0005-edge-enforcement-with-leases.md): an enforcement point that connects starts closed, and one that reconnects keeps deciding on the last state it applied, never on an older one.
3. **Halts in layers, reported honestly.** Gate closed at once; work in flight interrupted where the framework allows it; the process ended only in the `terminate` mode, when work still runs after its grace period; network quarantine by runtime-control modules. Each layer is acknowledged separately, never overstated. A halt applies wherever the instance runs, and a field an instance does not know never narrows it (section 5.1).
4. **Decisions shaped as AuthZEN evaluations**, with eight actions matching the intervention points agents have, a gate checked before policies, and the combining algorithm `wt-deny-overrides-v1`. **`v1alpha1` is Cedar only**, evaluated inside the enforcement point or beside it: the review found the Rego wrapper failing open and decision points unspecified, so both wait for Phase 2. Any evaluation error denies, which is stricter than Cedar.
5. **Signed bundles**: an RFC 8785 canonical manifest, a detached JWS with Ed25519, and seven ordered verification steps with rejection reasons. No rollback.
6. **Evidence as CloudEvents 1.0**, with a per-source sequence (`wtseq`) to detect gaps, at-least-once delivery, and data minimization: no argument values, prompts or outputs.
7. **Conformance first**: 48 language-neutral vectors that pass on `cedar-go` and on `cedarpy`, a kit that plays the core over the network, and a catalog of 24 scenarios tied to numbered obligations.
8. **The environment of a decision comes from the core.** Registration returns the environment recorded for the module's credential, `production` or `non_production`, and an enforcement point puts it in the subject of every decision that evaluates policies. Without one, it allows nothing (MAN-5, I-7).

The contracts were mapped onto Microsoft AGT, OPA, Cedar and engines with native AuthZEN ([engine-mappings.md](../contracts/engine-mappings.md)). The review found two gaps that the mapping had missed, in the Rego wrapper and in decision points; with both out of `v1alpha1`, no gap is blocking.

## Compatibility and versioning

This is the first version, so nothing breaks. `v1alpha1` stays a draft until this RFC is accepted and `contracts/v0.1.0` is tagged. From then on, a published version never changes incompatibly: a breaking change creates the next version, served next to the previous one (specification, section 10). CI compares the protobuf files with the latest `contracts/v*` tag. Within a version, section 10 tells open documents, whose readers ignore what they do not know, from closed ones, which change only in a stated order: a module's release is never newer than its core's. The contract reads decision 4 of [ADR-0005](../adr/0005-edge-enforcement-with-leases.md), and NFR-01, as denying while no verified bundle is active: an enforcement point that rejects a new bundle keeps deciding with its last valid one (EP-7). Section 10 also replaces two clauses of [ADR-0004](../adr/0004-api-and-contract-formats.md): alpha versions do not break in place, and the changes that need an RFC include `api/policy` and what the conformance vectors expect, besides the three directories the ADR names.

## Security considerations

The contracts cross the main trust boundaries of the system: between the core and the agents' processes, and between the core and third-party modules. Section 11 of the specification lists the threats and what the contracts do about each. The essential properties:

- nothing is allowed without current state, a lease and a verified bundle;
- halts never depend on a module's cooperation to stop token issuance, and network quarantine acts outside the agent's process;
- acknowledgements never claim more than was done;
- bundles are signed with keys from each enforcement point's configuration, and never roll back;
- evidence is ordered, gap-detected and minimized.

The [threat model](../security/threat-model.md) (plan P0-04) analyzes these boundaries in depth.

## Alternatives

- **gRPC only.** Simpler to specify, but every module would need an HTTP/2 gRPC stack; ConnectRPC serves the same definitions over plain HTTP too, with an HTTP/2 client for `Watch`.
- **Polling instead of a watch stream.** Easier for simple modules, but a halt would wait for the next poll (ADR-0005).
- **Reusing OPA's bundle format.** Well known, but tied to one engine; its signature scheme does not bind a bundle to the governance state.
- **A custom decision format.** Rejected for AuthZEN, a final OpenID specification since January 2026.
- **Rego as the primary language.** It does not run in-process in Python (spike S1), and its combination semantics must be written by hand; Cedar's are the contract's.
- **Protobuf CloudEvents.** Compact, but the audit log hashes canonical JSON (ADR-0006), so events would be converted anyway.

## Unresolved questions

Listed in section 12 of the specification: learning rotated bundle keys from the core, how deployments manage tool arguments visible to policies (if RFC-0002 is accepted, its per-tool argument records supersede `ToolArgs`, and P0-03 step 12 closes this question), stable URLs and label prefixes (which depend on the project's domain), and what decision points and a Rego mapping must settle before Phase 2 brings them. The [threat model](../security/threat-model.md) settled DNS during network quarantine, and added one rule before the review: a lease renewal counts only if it is fresh, so that a stream held back on its way cannot delay halts (section 5.3, DC-2).

## Implementation plan

| Plan | Implements |
| --- | --- |
| P1-05 | The credentials of modules and their tokens for the module API (section 4.2), with the environment of an enforcement point's credential (MAN-5) |
| P1-06 | Policy validation against the Cedar schema, bundle building and signing |
| P1-07 | The module API in the core, the fake token endpoint and the full conformance kit |
| P1-08 | Halt tracking with layered acknowledgements |
| P1-09 | The Python enforcement point, first implementation of the enforcement point obligations |
| P1-15 | The network quarantine module, first implementation of the runtime-control obligations |
| P1-02 | Event ingestion, de-duplication and gap detection |
