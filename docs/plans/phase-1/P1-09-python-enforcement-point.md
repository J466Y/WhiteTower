# P1-09: White Tower enforcement point (Python)

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | XL, split into subplans before it starts. Proposed: **P1-09.1**, the runtime core (steps 1 to 7); **P1-09.2**, the tooling that needs no framework (the references, hashes, redaction and reports of step 9, and steps 10 and 12); **P1-09.3**, the frameworks (step 8, the discovery of step 9, and step 11); **P1-09.4**, steps 13 to 16 |
| **Depends on** | P0-05 S1 (done), P1-06, P1-07, P1-08 (only step 5 and the final measurements need P1-08; the rest can start before it); P0-03 step 12 (RFC-0002 in the contracts) for steps 9 to 12 and for the RFC-0002 parts of steps 1, 2, 4 and 6; P1-16 steps 5 and 7 for the end-to-end tests of steps 9 to 12 (step 14) |
| **Unblocks** | The catalog flows of P1-12.2, P1-13, P1-14 |
| **Requirements** | MOD-06, KIL-01, KIL-04, KIL-07, POL-03, POL-05, AUD-02, NFR-02, NFR-04, NFR-08; CAT-01, CAT-04 (applying blocks), CAT-05 to CAT-07, CAT-10 (the enforcement point's redaction) |
| **Decisions** | ADR-0005, ADR-0010, ADR-0011, [RFC-0002](../../rfcs/0002-mcp-servers-tools-and-models.md) |

## Goal

Python agents built on common frameworks are governed by White Tower. Every governed call goes through a gate and the agent's approved policies, taken from White Tower's signed bundles. A halt from the console blocks the agent in milliseconds of receipt, the agent fails closed when it loses contact, and every decision reaches the tamper-evident audit log. The enforcement point also reports the agent's MCP servers, tools and models, lets the agent use only those enabled for it, hides the rest from its model, and applies the usage rules of its policies.

## Context: why White Tower's own enforcement point

Spike S1 tested Microsoft AGT as the foundation of this plan and recommended against it; the maintainers accepted the recommendation in [ADR-0011](../../adr/0011-own-python-enforcement-point.md). The findings that shape this plan ([S1 report](../../spikes/S1-agt.md)):

- **Cedar runs in-process with our semantics.** `cedarpy` evaluates one policy set holding the global and agent-specific policies with "forbid overrides permit" and default deny, which is exactly POL-03. A set that does not parse denies everything. Decisions take p99 ≤ 1.1 ms with 100 policies, if the set is parsed once per bundle rather than per call.
- **Blocking work cannot be interrupted in-process.** Cancelling a LangGraph run stops asynchronous tools and streaming calls within milliseconds, but not a blocking call in a worker thread. The acknowledgement must say so, and only the `terminate` halt mode guarantees the work stops.
- **Evidence must be written at decision time.** A bounded in-memory queue loses events under load. The enforcement point writes each decision to a durable buffer before the action proceeds.

## Scope

**In:** a Python package, `whitetower-ep`, loaded in the agent's process: the module API client, the gate, Cedar evaluation, the halt layers, the durable evidence buffer, configuration, framework hooks; the agent's tooling (RFC-0002): discovery and tooling reports, references and redaction, the catalog check and blocks, exposure through the framework's middleware, provider-run tools, arguments and transforms; observability, conformance, measurements and packaging.

**Out:** an interoperability adapter for Microsoft AGT (Phase 2, ADR-0011; AGT is re-tested live in P1-14); non-Python agents (a TypeScript enforcement point is a Phase 2 candidate); halts outside the agent's process (network quarantine in P1-15, stopping workloads with the Phase 2 harness module); the catalog and its workflow (P1-16); the MCP network gateway and stateful usage rules (Phase 2).

## Deliverables

- `modules/ep-python/`: the package, its manifest, tests and examples.
- Two example agents (LangGraph 1.x, and a second framework the pilot needs, for example the OpenAI Agents SDK or Microsoft Agent Framework) and a `demo-agent` service in the Compose evaluation profile. Each example agent uses a local (`stdio`) and a remote (`http`) MCP server: a demo server shipped in `modules/ep-python/examples/`, run both ways, with a flag that changes its tool's description (ST-76).
- A conformance report, a measurement report and a compatibility matrix (enforcement point version × contract version × framework versions, with the MCP and provider SDKs).

## Steps

### 1. Package skeleton

- `modules/ep-python/` with a modern Python build (for example `uv`), `ruff`, strict type checking and `pytest`.
- Python 3.11 or later; CI tests the three latest minor versions.
- `cedarpy` is pinned to a version whose Cedar language matches what the core's validator accepts (P1-06). The supported framework versions are pinned in the test matrix. A weekly CI job tests against the latest releases of `cedarpy` and of each supported framework, to catch breaking changes early.
- The test matrix also pins the MCP Python SDK, the frameworks' MCP adapters and the provider SDKs, and the weekly job covers them.
- References need RFC 8785 canonical JSON, and definition hashes RFC-0002's extension of it, which writes integers exactly whatever their size (RFC-0002, section 3). A library that follows RFC 8785 strictly refuses integers beyond 2^53, so the hashes need a small implementation checked against the vectors; references may use it too, or a new dependency with its justification.
- The module manifest from P0-03, which declares `tool.expose` among its intervention points (RFC-0002), shipped as JSON, which the contracts recommend.
- The release embeds its manifest's hash, computed with the reference tool from the manifest it ships, never taken from its configuration (contracts, section 3.2).

**Done when:** the package builds and its CI runs, including the weekly job.

### 2. Core client

- Python stubs generated by Buf for the module API.
- Token acquisition with `private_key_jwt`, sharing test vectors with the Go helper of P1-05, and a token cache that refreshes early. The enforcement point authenticates as the agent it serves (P1-05).
- The watch loop runs in a dedicated thread, so it serves both synchronous and asynchronous agents. The lease timer uses the monotonic clock, only fresh renewals renew it, and stale ones show in the heartbeat's health (contracts section 5.3). Reconnection uses jittered backoff. The loop keeps the highest version it applied across its streams and never lowers it (contracts, section 5.2), and treats a stream that stays silent past the renewal interval plus 5 seconds as failed, reconnecting on a new connection (I-9).
- The instance key is a random ID created with the evidence buffer and stored in it: unique to the process, and the same across its restarts (I-8).
- `RegisterInstance`, `Heartbeat`, `Acknowledge`, `GetBundle` and `Publish`, and, for step 9, `ReportTooling` and `ReportDefinitions`.
- The watch loop applies the blocks of snapshots and changes into the same immutable snapshot as the state, and acknowledges at once the state version that carries a new block (EP-15), apart from the 60-second rhythm of EP-12.
- The core's resolved addresses are kept, and reused when name resolution fails, still checking the certificate against the configured name: a quarantined pod has no DNS ([threat model](../../security/threat-model.md), DC-7).

**Done when:** the client connects to a real core, survives core restarts and passes the lease scenarios of the kit.

### 3. Governance gate

The first check of every hook (step 8). It denies, with a reason, when:

- no state has been received yet;
- the lease has expired;
- the agent or the fleet is halted;
- the lifecycle state closes the gate ([lifecycle](../../architecture/lifecycle.md), section 1);
- no valid bundle is active;
- the evidence buffer is full (step 6).

The gate reads an immutable snapshot of the state, swapped atomically by the watch thread. Blocks travel in the same snapshot, but the catalog check of step 10 applies them, after the gate: the gate's conditions do not change.

**Done when:** unit tests cover each condition, mirroring the conformance vectors.

### 4. Policy evaluation

When a new bundle reference arrives:

1. Fetch it with `GetBundle`.
2. Verify the JWS signature against the core's bundle keys (trust configured at installation), every file hash, including the catalog's (V4 accepts the manifest's `catalog` field, and V5 requires its file), and that its version is newer than the active one.
3. Parse the Cedar policy set once, as static policies (V7), and validate it against the bundle's own Cedar schema, which declares one argument record per tool (RFC-0002, section 7.6), for diagnostics only: a policy that fails validation is logged and the health reports `HEALTH_DEGRADED`, but the bundle is not rejected for it (contracts, section 7.4). Parse the catalog file (`catalog.json`) once, against its schema (V7, `parse_error`), and index it by reference. A bundle without a catalog counts as an empty catalog: every tool and model action is then `catalog.unknown`.
4. Swap it in atomically and acknowledge the activation.

A bundle that fails verification is handled by the P0-03 rule: keep the last valid bundle, never run without one, and raise an alert event.

For each governed call, build the request of the decision profile (principal, action, resource, context) from the hook's context and evaluate it. For tool and model actions, the resource's ID is its catalog key, and its properties come from the catalog, never from the agent; an MCP tool's parent is its server, `WhiteTower::McpServer::"<key>"`, and the context of `model.invoke` gains `digest`. The decision records the policies that determined it, and the usage rules (`@rule`) among them, each by its policy ID and rule ID.

**Done when:** the kit's bundle scenarios pass (unsigned, tampered, older, and bundles with a catalog), and the combination vectors produce the expected decisions.

### 5. Halt layers

When the agent or the fleet is halted:

1. **Close the gate at once:** every governed call and interaction is denied.
2. **Interrupt the work in flight** through the framework's own cancellation (for example cancelling the running graph's task), as registered by the hooks of step 8.
3. **Apply the agent's halt mode:**
   - `block`: gate only;
   - `interrupt`: gate plus cancellation;
   - `terminate`: all of the above, then, if work is still running at the end of a grace period (10 seconds by default), the process ends. Just before, it writes `instance.halted` to its durable buffer, reports `process_terminated` `done` as its last report for that halt, and waits at most about a second for the response. A release during the grace period cancels the end (contracts, section 5.5).
4. **Acknowledge** each layer with its timestamp, honestly: if blocking work is still running after the grace period, report "in-flight action not interrupted".

On release, the gate reopens only if the lease and the bundle are valid. A terminated agent is restarted by its supervisor (for example Kubernetes) and starts closed until its state arrives (KIL-07). A process that starts while its agent is halted stays up and closed until the release, and never ends itself for that halt (contracts, section 5.5).

A change that carries a halt and blocks closes the gate first; the gate's acknowledgement never waits for the blocks to be applied.

**Done when:** the kit's halt scenarios pass, and the measurements of step 15 meet NFR-04.

### 6. Evidence and durable buffer

- Write each decision, and each governed action's outcome, to a local SQLite file in WAL mode **before** the action proceeds. Events follow the catalog of the module contracts (`decision.made` for every decision, allowed or denied, and `action.executed` for the outcome of allowed calls), with the White Tower agent ID as subject, `wtseq` and the trace context, and with arguments recorded as the contracts' privacy rules require (names, or an HMAC, never values).
- With RFC-0002, `decision.made` also names the usage rules that decided, each by its policy ID and rule ID, and the resource's origin. The provider-run calls that a model response reports are `action.executed` events with origin `provider`, without a `decision_id` when no decision preceded them. An exposure decision is recorded when it is evaluated; reusing it writes nothing.
- Size the buffer for NFR-08 (24 hours at 10 events per second), counting exposure decisions, and cap it. Publish in batches, with retries and respect for backpressure.
- When the buffer is full, close the gate: no action without evidence.
- Keep the buffer on storage that outlives the container, such as a volume: a buffer that lives only as long as its pod loses what it has not delivered when the pod goes. Deliver it, within the platform's grace period for termination, before deregistering or ending the process, `terminate` included (contracts, I-5).
- Send each source's events in order, one `Publish` call at a time, and send them again first after a failure (I-12). Report `HEALTH_DEGRADED` once the oldest undelivered event is older than a threshold, and `HEALTH_UNHEALTHY` while the buffer is full (contracts, sections 4.9 and 8.4).
- The hashed mode of arguments takes its key from a file and the key's ID from a setting (contracts, section 8.3).

**Done when:** after a one-hour core outage under load, every event arrives once reconnected, with no gap in `wtseq`.

### 7. Configuration and identity

- Configuration: agent ID, core URL, credentials (a key file, or Kubernetes workload identity through P1-05), the bundle trust root and the buffer location, from a file or environment variables. It names no environment: the enforcement point takes the environment of its credential from `RegisterInstanceResponse`, and puts it in the subject of every decision (contracts, section 6.2). The enforcement point never reads it from its access token, which RFC 9068 (section 6) forbids a client to inspect ([design note](P1-08-kill-switch.md#progress-notes), section 13, decision 7).
- Invalid or incomplete configuration keeps the gate closed and says why; it never falls back to allowing. A private key file that other users can read is invalid configuration.
- The owner's personal data never reaches the agent's process: the enforcement point knows the owner only by pseudonymous principal ID.

**Done when:** each misconfiguration is covered by a test that shows the gate staying closed.

### 8. Framework hooks

Start with LangGraph 1.x, then the second framework the pilot needs. Each integration:

- routes every tool call, model call, input and output through the gate and the policies, and denies by raising the framework's own error or refusal;
- registers the cancellation used by the halt layers;
- registers what step 9 discovers: MCP sessions and their tool lists, function tools, model clients, and the provider-run tools that model requests declare;
- routes every tool and model call through the catalog check by reference (step 10), and every model request through exposure (step 11);
- applies what a denial does, action by action, as section 6.3 of the contracts lists, and never keeps the agent from stopping;
- waits, before the framework starts the agent, until the gate can open (EP-1), for a configurable time at most, which a test checks;
- maps the framework's names of model providers to the contracts' table of providers (section 6.3).

A small generic API (a decorator and a context manager) covers custom agents and tools outside the supported frameworks. The examples live in `modules/ep-python/examples/`, and the Compose `demo-agent` service uses one of them.

**Done when:** each example runs governed end to end.

### 9. Discovery and tooling reports (EP-13, EP-14; CAT-01, CAT-10)

Steps 9 to 12 are the enforcement point's side of RFC-0002, which the hooks of step 8 feed in each framework. The enforcement point finds the tools bound to the agent, the MCP servers it launches or connects to with the tools they list, the models it calls, and the tools its model requests ask the provider to run.

- **References**, exactly as RFC-0002, section 3, says: URLs normalized as it says, with the host that `url_host` reads; `connector:<provider>/<connector ID>`; `stdio:` followed by the RFC 8785 canonical JSON of the array of the command and its arguments, after redaction, the deployment's rules included. A tool or a model is written as the RFC 8785 canonical JSON of an object of its parts: `name` and `server` for an MCP tool, `name` for the agent's own tool, `provider` and `type` for a built-in tool, and `endpoint`, `name` and `provider` for a model, whose endpoint is always there, the provider's default included.
- **Hashes.** A tool's definition hash is the SHA-256 of the canonical JSON of the members that section 3 lists for its kind. For an MCP tool, they are read from the `tools/list` message itself, for example from the transport's messages before the SDK parses them, since the SDK's objects add defaults and drop members. Integers are written exactly, and a definition that section 3 leaves without a hash is reported without one. Built-in tools have no definition. The enforcement point also hashes what blocks name (step 10): the string form of each reference, the provider's name and the endpoint's base URL. All these hashes are computed when a tool list or a model changes, never on each call.
- **Reports** go out before the gate first opens (SHOULD), and again when an MCP server connects or sends `notifications/tools/list_changed`, when a model is first called, and when a request declares a provider-run tool not reported yet. A report covers what the agent is configured with, not only what it called, and carries each tool's definition hash. The definitions the core does not have, which its response lists, follow through `ReportDefinitions`, at most 4 MiB per call. Reports are coalesced to the latest one, sent within the core's rate limit (one per instance and agent every 10 seconds), and retried with backoff. A report over the limits is not retried as it is, and the heartbeats report `HEALTH_DEGRADED`.
- **Redaction (EP-14)**, before anything leaves the process:
  - no environment variables, headers or authorization values;
  - URLs lose their user information, query and fragment, including URLs passed as arguments;
  - `<redacted>` replaces the value of an argument that follows a flag, or is joined to it as `--flag=value`, when the flag's name contains, in any case, `token`, `secret`, `password`, `passwd`, `key`, `auth`, `credential` or `cookie`;
  - the deployment's redaction rules, from the active bundle's catalog file, replace the path segment that follows each of their URL prefixes, in URLs normalized as section 3 says, arguments included, and the values of the flags they name. Before the first bundle, the enforcement point reports without them, and the core applies them (CORE-11); references are computed again when a bundle brings other rules.

**Done when:** the vectors of references, definition hashes and redaction pass, and so do S-18, S-24 and ST-77: canary secrets placed in URLs, in the command-line arguments that EP-14 redacts and in environment variables never appear in anything sent to the kit's fake core, nor in the enforcement point's logs, and neither does one in a URL path segment that a redaction rule names, once a bundle has brought the rule. A secret in a positional argument, or in a URL path that no rule names, is beyond EP-14; the guide says to pass secrets through the environment. The core's own redaction (CORE-11) is tested in P1-16.

### 10. Catalog check and blocks (EP-15, EP-16; CAT-04, CAT-05)

- For `tool.invoke`, `tool.expose` and `model.invoke`, after the gate and `error.unknown_agent`, and before `error.invalid_request` and policies, deny with the first reason that applies, in the six-row order of RFC-0002, section 7.1: `catalog.blocked`, `catalog.unknown`, `catalog.not_approved`, `catalog.not_enabled`, `catalog.definition_changed`, `catalog.digest_mismatch`. For `tool.result` and `model.result`, only the block row applies, so a block also withholds the result of a call in flight.
- A catalog denial carries the bundle's version and no determining policies. Tooling that the catalog does not list is named by its name as the agent sees it, with `reference_sha256`, and a denial by a block carries its `block_id` (RFC-0002, section 9).
- Resolve the tool or the model by its reference at the time of the call, never by its name alone; anything unresolved is `catalog.unknown`. Blocks come first, so they also cover entries the bundle does not list.
- **Blocks** are matched by the SHA-256 of the string form of what they cover: the reference of a server, a tool or a model, the name of a provider, or the normalized base URL of an endpoint. A block of a server covers its tools. Blocks are indexed by kind and hash, so a call costs a few lookups, never a scan of 500 blocks. A block of a kind the enforcement point does not know denies every tool and model call while it is active. A snapshot's blocks replace the whole set, and a change adds and removes blocks by ID. Once a block is applied, the enforcement point acknowledges at once a state version at or above the block's, for one of the agents it serves (EP-15).
- A pinned model digest is checked against the runtime's, for example the digest that Ollama lists for the model, cached per endpoint and model. An unknown digest denies.

**Done when:** the catalog-check vectors, S-19 and S-20 pass.

### 11. Exposure and provider-run tools (EP-17, EP-18; CAT-05, CAT-07)

- **Exposure.** Before each model call, evaluate `tool.expose` for every tool the request offers, with `calls_decided` (RFC-0002, section 7.3), and remove the denied ones through the framework's middleware: in LangGraph 1.x agents, for example, LangChain's `wrap_model_call` middleware can replace the request's tools, and the second framework has its own equivalent. When a denied tool cannot be removed, deny the model call in every case: RFC-0002 requires it for provider-run tools and changed definitions, and recommends it otherwise.
- **Reuse.** Exposure decisions are kept until the bundle, the agent's state, the blocks, the tool's definition or whether its calls are decided change, and recomputed off the call path after each change. Only an evaluated decision is recorded (step 6).
- **Provider-run tools.** Narrow each declared remote MCP server to the tools enabled for the agent, for example through the declaration's list of allowed tools, and deny the model call when the provider could call a tool that is not enabled (ST-82). Where the provider can submit each call for approval, have it do so for every provider-run tool that a usage rule of the bundle names, for example through the `require_approval` setting of an OpenAI `mcp` tool, and decide each submitted call with `tool.invoke` and its arguments (CAT-07, EP-18). `calls_decided` is true only for the provider-run tools whose calls are submitted. Record the provider-run calls a response reports as `action.executed` events with origin `provider`.
- **Definitions seen in responses.** The provider lists a remote server's tools itself, so the enforcement point sees their definitions only in responses. When a response lists a provider-run MCP tool whose definition differs from the pinned one, deny its exposure from then on (`catalog.definition_changed`). The model may already have seen it in that response: a residual the threat model records (T-79, A-7).

**Done when:** the exposure vectors, S-21, S-22 and ST-82 pass.

### 12. Arguments and transforms (EP-19; CAT-06)

- Fill `context.args["<tool key>"]` with the declared arguments only (the catalog's `args`): each under its name, read at its path, an array of property names through objects only, with its transform and the type the catalog declares.
- Apply the transforms exactly:
  - `lowercase`: ASCII letters only;
  - `path`, `url_host` and `email_domain`: as RFC-0002 section 7.5 defines them, never through the standard library's parsers. `posixpath.normpath` keeps a leading `//`, and `urllib.parse` reads some hosts otherwise than requests and Node do;
  - hosts to A-labels as WHATWG converts them, without the STD3 rules: the `idna` package's `uts46_remap` with `std3_rules=False` and `transitional=False`, then Punycode, rather than `idna.encode`, which applies IDNA 2008 and refuses the underscores of names such as `my_service.internal`.
- Arrays of strings or of integers become sets, transformed element by element. A value that does not fit its declared type, or that a transform cannot read, denies the call with `error.invalid_request`. A missing argument is left out, so usage rules apply `if_absent`. Values never reach evidence.

**Done when:** the argument vectors pass with `cedarpy` (ST-79), and so does S-23. P1-16 runs the same vectors on `cedar-go`.

### 13. Observability

OpenTelemetry metrics: gate state, remaining lease, active bundle version, buffer depth, decision latency, halt timings; and, for RFC-0002, catalog denials by reason, exposure cache hits, reports by outcome, active blocks and the time to apply a block. Logs are structured, and they never include prompts or tool payloads unless explicitly enabled. Reported descriptions and schemas never reach them.

**Done when:** the metrics appear in the Compose stack's collector.

### 14. Conformance and end-to-end tests

- Run the conformance kit against the enforcement point, wrapping a sample agent, S-18 to S-24 included.
- End-to-end test in Compose: register an agent, approve it and its policy, activate it; the demo agent runs and its decisions reach the audit log; halt it and check the gate closes within target; release and reinstate it.
- Once P1-16 steps 5 and 7 are merged, the end-to-end test adds the tooling: the demo MCP server is discovered, approved and enabled, then usable; its tool's description changes, and the tool is denied and hidden until the new definition is approved (ST-76); a block denies without a new bundle.
- **The live test of blocks.** The maintainer decided on 2026-10-26 that the rules of RFC-0002's blocks record and EP-15's acknowledgement stay provisional until a live test, with real enforcement points in a real environment, confirms them. With several of these enforcement points, and P1-07's mock module as an instance that serves several agents, the test issues and lifts blocks, cuts and restores streams so that a snapshot replaces the set, and checks that each block's spread in the console matches what each enforcement point applied. It runs in the Compose stack with the end-to-end test, and once on Kubernetes, from P1-12's Helm chart. Its findings go to the review of RFC-0002 that precedes `v1beta1`.

**Done when:** both run in CI, the live test of blocks included, and the live test has run once on Kubernetes.

### 15. Measurements

Measure, with the pilot's frameworks:

- decision overhead including the gate, the catalog check and the transforms (NFR-02);
- the overhead of exposure with 10 and 100 tools offered, with cold and warm caches;
- the time from receiving a block to denying what it covers;
- halt effect: gate closing, in-flight interruption, termination (NFR-04);
- buffer durability during a core outage (NFR-08).

These numbers are evidence for the Phase 1 gate.

**Done when:** the report is in `docs/performance/`.

### 16. Packaging and documentation

- A wheel built in CI, signed with Sigstore, with an SBOM, published as `whitetower-ep`.
- An installation guide, the compatibility matrix and a troubleshooting section.
- The guide says what each integration discovers and can narrow, what redaction misses (secrets in positional arguments, and in URL paths that no redaction rule names), and what each `catalog.*` reason means.

**Done when:** a pilot engineer can instrument a new agent from the guide alone.

## Acceptance criteria

- The enforcement point passes the full conformance suite, S-18 to S-24 included, and the vectors of RFC-0002: references, definition hashes, redaction, the catalog check, arguments and exposure.
- The end-to-end demonstration runs with two frameworks: decisions in the audit log, halts effective within NFR-03 and NFR-04, and fail-closed within the TTL during a partition. With both frameworks, an MCP tool is usable only once approved and enabled, a changed definition is denied and hidden until approved, and a block denies without a new bundle.
- Decision overhead within NFR-02 (in-process p99 ≤ 5 ms, gate, catalog check and transforms included).
- The weekly job against the latest releases of `cedarpy`, the supported frameworks, and the MCP and provider SDKs is running.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-09-python-enforcement-point) pass: ST-46 to ST-53, ST-76, ST-77, ST-79 and ST-82.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| Framework hook points change between releases | Pinned test matrix, weekly job against the latest releases, thin hooks, compatibility matrix |
| A tool or model call bypasses the hooks (for example a raw HTTP call) | Document what each integration covers; the generic API for custom code; network quarantine (P1-15) and the Phase 2 gateways as layers that do not depend on the hooks |
| `cedarpy` and the core's Cedar validator disagree on a language feature | Pin matching versions; the core rejects features the enforcement point cannot evaluate (P1-06); shared vectors run against both in CI |
| Interrupting in-flight calls is unreliable in some frameworks | Halt modes, with `terminate` as the guaranteed option; honest layered acknowledgements |
| Mixing threads and `asyncio` in agent processes | The watch loop is isolated in its own thread; tests in both kinds of agents |
| A framework hides its MCP connections, or the tools its model requests declare, from the hooks | The generic API lets the agent declare them; what the enforcement point cannot resolve is unknown, and denied |
| A framework or provider does not let the enforcement point change a request's tools | Deny the model call; the compatibility matrix says which integrations can narrow |
| Python and the core's Go compute different definition hashes (integers beyond 2^53, `null` members, the SDK's objects instead of the wire form, Unicode, key order) | RFC-0002's canonical JSON, with integers written exactly; definition-hash vectors run on both stacks |
| A framework or Pydantic upgrade changes the generated parameter schemas, so every function tool is denied as `catalog.definition_changed` | Pinned versions; the weekly job flags the change; the compatibility matrix records it |
| Local servers launched through paths or versions that change on each start produce new references, and flood the catalog | Documented stable launch commands; the limits of reports and the bound on each agent's entries waiting for review (DC-10), beyond which new references are left out and denied, so the problem shows at once |
| Parsers differ (T-78): Python's own read `http://evil.com\@good.com/` as two hosts, `good.com` for `urlsplit`, httpx and yarl, and `evil.com` for urllib3 and requests, while Go's `net/url` refuses it | `url_host` refuses what parsers read differently (RFC-0002, section 7.5); transforms implemented to the RFC and its vectors, not to the standard libraries' defaults |
| Secrets in positional arguments, or in URL paths that no redaction rule names, escape EP-14 | The deployment's redaction rules; the core redacts again (CORE-11) and flags URL paths that look like they hold a secret (P1-16); the guide says to pass secrets in the environment, which is never reported |

## Notes for implementers

- The gate check must be cheap (a read of an immutable snapshot, 59 ns in S1); it runs on every hook. The catalog check must stay as cheap: dictionary lookups in the same snapshot.
- Drop the exposure cache atomically with the bundle, the state or the blocks it was computed from.
- Treat the core's bundle keys as the trust root; ship them through configuration, as a JWK Set of `OKP` keys on `Ed25519` (contracts, section 7.3), and never fetch them over an unauthenticated channel.
- Keep framework-specific code in thin integration modules, so a framework upgrade touches one file.
- Reconnect as spike S2 validated, with the session backoff of I-4: full jitter, capped at a third of the lease TTL and reset once the instance receives a fresh renewal, the client library's own reconnect backoff included (for grpcio, `grpc.initial_reconnect_backoff_ms` and `grpc.max_reconnect_backoff_ms`). `Publish` and the reports use the backoff of the other calls, capped at 60 seconds. HTTP/2 pings every 10 seconds or more (for grpcio, `grpc.keepalive_time_ms` and `grpc.keepalive_timeout_ms`), and the silence rule of I-9, find a dead connection before the lease expires.
- Follow the contract clarifications of the halt path's [design note](P1-08-kill-switch.md#progress-notes) (section 13, decisions 2, 6 and 7):
  - apply every agent state a change carries, whatever that state's own version: an agent that enters the scope keeps its older version;
  - treat a failure of an established `Watch` stream as transient whatever its code, except `PERMISSION_DENIED`, which ends every lease at once before the enforcement point registers again with backoff, and get a new token first after `UNAUTHENTICATED`: connect-go, for one, reports a stream cut in the middle of a message as `INVALID_ARGUMENT`;
  - accept a renewal whose version skips versions that carried nothing for the stream: that is no gap;
  - accept a snapshot in answer to any resumption, even at a version the core moved forward after a regression, and replace the state with it;
  - apply every halt wherever the instance runs: a field the enforcement point does not know never narrows a halt, and the environment that `RegisterInstanceResponse` returns (step 7) never decides what a halt covers;
  - decode JSON discarding unknown fields, as connect-go's codec does: Python's `json_format.Parse` refuses them by default, as Go's protojson does, so pass `ignore_unknown_fields=True`; otherwise S-13 fails (EP-10).
- Follow the corrections from the review of RFC-0001 ([P0-03's progress notes](../phase-0/P0-03-module-contracts.md#progress-notes), 2026-10-22):
  - close the gate for every agent before deregistering, and allow nothing afterwards (I-5);
  - ignore a renewal more than the tolerance before or after the local clock (section 5.3);
  - count a lease TTL above 300 seconds as 300, and a zero or absent one as renewing nothing (section 5.3);
  - refuse a snapshot whose first part lacks the fleet state, keeping the current state (section 5.2);
  - keep the heartbeat interval in force when a response carries none, or one that is not positive (I-6);
  - deactivate the bundle when the state stops naming one, keeping its version as the floor of V6 (EP-7);
  - lose at once the state and the lease of an agent that leaves the scope, and drop the acknowledgements queued for it (I-11);
  - verify the active bundle again whenever the configured bundle keys change (section 7.3);
  - request tokens as the profile of section 4.2 says (I-10): the issuer's metadata, the agent ID as client ID, the issuer identifier alone as the assertion's `aud`, and the module API's resource;
  - use HTTP/2 for `Watch`, and set no deadline on it (sections 4.1 and 4.6).
