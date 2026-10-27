# Module contracts v0.1

| | |
| --- | --- |
| **Status** | Accepted provisionally in [RFC-0001](../rfcs/0001-module-contracts-v0.1.md) on 2026-10-23, with the tooling of agents from [RFC-0002](../rfcs/0002-mcp-servers-tools-and-models.md), accepted provisionally on 2026-10-26. Contract version `v1alpha1`, a draft until `contracts/v0.1.0` is tagged (section 10) |
| **Date** | 2026-09-29; updated 2026-09-30 (fresh lease renewals, from the [threat model](../security/threat-model.md)), 2026-10-02 (how message sizes are measured, from P1-01), 2026-10-09 (the core's request IDs in its events, from P1-02), 2026-10-20 (where halts apply, four clarifications of the watch stream, and the environment that registration returns, from the [design of the halt path](../plans/phase-1/P1-08-kill-switch.md#progress-notes)), 2026-10-21 (a conformance scenario for every module obligation, from [P0-03](../plans/phase-0/P0-03-module-contracts.md#progress-notes)), 2026-10-22 and 2026-10-23 (changes to what the conformance vectors expect need an RFC, and the corrections from the review of RFC-0001, which [P0-03's progress notes](../plans/phase-0/P0-03-module-contracts.md#progress-notes) list) and 2026-10-26 (the MCP servers, tools and models of agents, from [RFC-0002](../rfcs/0002-mcp-servers-tools-and-models.md): sections 4.10, 5.10, 6.9 to 6.11 and 7.7, and the sections they change) |
| **Plan** | [P0-03](../plans/phase-0/P0-03-module-contracts.md) |
| **Machine-readable parts** | [`api/proto/whitetower/module/v1alpha1/`](../../api/proto/whitetower/module/v1alpha1/), [`api/manifest/`](../../api/manifest/README.md), [`api/events/`](../../api/events/README.md), [`api/policy/`](../../api/policy/README.md) |
| **Conformance** | [`test/conformance/`](../../test/conformance/README.md) |
| **Related** | [ADR-0004](../adr/0004-api-and-contract-formats.md), [ADR-0005](../adr/0005-edge-enforcement-with-leases.md), [ADR-0006](../adr/0006-tamper-evident-audit-log.md), [ADR-0010](../adr/0010-built-in-agent-token-issuer.md), [ADR-0011](../adr/0011-own-python-enforcement-point.md), [domain model](../architecture/domain-model.md), [lifecycle](../architecture/lifecycle.md) |

These contracts let any product be wrapped as a White Tower module: an enforcement point inside an agent, a gateway, a policy engine or a component that isolates workloads. A module that follows them can replace another without any change to the core (MOD-08).

The contracts have seven parts: the capability taxonomy (section 2), the module manifest (3), the module API (4), the governance state with its leases and halts (5), the decision profile (6), the policy bundle format (7) and the event catalog (8). Section 9 describes how conformance is checked, section 10 how the contracts evolve, and section 11 what they protect against.

---

## 1. Conventions

- **Keywords.** MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in capitals.
- **Obligations are numbered**, so tests and reviews can name them: `I-n` for every module instance, `EP-n` for enforcement points, `RC-n` for runtime-control modules, `MAN-n` for how the core handles manifests, and `CORE-n` for what the core guarantees in return. The obligations of modules each have a conformance scenario (section 9.3).
- **Formats.** JSON is UTF-8. Timestamps are RFC 3339, in UTC, with milliseconds (`2026-09-29T10:15:02.118Z`). Identifiers are lowercase UUIDs (UUIDv7 when White Tower creates them). Hashes are lowercase hexadecimal SHA-256.
- **Canonical JSON** is RFC 8785, which applies to I-JSON (RFC 7493): member names are unique, and numbers are exactly representable as IEEE 754 doubles, so integers have a magnitude of at most 2^53 - 1. Each use says what happens to other input: a manifest that is not I-JSON is refused (MAN-1), never rounded, and a tool's definition is hashed with its integers written exactly (section 4.10).
- **Terms** are those of the [domain model](../architecture/domain-model.md#2-glossary).
- **The machine-readable files are normative for syntax, and this document for behavior.** A disagreement between them is a bug in the contract. Until it is fixed, implementations follow whichever reading denies more.

## 2. Capabilities

A module declares one or more capabilities in its manifest. Four are specified in `v1alpha1`; eight more are reserved, so later phases can specify them without renaming anything.

| Capability | Status in `v1alpha1` | What the core expects from it | Module API it uses | Events it emits |
| --- | --- | --- | --- | --- |
| `enforcement-point` | Specified | Applies governance to the agents it serves at runtime: a gate before every governed call, the catalog check, policy decisions, halts, evidence, and reports of the agents' tooling (section 4.10) | All services | Decisions, actions, halts, bundles, leases |
| `policy-engine` | Specified | Evaluates decision requests with the profile and the combining algorithm of section 6, embedded in an enforcement point: it serves only that module's enforcement points, and evaluates exactly the bundle they verified. Decision points that others call through AuthZEN wait for `v1beta1` (section 6.8) | None | None of its own |
| `runtime-control` | Specified | Acts on halts outside the agents' processes: in `v1alpha1`, the network quarantine of Kubernetes workloads (KIL-10, section 5.8). Evaluates no policy | Registry, `Watch`, `Acknowledge`, `Publish` | Quarantine events, leases |
| `event-source` | Specified | Publishes the event types its manifest declares | Registry, `Publish` | Those it declares, among the types the catalog lists for event sources (MAN-6) |
| `mcp-gateway` | Reserved, Phase 2 | An enforcement point for tool calls through MCP | | |
| `llm-gateway` | Reserved, Phase 2 | An enforcement point for model calls, with quotas and cost | | |
| `skills-repository` | Reserved, no longer planned | Reviewed, signed skills for agents; the name stays reserved, so that nothing is renamed if skills return ([RFC-0002](../rfcs/0002-mcp-servers-tools-and-models.md)) | | |
| `harness` | Reserved, Phase 2 | Enforced execution environments; stopping workloads on a halt | | |
| `observability` | Reserved, Phase 2 | Consumes events for dashboards and analytics | | |
| `identity-source` | Reserved, Phase 2 | External issuers of agent identities | | |
| `compliance` | Reserved, Phase 3 | Evidence packages and GRC export | | |
| `discovery` | Reserved, Phase 3 | Finds agents that are not in the inventory | | |

The charter's eight module types all have a place: the policy engine is `policy-engine`; the MCP and LLM gateways are `mcp-gateway` and `llm-gateway`, and will also declare `enforcement-point`, with the actions each must evaluate; the skills repository, observability, compliance and discovery have their own names; the harness or sandbox is `harness`, and will also declare `runtime-control`.

## 3. Module manifest

### 3.1 Format

A manifest is a YAML or JSON document with `apiVersion: whitetower/v1alpha1` and `kind: ModuleManifest`, validated by [`module-manifest.schema.json`](../../api/manifest/module-manifest.schema.json). [Examples](../../api/manifest/examples/) exist for the mock module, the Python enforcement point and the network quarantine module.

A JSON manifest is used as it is, and JSON manifests are RECOMMENDED. A YAML manifest is read under the YAML 1.2 Core schema, and MAN-1 also refuses in it anchors, aliases, merge keys and explicit tags, and any unquoted scalar that would not be a plain string under both YAML 1.1 and YAML 1.2, unless it is `true`, `false`, `null` or a plain decimal number: `yes`, `no`, `on`, `off`, `y` and `n`, octal, binary and sexagesimal forms, numbers with underscores or exponents, and dates. The core checks the document's tree of nodes rather than trusting its decoder.

| Field | Meaning |
| --- | --- |
| `metadata.name` | The module's slug, unique in a deployment |
| `metadata.version`, `vendor`, `license`, `homepage`, `description`, `displayName` | What the console shows; the version is SemVer 2.0 and the license an SPDX expression |
| `spec.contractVersions` | Contract versions the module implements: any well-formed version, from which the core chooses at registration (CORE-3) |
| `spec.identity` | `agent`: instances run inside an agent's process and authenticate as that agent; only an enforcement point may declare it. `module`: instances authenticate with the module's own identity |
| `spec.agents` | Which agents instances serve: `self` (the agent they run in), `bound` (agents an operator binds to the module), `all` (every agent, through one binding to all agents) |
| `spec.capabilities` | The capabilities, each at most once, with its own settings: intervention points, halt modes and layers for an enforcement point; languages and combining algorithms for a policy engine; layers and platforms for runtime control, which `v1alpha1` limits to the layer `network_quarantined` on the platform `kubernetes` |
| `spec.events.emits`, `spec.events.consumes` | Event types the module publishes, and consumes (always empty in `v1alpha1`) |
| `spec.permissions` | What instances may do through the module API (section 3.3) |
| `spec.endpoints` | Endpoints others may call, such as an AuthZEN decision point (section 6.8). None are required in `v1alpha1` |
| `spec.configSchema` | A JSON Schema of the module's own configuration |

### 3.2 Registration and approval

A module has a set of approved manifests, typically one for each release it runs. An operator registers a manifest and another step approves it (MOD-02). The core stores each manifest and the SHA-256 of its canonical JSON (section 1). Instances present that hash when they register, and the core applies to each instance the manifest it registered with: its permissions, the types it emits and its capabilities. An instance takes the hash from its release, a constant that the reference tool computes from the manifest the release ships, never from its configuration, which would let it present a manifest it does not run.

- **MAN-1.** The core MUST refuse a manifest that does not validate against the schema, which includes one that declares a reserved capability.
- **MAN-2.** The core MUST refuse the registration of an instance whose module is not approved, or whose `manifest_sha256` is not the hash of one of the module's approved manifests. The error carries only the hash presented; the console and `wtctl` show both.
- **MAN-3.** A changed manifest is a new manifest of the module, which MUST be approved on its own before instances that run it can register; its registration leaves the approved ones in force. An operator retires a manifest explicitly, which ends the streams of the instances registered with it and refuses their calls, as MAN-4 does. Every manifest of a module keeps the same `metadata.name`, `spec.identity` and `spec.agents`.
- **MAN-4.** Revoking a module MUST end its instances' streams and refuse their calls from then on.
- **MAN-5.** The core MUST return, in `RegisterInstanceResponse`, the environment recorded for the credential the instance registered with. It MUST refuse, with `PERMISSION_DENIED`, the registration of an enforcement point whose credential has none, since every decision that evaluates policies needs one (section 6.2).
- **MAN-6.** The core MUST refuse a manifest whose `spec.events.emits` lists a type that the catalog (section 8.5) does not have, that only the core emits, or whose emitters include none of the manifest's capabilities, and MUST check the same when it ingests an event. The catalog's emitters bind; adding an emitter to a type later is an additive change.

### 3.3 Permissions

| Permission | Allows |
| --- | --- |
| `governance.watch` | `Watch` for the agents in the instance's scope |
| `governance.acknowledge` | `Acknowledge` for the agents in the instance's scope |
| `policy.bundles.read` | `GetBundle` for the agents in the instance's scope, and `GetBundleKeys` |
| `events.publish` | `Publish` for the types in `spec.events.emits` |

An enforcement point needs all four; a runtime-control module needs `governance.watch`, `governance.acknowledge` and `events.publish`, since it emits its events (RC-3, RC-5); an event source needs `events.publish`; and so does any manifest whose `spec.events.emits` is not empty. The schema enforces these combinations, and requires the types that each capability must emit: for an enforcement point, those of EP-3, EP-4, EP-7 and EP-8; for runtime control, `whitetower.lease.expired.v1`, and the quarantine events when it declares the `network_quarantined` layer.

## 4. Module API

### 4.1 Transport

- The module API is served by the core's machine listener with **ConnectRPC**: the Connect protocol (version 1), gRPC over HTTP/2 and gRPC-Web, which are equivalent. Messages may be binary protobuf or JSON. The definitions are in [`api/proto/whitetower/module/v1alpha1/`](../../api/proto/whitetower/module/v1alpha1/).
- The listener uses TLS 1.2 or later (1.3 preferred). Mutual TLS is optional.
- **`Watch` MUST use HTTP/2,** and the core refuses it over HTTP/1.x: the core's cut-off of slow clients (CORE-7) and its check of dead peers need HTTP/2. Unary calls may use HTTP/1.1 or HTTP/2.
- **CORE-14.** The core MUST accept HTTP/2 PING frames from a client as often as every 10 seconds, and MUST NOT end a connection because of them.
- Instances SHOULD send HTTP/2 PINGs, to find a dead connection early (I-9): for example through Go's `http.HTTP2Config` (`SendPingTimeout` and `PingTimeout`), grpc-go's `keepalive.ClientParameters` with a `Time` of at least 10 seconds, or grpcio's `grpc.keepalive_time_ms` and `grpc.keepalive_timeout_ms`.
- **I-1.** An instance MUST verify the core's certificate as HTTPS requires (RFC 9110, section 4.3.4): it chains to trust anchors from the instance's configuration, and it is valid for the host of the core's configured URL, a DNS name or, only when the URL names one, an IP address. An instance that connects to an address kept from an earlier resolution still checks the certificate against that host, never against the address.
- Intermediaries between an instance and the core, such as proxies and ingress controllers, need to pass each `Watch` message as it arrives: one that buffers the stream makes every renewal stale and every lease run out (section 5.3). The operations guide (plan P1-12) gives the settings of the supported ones.

### 4.2 Authentication

- Every call carries `Authorization: Bearer <access token>`. Tokens come from the core's token endpoint (`/oauth2/token`): the client credentials grant with `private_key_jwt` client authentication (RFC 7523), for the module API as audience (resource indicator, RFC 8707). They are JWTs (RFC 9068) valid for 5 minutes by default and 15 at most ([ADR-0010](../adr/0010-built-in-agent-token-issuer.md)). **Token requests**, below, give the profile.
- An instance SHOULD request its next token at a random point between half and four fifths of its current token's lifetime, so that the instances of a fleet spread their requests.
- **Identities.** An enforcement point that runs inside an agent's process (`identity: agent`) authenticates **as that agent** (`spiffe://<trust-domain>/agent/<agent-id>`). Any other instance authenticates as its module (`spiffe://<trust-domain>/module/<module-id>`).
- **CORE-1.** The core MUST end a `Watch` stream, with `UNAUTHENTICATED`, no later than the expiry of the token that opened it.
- **I-2.** An instance SHOULD open a replacement stream with a fresh token before its token expires, resuming from the last version it applied, and close the old stream once the new one has delivered a message at or above that version. Messages from both streams follow the rule of section 5.2: the version the instance applied never goes back.

**Token requests.**

- **I-10.** An instance MUST request its tokens as the rest of this list says, and the core's token endpoint follows the same profile.
- **The issuer.** The core's configured base URL is its issuer identifier. Its metadata is at `/.well-known/oauth-authorization-server` (RFC 8414), and an instance refuses metadata whose `issuer` is any other value.
- **The client.** The client ID is the agent ID for `identity: agent`, and the module ID, the UUID in the module's SPIFFE ID, for any other instance: never the ID of a credential. The SPIFFE ID is the access token's `sub`.
- **The assertion** (`private_key_jwt`, RFC 7523). `iss` and `sub` are the client ID. `aud` is the issuer identifier alone, as a single string: the core refuses any other value, the token endpoint's URL included. `exp` is at most 5 minutes after `iat`; `iat` and `nbf` are within 60 seconds of the core's clock; `jti` is unique; `kid` is the ID of the registered key. `typ` SHOULD be `client-authentication+jwt`, which the core never requires.
- **The request.** `grant_type=client_credentials`, the assertion, and `resource`, the module API's identifier: the issuer identifier followed by `/module-api`, with no contract version, since a token comes before the version is negotiated (CORE-3). The core MAY publish protected resource metadata for it (RFC 9728).
- **The response.** The core MUST return `expires_in`, from which the instance schedules its next token and the rollover of I-2.
- **Errors.** An OAuth error with HTTP status 400 or 401 (RFC 6749, section 5.2) is logged and retried at the cap of I-4's session calls, since only a change on the core's side ends it. A 429, a 5xx or a network failure follows section 4.7.
- **Workload identity,** such as a Kubernetes service account token used as the assertion, is outside `v1alpha1` until plan P1-05 profiles it (its step 8).

### 4.3 Authorization

An instance's **scope** is the set of agents it may act on: its own agent for `identity: agent`, and otherwise the agents bound to its module (every agent, for a binding to all agents).

An instance belongs to the principal whose token registered it. Its key is unique per module and principal: the same key, registered by another principal, names another instance.

| Method | Enforcement point inside an agent | Other module instances |
| --- | --- | --- |
| `RegistryService.*` | Its own instance | Their own instances |
| `RegistryService.ReportTooling`, `RegistryService.ReportDefinitions` | Its own instance, about its agent | Their own instances, about agents in their scope, for a module that declares `enforcement-point` |
| `GovernanceService.Watch` | Its agent | Their scope |
| `GovernanceService.Acknowledge` | Its agent | Their scope |
| `PolicyService.GetBundle` | Its agent's bundles | Bundles of agents in their scope, with `policy.bundles.read` |
| `PolicyService.GetBundleKeys` | Yes | With `policy.bundles.read` |
| `EventService.Publish` | Types in `emits`, from a source under `/agents/<its agent>/ep/`, about its agent | Types in `emits`, from a source under `/modules/<its module>/`, about agents in their scope |
| `MetaService.GetServerInfo` | Yes | Yes |

- **CORE-2.** The core MUST check these rules on every call, not only at registration. A failure of the call itself MUST refuse the whole call with `PERMISSION_DENIED`: the caller's identity or permission, a module not approved or revoked, an enforcement point's credential without an environment (MAN-5), a bundle of an agent outside the scope (`GetBundle`), a tooling report about an agent outside the scope or from a module that does not declare `enforcement-point` (`ReportTooling` and `ReportDefinitions`), or an instance that the caller's principal did not register (`Heartbeat`, `DeregisterInstance`, `Watch`, `Acknowledge`, `Publish`, `ReportTooling` and `ReportDefinitions`). A failure of one item decides that item only: an `Acknowledge` item about an agent outside the scope is not recorded and is counted, as one about an unknown halt is; a `Publish` event outside these rules is rejected on its own, with its reason (section 8.4); and a definition that none of the instance's reports names is refused on its own (section 4.10).

### 4.4 Services

| Method | Purpose | Idempotency |
| --- | --- | --- |
| `RegistryService.RegisterInstance` | Announce an instance: module, manifest hash, version, instance key, supported contract versions, agents served. Registering again with the same key, under the same principal, updates the instance (section 4.3) | Idempotent |
| `RegistryService.Heartbeat` | Report health, and the set of agents served when it changed since the last `RegisterInstance` or `Heartbeat` the core accepted: after a failed heartbeat, the next one carries the set | Idempotent |
| `RegistryService.DeregisterInstance` | Leave cleanly, so the instance shows as disconnected rather than lost. An enforcement point closes its gate first (I-5) | Idempotent |
| `RegistryService.ReportTooling` | Report an agent's MCP servers, tools and models; the response lists the definitions the core lacks (section 4.10) | Idempotent |
| `RegistryService.ReportDefinitions` | Send the definitions the core lacks (section 4.10) | Idempotent |
| `GovernanceService.Watch` | Stream the governance state of the instance's scope (section 5) | Server stream |
| `GovernanceService.Acknowledge` | Report halt layers, bundle activations and the state version applied | Idempotent through `acknowledgement_id` |
| `PolicyService.GetBundle` | Download one version of an agent's bundle (section 7) | No side effects |
| `PolicyService.GetBundleKeys` | List the bundle signing keys: active, next and retired | No side effects |
| `EventService.Publish` | Deliver a batch of events (section 8) | Idempotent through each event's source and ID |
| `MetaService.GetServerInfo` | The core's version and the contract versions it supports | No side effects |

JSON examples of every method are in appendix A.

### 4.5 Version negotiation

- The protobuf package carries the contract version: `whitetower.module.v1alpha1`.
- **CORE-3.** `RegisterInstance` MUST select the highest version that both sides support and return it. With no common version, the core MUST answer `FAILED_PRECONDITION`, listing the versions it supports in the error's message, for people; instances learn them from `MetaService.GetServerInfo`.
- **I-3.** An instance MUST use only the selected version until it registers again.
- **Order and bootstrap.** Versions are ordered as Kubernetes orders API versions: a stable version above every beta, a beta above every alpha, and a higher number above a lower one within each (`v1`, then `v1beta2`, `v1beta1`, `v1alpha2` and `v1alpha1`). An instance registers through the package of a version it supports, listing every version it supports; every later call uses the package of the selected version, in which the instance ID is valid.

### 4.6 Errors

| Code | Meaning | What the client does |
| --- | --- | --- |
| `UNAUTHENTICATED` | Token missing, expired or invalid | Get a new token, then retry |
| `PERMISSION_DENIED` | A failure of the call (CORE-2): outside the instance's scope or permissions; module not approved or revoked; an enforcement point's credential without an environment (MAN-5); an instance that the caller's principal did not register | From `RegisterInstance` or `Watch`: end every lease at once (an enforcement point denies everything and applies the halt mode; a runtime-control module keeps its layers), then register again with the backoff of section 4.7, never treating the code as final. From another call: do not retry that call until a registration succeeds again |
| `INVALID_ARGUMENT` | Malformed request, such as a tooling report over its limits (section 4.10) | Do not retry the same request |
| `FAILED_PRECONDITION` | No common contract version; manifest hash mismatch; instance not registered | Not registered: register again, then retry. A version or a manifest hash that registration refuses: as `PERMISSION_DENIED` from `RegisterInstance`, since an operator's action ends it |
| `NOT_FOUND` | Unknown bundle version | Wait for the next state; do not retry the same version |
| `RESOURCE_EXHAUSTED` | Rate limit or backpressure; or a message over the limits of section 4.8 | Retry with backoff, no sooner than its `RetryInfo` says (section 4.7), but never a message over the limits as it is |
| `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `ABORTED` | Transient | Retry with backoff |
| `INTERNAL`, `UNKNOWN` | Server error | Retry with backoff |
| `UNIMPLEMENTED` | The core does not serve the method | On `RegisterInstance`: register through another version the instance supports, and with none left, stay closed and retry with backoff. On a method added within the version: carry on without it. Otherwise: retry with backoff |
| `CANCELED` | The call was cancelled | Transient: retry with backoff |

Any other code is handled as `INTERNAL`.

A failure of an established `Watch` stream is transient whatever its code, except `UNAUTHENTICATED`, which needs a new token first, and `PERMISSION_DENIED`, which ends every lease at once (the table above): the instance then registers again, and reconnects, with the backoff of section 4.7, and resumes. A stream is established once it has delivered its first message. Before then, an error that the core sends follows the table above, but a failure that the instance's own library reports, such as a cut in the middle of the first message, is transient. The code may come from the instance's own library rather than from the core: connect-go, for example, reports a stream cut in the middle of a message as `INVALID_ARGUMENT`, and `connect.IsWireError` tells the two apart. The error the core sends on a stream is in its end-of-stream message (Connect) or in its trailers (gRPC and gRPC-Web): a body that ends without one is a cut, and is transient. An instance sets no deadline on `Watch`.

A stream that the core ends with `ABORTED`, because its instance opened another (CORE-16), is not reconnected while the instance holds a newer stream. A stream that falls silent has failed too (I-9).

### 4.7 Retries and backoff

- **I-4.** Instances MUST retry with exponential backoff and full jitter. The first wait SHOULD be a random duration up to 0.5 seconds, each later cap doubling. Two backoffs apply:
  - **Session calls** keep the instance governed: token requests, `RegisterInstance`, `Watch`, and `Acknowledge` requests that carry a halt acknowledgement. Their backoff's cap MUST NOT exceed 30 seconds, nor a third of the shortest lease TTL the instance holds, so that once the core returns every instance is back within one renewal interval, and it never falls below the first step. The backoff MUST return to its first step once the instance receives a fresh lease renewal (section 5.3). The cap bounds the whole reconnection: a library's own channel backoff counts, and so does each connection attempt (for example grpc-go's `ConnectParams`, or grpcio's `grpc.initial_reconnect_backoff_ms` and `grpc.max_reconnect_backoff_ms`). (Spike S2: with a 30-second cap, a five-second outage of the whole core left 6 to 8% of 1,000 enforcement points failed closed; with this rule, none.)
  - **Other calls** (`Publish`, the other `Acknowledge` requests, `GetBundle`, `GetBundleKeys` and `Heartbeat`) have a backoff of their own, capped at 60 seconds and reset after a success: safety does not need them to hurry.
- A `RESOURCE_EXHAUSTED` error MAY carry a `google.rpc.RetryInfo` detail. The instance waits at least the delay it gives before it retries that call, but for a session call never longer than the cap of I-4.
- **CORE-15.** The core MUST NOT refuse an `Acknowledge` request that carries a halt acknowledgement because of a rate limit.
- Unary calls SHOULD carry a deadline, 10 seconds RECOMMENDED.
- Retrying is always safe: acknowledgements carry an `acknowledgement_id` chosen by the instance, and events are de-duplicated on their source and ID for at least 28 days (section 8.4).

### 4.8 Limits

A message's size is that of its encoding in the call, binary protobuf or JSON, once decompressed: a client that compresses its messages, or accepts compressed ones, gains no room. The core refuses a larger request with `RESOURCE_EXHAUSTED`, and never sends a larger message.

Events travel as bytes, which JSON carries as base64: a JSON `Publish` holds about 3 MiB of events, 47 of 64 KiB, and a binary one about 4 MiB, 63 of them. An instance checks a batch's encoded size before it sends it, and splits a larger batch, whose events stay in its buffer (section 8.4).

| Limit | `v1alpha1` |
| --- | --- |
| Size of a request or response message | 4 MiB |
| Compression of messages | `gzip`, or none |
| Size of a `Watch` message | 1 MiB; the core splits larger snapshots into parts |
| Acknowledgements per request | 100 |
| Events per `Publish` | 500, within the message limit |
| Size of one event | 64 KiB, as its CloudEvent's JSON in UTF-8; an event over the limit is `REJECTED` on its own |
| Size of a bundle | 2 MiB, at most 1,000 files |
| Tooling report | 256 servers, 4,096 tools and 256 models, and the limits of its strings (section 4.10) |
| Tooling reports per instance and agent | One every 10 seconds; the core may refuse more, with `RESOURCE_EXHAUSTED` |
| Active blocks | 500 (section 5.10) |
| Heartbeat interval | Set by the core, 30 seconds by default |
| Lease TTL | 10 to 300 seconds, per agent |
| Lease renewal interval | A third of the shortest TTL in scope, and at most 30 seconds |
| Age of a lease renewal when it arrives | At most 5 seconds by default, before or after the instance's clock; an instance may configure another tolerance, up to 30 seconds |
| Silence of a `Watch` stream | The renewal interval plus 5 seconds, or 35 seconds before its first message: a longer one means the stream failed (I-9) |
| Concurrent `Watch` streams per instance | At least 2, for the token rollover of I-2; beyond that, the core may end the oldest (CORE-16) |
| HTTP/2 PINGs from a client | Accepted as often as every 10 seconds (CORE-14) |
| Deadline of a unary call | 10 seconds recommended (section 4.7) |

### 4.9 Instances

An **instance** is one process of a module, with its own leases, streams and evidence buffer, and, for an enforcement point, its own gate.

- **I-5.** An instance MUST register before any other call, and SHOULD deregister when it stops on purpose. Before an enforcement point deregisters, it MUST close its gate for every agent it serves, and allow nothing afterwards. Before an instance deregisters, or ends its own process, `terminate` included, it SHOULD deliver its evidence buffer, within a bound that fits its platform's grace period for termination.
- **I-6.** An instance MUST send heartbeats at the interval the core sets, which every `RegisterInstanceResponse` and `HeartbeatResponse` carries. An instance that receives none, or one that is not positive, keeps the interval in force: 30 seconds before the first. A runtime-control instance reports as served agents those that have workloads it controls, and an enforcement point that serves several agents those in its scope for which it holds an active bundle. Served agents never authorize anything, and the core ignores those outside the scope.
- **I-7.** An enforcement point MUST put in the subject of every decision the environment its registration returned (MAN-5, section 6.2). It MUST NOT take the environment from its configuration, nor from its access token, which RFC 9068 (section 6) forbids a client to inspect. Until a registration of this process returns an environment, its decisions carry none, never one from an earlier process, its configuration or its token. It MUST treat a registration that returns no environment, or one it does not know, as refused, and allow nothing (EP-1, EP-10).
- **I-8.** An instance's key MUST be unique to its process, and SHOULD stay the same across the process's restarts: a random ID, created with the evidence buffer and stored in it, is RECOMMENDED. A host or pod name is not enough, since several processes, or the same agent in two environments, may share it.
- **CORE-4.** The core MUST show an instance as lost:
  - an instance of a module that watches the governance state (an enforcement point or a runtime-control module), with an agent in its scope, once it has held no stream for longer than the shortest lease TTL in its scope, whatever its heartbeats;
  - any other instance, once it has neither sent a heartbeat nor held a stream for three of the heartbeat intervals the core last set for it.

  It MUST count a lost instance in the status of the halts it had to acknowledge.

**Health**, which each heartbeat reports, says whether the instance can do what the state asks:

- `HEALTH_HEALTHY`: it can. A gate that the state closes, for a halt or a drill, a lifecycle state, or a state that names no bundle, leaves health as it is.
- `HEALTH_DEGRADED`: enforcement works, but needs an operator: renewals arrive stale while the lease still holds, events are `REJECTED`, the oldest undelivered event is older than a threshold (section 8.4), or a tooling report leaves something out (EP-13).
- `HEALTH_UNHEALTHY`: the instance cannot enforce what the state asks: the lease ran out while it was connected, the evidence buffer is full, a bundle the state names could not be activated and none is active, or a halt layer failed. An instance MUST report it while its gate is closed with `gate.evidence_full`.

### 4.10 Tooling reports

An enforcement point reports the tooling of the agents it serves: the MCP servers they launch or connect to, with the tools those list, their own tools, the models they call, and the tools their model providers run for them. The core keeps it in its catalog, where people approve or block each entry and enable it agent by agent, and each agent's bundle carries what the agent may use (section 7.7). Reports inform; they never authorize (CORE-10).

| Term | Meaning |
| --- | --- |
| MCP server | A server that speaks the Model Context Protocol. It is either local (`stdio`, a process the agent launches) or remote (`http`, streamable HTTP or SSE) |
| Tool | Something a model can call. Its **kind** is `function` (the agent's own code), `mcp` (a tool of an MCP server), `builtin` (defined by the model provider, such as web search), `http` or `other` |
| Origin | Who runs the tool: `agent` (the agent's process, or an MCP server the agent connects to) or `provider` (the model provider, during a model call: its built-in tools, and the remote MCP servers it calls for the agent) |
| Model | A model the agent calls: provider, endpoint, name and, for self-hosted runtimes, the digest of its weights |
| Catalog | The organization's list of MCP servers, tools and models. Each **entry** is `discovered` or `approved`, and shows as blocked while a block covers it (section 5.10) |
| Reference | How an enforcement point identifies an entry at runtime |
| Key | The entry's name in policies and in the console, assigned by the core: `github`, `github/create_issue`, `agent/send_email`, `provider.openai/web_search`, `gpu-01/llama3.1-8b` |
| Definition | What the model sees of a tool: its name, description and schemas. Approval pins its hash. Built-in tools have none |

**References.** An enforcement point MUST compute references exactly as follows, so that they match the catalog's:

| Entry | Reference |
| --- | --- |
| Remote MCP server, called by the agent or by its model provider | The server's URL, normalized as below, after the redaction of EP-14 |
| MCP server hosted by the model provider and named by an ID rather than a URL | `connector:<provider>/<connector ID>` |
| Local MCP server | `stdio:` followed by the canonical JSON (section 1) of the array of its command and arguments, as configured, after the redaction of EP-14 |
| Tool | Its server's reference and the tool's name. A function, `http` or `other` tool: its name alone. A built-in tool: the provider and the tool's type |
| Model | The provider, a value of the table of model providers (section 6.3), such as `openai`, `anthropic` or `ollama`; the base URL of the endpoint the agent calls, normalized as below, even when it is the provider's default; and the model's name as requested |

**Normalized URLs.** A remote server's URL and a model's endpoint are normalized as follows, so that two enforcement points that read one URL write one reference:

1. The URL is read as the `url_host` transform reads it (section 6.11), which also gives its host, and its scheme is `http` or `https`. A URL that this cannot read, or with a backslash in its path, makes no reference: the server or the model is not reported, and its calls are `catalog.unknown`.
2. User information, query and fragment are removed.
3. The scheme is written in lowercase, the host as `url_host` gives it, and the port only when it is not the scheme's default (80 for `http`, 443 for `https`).
4. In the path, a character that RFC 3986 does not allow there is percent-encoded as UTF-8. Percent-encoding is then normalized as RFC 3986 says in section 6.2.2 (hexadecimal digits in uppercase, unreserved characters decoded), and dot segments are removed as its section 5.2.4 says. An empty path is written `/`; any other trailing slash stays as written.

For example, `HTTPS://API.Example.COM:443/mcp/./tools/../%7euser/` becomes `https://api.example.com/mcp/~user/`.

**What a reference covers.** A reference names what an enforcement point can report without secrets. It leaves out a URL's user information, query and fragment, the values that redaction replaces (EP-14), and a local server's environment variables. Configurations that differ only in those share one reference, and one approval covers them all: a server that takes its roots or its database from environment variables, or a remote server whose query names a tenant, is one entry whatever they hold.

**String form.** A server's reference is a string. A reference with several parts is written as the canonical JSON of an object of those parts:

| Entry | String form |
| --- | --- |
| MCP tool | `{"name":"create_issue","server":"https://api.githubcopilot.com/mcp/"}` |
| The agent's own tool | `{"name":"send_email"}` |
| Built-in tool | `{"provider":"openai","type":"web_search"}` |
| Model | `{"endpoint":"http://gpu-01.internal:11434/","name":"llama3.1:8b","provider":"ollama"}`, and for a model of a provider's default endpoint, `{"endpoint":"https://api.openai.com/v1","name":"gpt-4o","provider":"openai"}` |

Blocks and events name a reference by the SHA-256 of the UTF-8 bytes of its string form (sections 5.10 and 8.3).

**Keys.** The core assigns each entry a key the first time it sees the entry, and the key never changes once the entry is approved. The agent's own tools are entries of their agent: their keys are unique within the agent, because the same name in two agents is different code. Every other key is unique in the catalog:

- **Servers:** a slug of lowercase letters, digits and hyphens, at most 63 characters, derived from the name the server announces or from its host, never from a command line, whose paths can hold a user name: events carry keys in clear.
- **Tools:** `<server key>/<tool name>`. Two server keys are reserved: `agent`, for the agent's own tools, and `provider.<provider>`, for a provider's built-in tools.
- **Models:** a slug of their provider or endpoint, a slash, and a slug of their name, which keeps its dots (`gpu-01/llama3.1-8b`). For an endpoint that the core knows as its provider's default, the slug is the provider's (`openai/gpt-4o`): a table of the core's own, which shapes only the key, never the reference.

**Definitions.** A definition hash is the lowercase hexadecimal SHA-256 of the canonical JSON of the following members, leaving out those that are absent or `null`:

- **MCP tool:** the members `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations` of the tool, as the `tools/list` result carries them in the JSON-RPC message itself. SDKs turn tools into objects that add defaults or drop members, so their objects are not the input.
- **Function, `http` or `other` tool:** its name and the JSON Schema of its parameters, as the framework presents them to the model. Their descriptions belong to the agent's own code, which its owner controls ([threat model](../security/threat-model.md), A-6).

The canonical JSON of a definition is that of section 1, with one extension. Tool schemas often hold integers beyond I-JSON's 2^53 - 1, such as 18446744073709551615, the bound of an unsigned 64-bit field. A library that rounds it, as `gowebpki/jcs` does (it writes 18446744073709552000), gives a hash that the other stack does not compute, and two schemas that differ only in such a number hash alike; one that refuses it makes the tool unusable. So **a number written without a fraction or an exponent is written as its exact value in decimal**, with `-0` as `0`: for a magnitude of at most 2^53 - 1, this is what RFC 8785 writes. Any other number is written as RFC 8785 says. A number that is not finite as a double, a member name that repeats, or a string with a lone surrogate leaves the definition without a hash. A tool without a hash is reported without one and can never be approved, so its calls are denied (`catalog.not_approved`, or `catalog.definition_changed` once another definition is pinned).

A built-in tool has no definition. The provider versions it in its type, which is part of its reference, and what a declaration configures belongs to the agent's code (A-6). The core recomputes every hash from the members it receives, so the hash that approval pins is that of what reviewers saw.

**The methods.** `RegistryService.ReportTooling` is idempotent. Only an instance of a module that declares the `enforcement-point` capability calls it, and only for an agent in its scope; the core refuses any other call as a whole (CORE-2):

| Field | Meaning |
| --- | --- |
| `instance_id` | The reporting instance |
| `agent_id` | The agent the tooling belongs to, in the instance's scope |
| `servers` | Each MCP server: reference, transport (`stdio` or `http`), origin, the name and version it announces, and a display form (its URL or command line, redacted) |
| `tools` | Each tool: kind, origin, its server (MCP tools, named by the server's position in `servers`) or its provider and type (built-in tools), its name and, except for built-in tools, its definition hash, when its definition has one |
| `models` | Each model: provider, endpoint, name and, when the runtime reports one, digest |

A report is complete: it replaces the instance's previous report for that agent. Its response lists the definition hashes the core does not have.

`RegistryService.ReportDefinitions`, also idempotent, and called by the same instances under the same rules, carries the calling instance's `instance_id` and those definitions: for each, the members that its hash covers, taken as above. The core recomputes each hash and stores the definition under it. A definition whose hash matches none that this instance's current reports name, for any of its agents, is refused on its own and listed in the response, and the others are still stored (CORE-2). Definitions are content-addressed, so each is sent once, whatever the number of agents, instances and restarts. They travel apart from reports because a report carrying every description and schema could exceed the message limit many times over.

- **EP-13. Report tooling.** Report the agent's tooling as soon as it is known; the first report SHOULD come before the gate first opens. Report again whenever it changes, for example when:
  - an MCP server connects, or announces a changed tool list (`notifications/tools/list_changed`);
  - a model is called for the first time;
  - a model request declares a provider-run tool not reported yet.

  Report what the agent is configured with, not only what it has called. Then send the definitions the core asks for.

  Keep at most one report per agent in flight. Retry a report that failed, or that the core refused, with the agent's tooling as it is when the retry is sent, never as it was: each report replaces the one before it, so an older report that arrived late would undo a newer one. Leave out of a report, and log, what is over the limits below: the servers, tools and models beyond its counts, and those whose strings, or whose definition, are over their limits. A server left out takes its tools with it. An instance that calls in JSON, whose escapes can make a report at the limits larger than the message limit, leaves out what does not fit the same way. Report `HEALTH_DEGRADED` while anything is left out (section 4.9): what is left out stays unknown, so its calls are denied (`catalog.unknown`).
- **EP-14. Redact.** Never report environment variables, HTTP headers, authorization values or any other credential. Remove user information, query and fragment from URLs, including URLs passed as command-line arguments. Replace with `<redacted>` the value of any command-line argument that follows a flag, or is written `--flag=value`, when the flag's name contains, in any case, `token`, `secret`, `password`, `passwd`, `key`, `auth`, `credential` or `cookie`.

  Apply also the deployment's redaction rules, which the catalog file carries (section 7.7). In a URL that, normalized as above, starts with one of their prefixes, replace the path segment that follows the prefix with `<redacted>`, and write the URL normalized, also where it is a command-line argument. Treat the flags they name, each matched exactly without its leading dashes, like those above. Apply them to everything reported and to the references computed, so that references match the catalog's. Until a bundle is active, an instance has no rules and reports without them: the core applies them (CORE-11).
- **CORE-10.** The core MUST treat reports as observations. A report MUST NOT approve, enable or unblock anything, and MUST NOT change an approved definition.
- **CORE-11.** The core MUST apply the redaction of EP-14, with the deployment's redaction rules, again before it stores or logs anything from a report, and MUST NOT copy reported descriptions, schemas or references into audit events, which name references only by their SHA-256 (section 8.3). When an administrator adds a rule, the core applies it to the references the catalog already holds.
- **CORE-13.** The core MUST bound, for each agent, what the agent's reports brought that still waits for review: new entries of each kind, and new definitions and digests of known entries. Beyond the bound, it still records the report but leaves out what is new, and says how much in its response. A new entry left out stays unknown (`catalog.unknown`); a new definition or digest left out is not stored, so the tool or the model stays denied (`catalog.definition_changed`, `catalog.digest_mismatch`). Both last until reviewers approve or decline enough of what the agent brought. The bound is one report's worth by default (256 servers, 4,096 tools and 256 models, and as many new definitions as tools), and administrators can change it. A compromised agent therefore cannot make the catalog, or the reviewers' queue, grow faster than people decide.
- **New entries.** A reference the catalog does not have becomes a `discovered` entry; the agent's own tools become entries of that agent. When a tool's reported definition differs from the approved one, the approved definition stays pinned and the new one waits for review. A model's new digest is handled the same way: the pinned digest stays, and the new one waits for review.
- **Observations.** For each agent, the core keeps the entries observed and when each was last seen, so that people see tooling waiting for a decision, and enabled tooling the agent no longer has.

**Limits** (section 4.8):

- A report holds at most 256 servers, 4,096 tools and 256 models.
- References, endpoints and display forms are at most 2 KiB each, names at most 256 bytes, and versions, providers, built-in tools' types and digests at most 128 bytes, so a full report fits in the 4 MiB message limit in binary protobuf, at about 3.8 MiB. In JSON, escapes can make it larger (EP-13).
- Each description is at most 16 KiB, each schema at most 64 KiB, each title at most 256 bytes, and each tool's annotations at most 4 KiB.
- The core refuses as a whole, with `INVALID_ARGUMENT`, a report or a `ReportDefinitions` call over these limits: an enforcement point leaves out what does not fit them (EP-13).
- The core MAY refuse, with `RESOURCE_EXHAUSTED`, more than one report per instance and agent every 10 seconds. The instance retries a refused report with the backoff of the other calls of section 4.7, no sooner than the error's `RetryInfo` says, and with the agent's current tooling (EP-13).

## 5. Governance state, leases and halts

This section is the wire form of ADR-0005: the core publishes each agent's governance state, enforcement points decide locally, and leases make them fail closed when they lose the core.

### 5.1 The state

`AgentState`, one per agent in scope:

| Field | Meaning |
| --- | --- |
| `agent_id`, `slug` | The agent |
| `version` | The global state version of the agent's last change |
| `lifecycle_state` | Decides whether the gate may open: only in `validated`, `ready` and `active` |
| `halts` | The agent and selector halts that cover the agent: IDs, scope, issue time and whether they are drills. Reasons are never sent to modules |
| `bundle` | The effective bundle: version, SHA-256 of its manifest, size. Absent while the agent has none |
| `lease_ttl` | How long the lease lasts after each renewal, from the agent's risk tier |
| `halt_mode` | `block`, `interrupt` or `terminate`, chosen by the agent's owner |
| `attributes` | What policies may use about the agent: kind, risk tier, data categories, labels, owner ID (section 6.2) |

`FleetState` holds the active fleet halts. **An agent is halted when its `halts` list is not empty or the fleet's list is not empty.** A fleet halt changes one record, so enforcement points must always combine the two.

The **blocks record** holds the organization-wide blocks of MCP servers, tools and models (section 5.10). It belongs to no agent and halts nothing: a block denies through the catalog check.

A halt applies wherever the instance runs. An instance applies every halt in an agent's `halts` list, and every fleet halt, to that agent, whatever the instance's own environment, credential, cluster or configuration. No field of `Halt` limits where it applies. A later revision may add one: an instance that does not know it ignores it (EP-10) and applies the halt as before, so it halts more, never less.

### 5.2 The watch stream

- **CORE-5.** When `since_version` is 0, or when the core cannot send every change since it, the core MUST start with a snapshot. It MAY send a snapshot at any time, and MUST NOT send a snapshot or a change older than `since_version`. It MAY answer any resumption with a snapshot, including one at a version it moved forward after a regression, when a client resumes from a version above the core's latest state version (after an asynchronous failover or a restore). That snapshot replaces the client's state.
- A **snapshot** is one or more `SnapshotPart` messages with the same version, consecutive on one stream: the first has `first` set and carries the fleet state and, on an enforcement point's stream, the blocks record (section 5.10), the last has `last` set. Agents missing from a snapshot are out of scope. An instance MAY apply the halts that a snapshot part carries as soon as the part arrives. A snapshot whose first part lacks the fleet state is malformed: the instance keeps its current state (at start it has none, so its gate stays closed with `gate.no_state`), and reconnects with the backoff of I-4.
- **Changes** follow in strictly increasing version order. Each carries the complete new state of every agent that changed or entered the scope, the new fleet state when it changed, the agents that left the scope, and, on an enforcement point's stream, the blocks added and the IDs of those removed. An instance applies every agent state a change carries, whatever that state's own `version`: an agent that enters the scope keeps the version of its last change, which may be older than the last version the instance applied.
- **The version applied never goes back.** An instance keeps the highest `WatchResponse.version` it has applied, across all its streams, and never lowers it. It ignores a change, or a whole snapshot, whose version is below it. A fresh renewal renews its leases whichever stream carries it, but never lowers that version. The agent states inside a change it applies are still applied, whatever their own version. So the two streams of a token rollover (I-2), even on two replicas of the core that are not equally current, can never undo a halt.
- **I-11.** An agent that leaves the scope, because a snapshot does not carry it or a change lists it as removed, MUST lose its state and its lease at once, and the instance drops the acknowledgements it has queued for it. An enforcement point's gate for that agent closes with `gate.no_state`.
- **CORE-6.** The core MUST send a `LeaseRenewal` right after each complete snapshot, right after a resumed stream has sent every change since `since_version`, and then at least at the renewal interval of section 4.8. It sends one only when it has sent every change it knows of, and MAY withhold them while it cannot show that it is current, for example while a replica cannot read its database: leases then run out, rather than trust a core that may have missed a halt. A renewal therefore always means "your state is current". Its version may pass versions that carried nothing for the stream; that version is then the last version the instance applied (EP-9). Every renewal carries `server_time`, the core's clock when it sends it (section 5.3).
- **CORE-7.** The core MUST end a stream it cannot keep up to date, for example a client too slow to read, rather than let it fall behind. The client's lease then expires if it cannot reconnect.
- **CORE-16.** The core MUST NOT refuse a `Watch` stream because its instance holds others. It keeps at least two per instance, for the rollover of I-2. When an instance opens more, the core MAY end the oldest with `ABORTED`, so that a dead stream it has not noticed never refuses a live reconnection.
- **I-9.** A `Watch` stream that has delivered no message for longer than the renewal interval of section 4.8 plus 5 seconds, or for 35 seconds before its first message, has failed. The instance closes the connection that carried it, not only the stream, and reconnects on a new connection with the backoff of I-4.

### 5.3 Leases

- A renewal renews the lease of every agent in scope. Each lease then lasts that agent's `lease_ttl`, measured on the client's **monotonic clock** from the moment it received the renewal. A `lease_ttl` above 300 seconds counts as 300; one that is zero, negative or absent renews nothing; one under 10 seconds is applied as it is, never lengthened.
- **Only a fresh renewal counts.** An instance ignores a renewal without `server_time`, or whose `server_time` is more than a tolerance before or after its own clock: 5 seconds by default, and at most 30 (section 4.8). Such a renewal renews nothing. While an instance receives only those, it SHOULD report `HEALTH_DEGRADED` in its heartbeats while the lease holds, and `HEALTH_UNHEALTHY` once it runs out (section 4.9). A renewal from the future counts as stale too, since an instance whose clock is behind the core's would otherwise accept renewals as old as the tolerance plus its lag. Something on the path that holds the stream back can then delay it by the tolerance at most: beyond that, leases run out and the gate closes, instead of halts arriving late ([threat model](../security/threat-model.md), T-32). The check relies on clocks synchronized within the tolerance (ASM-04), far tighter than token expiry needs; the lease itself is still measured on the monotonic clock.
- **A lease belongs to the instance,** not to a stream. The end of a stream, a reconnection, or a new registration with the same key neither renews a lease nor ends it: only a fresh renewal renews it, and only its TTL ends it. So an enforcement point that reconnects within its lease keeps deciding on the last state it applied. There is no lease before the first fresh renewal after the instance starts. An agent that enters the scope through a change gets its lease from the next renewal; the core SHOULD send one right after such a change.
- **When a lease expires, the agent is treated as halted**: the enforcement point denies everything and applies the agent's halt mode (KIL-04), and emits `whitetower.lease.expired.v1`, one event per agent, with that agent as subject: it says whether renewals stopped or arrived stale, and the halt mode applied, with its layers. A denial of `agent.stop` never keeps the agent from stopping (section 6.3). The gate opens again when the instance has a current state and a new lease.

### 5.4 The gate

An enforcement point checks its gate when each governed call or interaction is made, then evaluates policies (section 6). It never holds a governed call waiting for the core (NFR-02). The gate is closed, with the first reason that applies in this order:

| Order | Condition | Reason |
| --- | --- | --- |
| 1 | No complete snapshot applied since the instance started, or the agent is not in the state applied (I-11) | `gate.no_state` |
| 2 | The agent's lease has expired, or it never had one | `gate.lease_expired` |
| 3 | An agent or selector halt covers the agent | `gate.halted` |
| 4 | A fleet halt is active | `gate.fleet_halted` |
| 5 | The lifecycle state is not `validated`, `ready` or `active`, including unknown values; or it is `validated` or `ready` and the registration returned `production` | `gate.lifecycle` |
| 6 | No verified bundle is active for the agent | `gate.no_bundle` |
| 7 | The evidence buffer cannot accept another event | `gate.evidence_full` |

The [fail-closed vectors](../../test/conformance/vectors/fail-closed.json) cover every row.

A block is not a gate condition: it denies tool and model calls in the catalog check, after the gate (section 6.9).

### 5.5 Halts

When an agent becomes halted, the enforcement point:

1. **Closes the gate at once**, before anything else and before acknowledging. From then on, every governed call and interaction is denied (KIL-01), though a denial of `agent.stop` never keeps the agent from stopping (section 6.3).
2. **Applies the halt mode** to work already in flight:
   - `block`: nothing more; the work in flight finishes.
   - `interrupt`: interrupts the work in flight through the framework's own cancellation, where the framework allows it.
   - `terminate`: interrupts, then ends the agent's process if work is still running at the end of a grace period (10 seconds by default). A release during the grace period cancels the end. An unknown mode is treated as `interrupt`.
3. **Acknowledges each layer** with its outcome: `done`, `not_done` (attempted, not achieved, such as a blocking call still running), `not_applicable` (nothing in flight, or the mode excludes the layer) or `failed`. Each report carries the time since this process received the halt, on the monotonic clock: for a halt it found at start, since it applied the state that carried it. The gate is acknowledged as soon as it is closed; later layers follow in further acknowledgements.
4. **Emits** `whitetower.instance.halted.v1` with the same layers and the halt mode it applied, once per halt and agent. The halt's scope is left out when the instance does not know it (EP-10).

Drill halts are handled exactly like real halts. Every halt ID that covers the agent, including a fleet halt, is acknowledged for that agent.

The halt mode acts on the work in flight when the agent becomes halted. A process that applies its first complete snapshot while its agent is already halted acknowledges the gate `done`, reports the later layers `not_applicable`, and keeps running, closed, until the release: it never ends itself for that halt.

An instance inside the agent's process that ends the process (`terminate`) reports `process_terminated` `done` just before, as its last report for that halt. It first writes `whitetower.instance.halted.v1` to its durable buffer, and waits at most about a second for the acknowledgement's response.

A runtime-control module acknowledges its own layer (`network_quarantined`, with the number of workloads isolated) per agent, once the layer is in place.

### 5.6 Releases

When no halt covers the agent any more, the gate reopens only if every other condition of section 5.4 holds. A release never reinstates a suspended agent: that is a lifecycle transition, which reaches the enforcement point as a new lifecycle state.

### 5.7 Obligations of enforcement points

- **EP-1. Start closed.** Allow nothing until the instance has registered, applied a complete snapshot, received a lease renewal and activated a verified bundle for the agent.
- **EP-2. Decide locally, gate first.** For every governed call and interaction, check the gate (section 5.4), then evaluate the agent's bundle with the profile and the combining algorithm of section 6, within a bounded evaluation time (section 6.5). Never call the core synchronously to decide.
- **EP-3. Leases.** Keep one lease per agent on a monotonic clock, renewed only by fresh renewals; when it expires, deny everything, without keeping the agent from stopping, apply the halt mode and emit `whitetower.lease.expired.v1` (section 5.3).
- **EP-4. Halts.** When the agent or the fleet becomes halted, close the gate at once, apply the halt mode, acknowledge each layer honestly and emit `whitetower.instance.halted.v1` (section 5.5).
- **EP-5. Releases.** Reopen only when no halt covers the agent and every other gate condition holds (section 5.6).
- **EP-6. Lifecycle.** Open the gate only in the `active` state, and in `validated` and `ready` only when the registration returned `non_production`: no decision is labeled production for an agent that is not active (section 5.4, row 5).
- **EP-7. Bundles.** Fetch the bundle the state refers to, verify it (section 7.4), activate it atomically, acknowledge the outcome, and emit `whitetower.bundle.activated.v1` or `whitetower.bundle.rejected.v1`. Keep the last valid bundle when a new one is rejected, and never allow anything without one. While the active bundle is not the one the state names, report `HEALTH_DEGRADED`: the core flags the drift (POL-05), and a halt is the tool for an emergency that the rejected bundle would have handled. When the state stops referring to a bundle, deactivate the active one, so that the gate closes with `gate.no_bundle`, and keep its version as the floor of V6 for the next one.
- **EP-8. Evidence.** Record each decision (`whitetower.decision.made.v1`) durably before the action proceeds, and each allowed call's outcome once it finishes (`whitetower.action.executed.v1`, AUD-02); publish events at least once, in order, from a stable source (section 8.4). Close the gate when the evidence buffer cannot accept another event. A denial with `gate.evidence_full` is the one decision not recorded, since the buffer cannot take it.
- **EP-9. Reconnection.** Reconnect with the backoff of section 4.7 when an established stream fails (section 4.6) or falls silent (I-9), resuming from the last version applied. Never lower that version, whichever stream a message comes on, and apply every agent state a change carries, whatever that state's own version (section 5.2). Accept a snapshot at any time, unless it is below the version applied.
- **EP-10. Unknown content.** Ignore the unknown fields of protobuf messages, in either encoding, and read an unknown enum value with its fail-closed meaning; the bundle manifest and the catalog file are the exceptions, since V4 refuses the manifest's unknown members and V7 parses the catalog file against its schema (section 10). An unknown field never narrows a halt. Treat an unknown lifecycle state as closing the gate, an unknown halt scope as a halt, an unknown halt mode as `interrupt`, and a block of an unknown kind as denying every tool and model call (EP-15). Never let an unknown value open anything.
- **EP-11. Identity and trust.** An enforcement point inside an agent's process authenticates as that agent and serves it only. One that authenticates as its module establishes the agent of each call without trusting its caller: it originates the call itself, or the caller presents a White Tower access token issued to that agent for the enforcement point's own audience, never the module API's, which it verifies against the core's keys ([ADR-0010](../adr/0010-built-in-agent-token-issuer.md)); never a header, a parameter or an address. A call it cannot attribute to an agent in its scope is denied with `error.unknown_agent`. Take the core's trust anchors and the bundle keys from configuration. When the configured bundle keys change, verify the active bundle again (section 7.3).
- **EP-12. State acknowledgements.** Acknowledge the state version applied at least every 60 seconds while it changes, so the console can show instances that lag behind. An instance that serves several agents acknowledges it per agent, up to 100 per request (section 4.8).
- **EP-13 to EP-19** are the obligations of tooling: reports and redaction (section 4.10), blocks (section 5.10), and the catalog check, exposure, provider-run tools and arguments (sections 6.9 to 6.11).
- An enforcement point SHOULD keep the core's last resolved addresses, and reuse them when name resolution fails, as it does during a network quarantine without DNS (RC-7). It still checks the certificate against the configured host (I-1).

### 5.8 Obligations of runtime-control modules

`v1alpha1` specifies runtime control as the network quarantine of Kubernetes workloads (KIL-10); other platforms and layers come as additive changes, through an RFC.

- **RC-1.** Apply the module's layer to every agent in scope that is halted, whether by an agent, selector or fleet halt, including workloads started after the halt.
- **RC-2.** Never lift a layer without a current state from the core showing the agent running: not after a restart, not while disconnected or on a silent stream (I-9), and never on a message below the version applied (section 5.2).
- **RC-3.** When the lease expires, keep every layer in place, apply no new one, and emit `whitetower.lease.expired.v1`. A module MAY offer, off by default, to apply its layer to every agent in scope when its lease expires. It reports that layer in `whitetower.lease.expired.v1`, whose `effect` is then `all_quarantined`, and its lift in `whitetower.quarantine.lifted.v1`.
- **RC-4.** Acknowledge each halt per agent with the layer, its outcome and the number of workloads isolated. Report `done` only once the layer is in place, and `not_applicable` when the agent has no workloads the module controls.
- **RC-5.** Emit the module's events when a layer is applied or lifted.
- **RC-6.** Report, through heartbeats, the agents that have workloads the module controls.
- **RC-7.** A layer MUST leave the core's machine listener and token endpoint reachable from the workloads it isolates, so that their enforcement points can acknowledge the halt, deliver their evidence and learn of the release. It SHOULD block DNS by default ([threat model](../security/threat-model.md), DC-7); where the platform's rules can tell names apart, an option may allow the core's name only.

### 5.9 What the core guarantees

Besides the obligations of the core in sections 4, 5.2 and 5.10 (CORE-1 to CORE-7, and CORE-10 to CORE-16):

- **CORE-8.** A halt is committed, and the stream updated, without waiting for any module. Token issuance for the halted agents stops in the same transaction, except for tokens for the module API, which their enforcement points still need to acknowledge the halt, deliver their evidence and learn of the release ([ADR-0010](../adr/0010-built-in-agent-token-issuer.md)).
- **CORE-9.** The core adds no personal data to governance state other than the owner's pseudonymous principal ID, and the SHA-256 of what each block covers, which can derive from a local path that holds a user name: the hash keeps the path out of the stream, but a path that can be guessed can be checked against it (section 5.10). Slugs and labels are written by people, who must not put personal data in them.
- **CORE-17.** The subject properties that an enforcement point builds from the state (section 6.2) MUST always match [`decision-request.schema.json`](../../api/policy/decision-request.schema.json): labels, for one, follow its syntax.
- **CORE-18.** The bundle reference that the core sends for an agent MUST never name a version lower than one it may have sent before, nor the same version with another manifest hash, also after a restore or an asynchronous failover. After either, the core re-issues every agent's bundle at a higher version, even when its content is unchanged.
- **CORE-19.** The core MUST record a layer report only for a layer that a capability of the instance's manifest declares, MUST count and drop the others, and judges each capability's layers on their own. A report whose layer or outcome is unspecified never counts as done, nor a bundle acknowledgement whose outcome is unspecified as an activation.

### 5.10 Blocks

A block denies, for every agent and at once, one of:

- an MCP server and all its tools;
- a single tool;
- a model;
- every model of a provider or of an endpoint.

A block of one of the agent's own tools covers that name in every agent.

Blocks name references, not keys (section 4.10), so an enforcement point applies them without waiting for a new bundle. They never change an entry's status and never travel in bundles, so issuing or lifting one rebuilds no bundle, and lifting one leaves the entry as it was.

- **The blocks record.** Blocks travel in their own record of the watch stream, apart from every agent's state and from the fleet state. A snapshot carries every active block, and changes carry the blocks added and the IDs of those removed. The first part of a snapshot carries the record, with the fleet state, and a snapshot's record replaces the instance's whole set of blocks. A change adds the blocks it carries, replacing one whose ID the instance knows, and removes the IDs it lists, ignoring those it does not know. Only enforcement points' streams carry the record.
- **A block** (`Block`) carries its ID, its kind (`server`, `tool`, `model`, `provider` or `endpoint`), the SHA-256 of what it covers and its issue time. What it covers is hashed as the UTF-8 bytes of its string form (section 4.10): the reference of a server, a tool or a model, the name of a provider, or the normalized base URL of an endpoint. Hashes keep blocks small, and keep local paths out of a record that every enforcement point receives; the references and the reasons stay in the core, which shows them. Enforcement points compute the hashes of an entry once, when a tool list or a model changes, never on each call.
- **Versions.** Blocks take their versions from the same version counter as the rest of the state ([the design of the halt path](../plans/phase-1/P1-08-kill-switch.md#progress-notes), section 2), so a lease renewal still means "your state is current" (CORE-6).
- **CORE-12.** A block is committed, and the stream updated, without waiting for any bundle, as for halts (CORE-8).
- **EP-15. Blocks.** Apply a block as soon as it arrives. It denies every later call to, exposure of, and result from what it covers (section 6.9). A block of a kind the enforcement point does not know denies every tool and model call while it is active. Then acknowledge at once a state version at or above the one that carries the block, for at least one agent the instance serves, without waiting for the 60 seconds that EP-12 allows: it covers every earlier block, and the per-agent acknowledgements of EP-12 follow at their own pace. From these acknowledgements, the console shows how far each block has spread, as it does for halts.
- **Halts stay fast.** Blocks never enlarge the fleet record that fleet halts change, so a fleet halt costs the same with or without blocks. The core caps active blocks at 500, about 40 KB in a snapshot, which keeps them within one watch message (section 4.8).

**Provisional.** The rules of the blocks record and EP-15's acknowledgement apply provisionally: a live test with real enforcement points in a real environment confirms them before the contracts leave alpha (`v1beta1`), and its findings go to the review that precedes it (section 12).

## 6. Decision profile

### 6.1 Alignment with AuthZEN

A decision request is an **OpenID AuthZEN Authorization API 1.0** evaluation request (subject, action, resource, context), and the response an AuthZEN evaluation response (a boolean `decision` and a `context`). The profile restricts both; [`decision-request.schema.json`](../../api/policy/decision-request.schema.json) and [`decision-response.schema.json`](../../api/policy/decision-response.schema.json) are its syntax.

```json
{
  "subject": {
    "type": "agent",
    "id": "0192f1c2-7a3b-7c4d-8e5f-000000000001",
    "properties": {
      "slug": "invoice-triage", "kind": "in_house", "risk_tier": "high", "environment": "production",
      "data_categories": ["customer data"], "owner": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
      "labels": { "team": "finance" }
    }
  },
  "action": { "name": "tool.invoke" },
  "resource": {
    "type": "tool", "id": "agent/send_email",
    "properties": { "kind": "function", "origin": "agent", "name": "send_email", "read_only": false, "destructive": true, "open_world": true }
  },
  "context": { "time": "2026-09-29T10:15:02.118Z", "task_id": "run-7f41" }
}
```

```json
{ "decision": false, "context": { "reason": "policy.forbid", "policies": ["0192f1c2-7a3b-7c4d-8e5f-000000000101"], "bundle_version": 42 } }
```

### 6.2 The subject

The subject is always the agent (`type: agent`). The enforcement point builds it from its state and its registration, never from the agent's input:

| Property | Source | Cedar |
| --- | --- | --- |
| `id` | The agent ID. For an enforcement point that serves several agents, one in its scope, established without trusting the caller (EP-11) | The principal's ID |
| `slug`, `kind` (`in_house` or `third_party`), `risk_tier` (`low`, `medium`, `high` or `critical`), `data_categories`, `owner` | Governance state: `slug`, and `attributes`, where `owner` is `attributes.owner_id` | Attributes of the same names |
| `environment` | The environment the core returned when the enforcement point registered, the one recorded for the credential it runs with (I-7, MAN-5): `production` or `non_production` | Attribute `environment` |
| `labels` | Governance state (`attributes.labels`) | Entity tags: `principal.getTag("team")` |

An enforcement point need not validate what it takes from the state (CORE-17). One that does, and finds it invalid, denies with `error.invalid_request`.

### 6.3 Actions and resources

Eight actions match the intervention points agents actually have, and a ninth, `tool.expose`, is the offer of a tool to a model (section 6.10). Microsoft AGT's policy runtime names the eight differently; the mapping is one to one.

| Action | AGT intervention point | Resource type | Evaluation |
| --- | --- | --- | --- |
| `agent.start` | `agent_startup` | `agent`, the agent itself | SHOULD, where the framework has the hook |
| `input.receive` | `input` | `agent` | SHOULD |
| `tool.expose` | None | `tool` | MUST, for every provider-run tool, and for every tool of a model request where the framework lets the enforcement point change the request's tools (section 6.10) |
| `model.invoke` | `pre_model_call` | `model` | MUST |
| `model.result` | `post_model_call` | `model` | SHOULD |
| `tool.invoke` | `pre_tool_call` | `tool` | MUST |
| `tool.result` | `post_tool_call` | `tool` | SHOULD |
| `output.emit` | `output` | `agent` | SHOULD |
| `agent.stop` | `agent_shutdown` | `agent` | SHOULD |

An enforcement point declares the actions it evaluates in its manifest, the three it MUST evaluate among them. Every action is denied by default, so a deployment that evaluates the lifecycle actions usually permits them with a global policy (plan P1-06 seeds one), and the tool and model actions pass the catalog check first (section 6.9).

**What a denial does.** A denial means the step does not take effect. The enforcement point tells the agent through the framework's own error or refusal, and whether the run goes on is the framework's choice:

| Action | A denial |
| --- | --- |
| `agent.start` | The agent does not begin work |
| `input.receive` | The input is not passed to the agent |
| `model.invoke`, `tool.invoke` | The call is not made |
| `tool.expose` | The tool is not offered to the model: it is removed from the request, or the model call is denied when it cannot be (EP-17) |
| `model.result`, `tool.result` | The result never reaches the agent or its model; the call's effects stand |
| `output.emit` | The output is not delivered |
| `agent.stop` | Nothing: a denial never keeps an agent from stopping, so `agent.stop` is evaluated for the evidence only |

An enforcement point that evaluates `agent.start` SHOULD meet EP-1 before it lets the framework start the agent, waiting at most a configurable time before any decision. No event records that wait, which counts neither in `evaluation_us` nor against the deadline of EP-2.

| Resource type | ID | Properties |
| --- | --- | --- |
| `tool` | Its key in the catalog (section 4.10); for a tool the catalog does not list, its name as the agent sees it | From the catalog, never from the agent: `kind` (required: `function`, `mcp`, `builtin`, `http` or `other`), `origin`, `name`, `read_only`, `destructive` and `open_world`; for MCP tools, `server` (the server's key) and `transport`; for built-in tools, `provider` |
| `model` | Its key in the catalog; for a model the catalog does not list, its name as requested | From the catalog: `provider`, the lowercase identifier of the service that serves the model, from the table below; `name`; and `endpoint`, the normalized base URL of its endpoint (section 4.10) |
| `agent` | The requesting agent's ID: an agent action concerns the agent itself | None |
| `mcp_server`, `dataset`, `skill`, `url` | Reserved for later actions. In Cedar, an MCP server is already the parent of its tools (section 6.7) | None |

A request whose resource type does not match its action, or whose agent action names another agent, is invalid and denied (`error.invalid_request`), and so is one whose resource ID is empty or longer than 512 characters.

**Model providers.** `provider` takes a value of this table, or, for any other provider, a lowercase name of its own, such as `ollama` for a model that Ollama serves locally. The table copies the well-known values of OpenTelemetry's `gen_ai.provider.name` in semantic conventions v1.41.1. They are pinned here, because OpenTelemetry's values are still in development and have been renamed since; a new row is an additive change.

| `provider` | Service |
| --- | --- |
| `anthropic` | Anthropic |
| `aws.bedrock` | Amazon Bedrock |
| `azure.ai.inference` | Azure AI Inference |
| `azure.ai.openai` | Azure OpenAI |
| `cohere` | Cohere |
| `deepseek` | DeepSeek |
| `gcp.gemini` | The Gemini API of Google AI Studio |
| `gcp.gen_ai` | Another generative AI endpoint of Google |
| `gcp.vertex_ai` | Vertex AI |
| `groq` | Groq |
| `ibm.watsonx.ai` | IBM watsonx.ai |
| `mistral_ai` | Mistral AI |
| `openai` | OpenAI |
| `perplexity` | Perplexity |
| `x_ai` | xAI |

### 6.4 The context

| Property | Rule |
| --- | --- |
| `time` | Required: when the request was made, on the enforcement point's clock. Policies can use it, for example for business hours |
| `task_id` | The task or run the request belongs to |
| `trace_id` | The W3C trace ID, 32 hexadecimal characters. When present, it is the trace ID of the `traceparent` of the event that records the decision (section 8.2), whose span is one of the enforcement point's spans in that trace |
| `on_behalf_of` | Reserved for per-task delegated credentials (AID-08). MUST be absent in `v1alpha1`: a request that carries it, even empty, is invalid |
| `args` | `tool.invoke` and `tool.result` only: one record per tool, keyed by the tool's key, with the arguments that its catalog entry declares, and nothing else (section 6.11). Values are strings, booleans, signed 64-bit integers (Cedar's `Long`), and sets of strings or of integers, never null. A number with a fraction or an exponent, or outside that range, makes the request invalid: numbers are decoded exactly, never through a floating-point type |
| `calls_decided` | `tool.expose` only, and required there: whether every call of the tool will be decided as `tool.invoke` before it runs (section 6.10) |
| `digest` | `model.invoke` only: the digest of the model's weights, when the runtime reports one (section 6.9) |

### 6.5 The combining algorithm `wt-deny-overrides-v1`

For every request, the applicable global policies and the agent-specific policies of the requesting agent are evaluated together (requirements, section 5.4.1):

1. If any applicable policy, global or agent-specific, forbids the request, the decision is **deny**. An agent-specific policy cannot override a global denial.
2. Otherwise, if at least one applicable policy permits it, the decision is **allow**.
3. Otherwise the decision is **deny** (default deny).
4. Any error, an evaluation that exceeds its deadline, a missing or unverifiable bundle, an unknown agent, a request outside the profile, an expired lease or a halt results in **deny**.

**Rule 4 is stricter than Cedar.** Cedar skips a policy whose evaluation fails and decides with the others, so a failing `forbid` can leave a `permit` standing. White Tower denies instead: if the evaluation reports any error, the decision is `deny` with reason `error.evaluation`. Vector C-14 checks it. Validation before approval (section 6.7) prevents such errors in practice.

- **EP-2** requires every enforcement point to bound evaluation time. The deadline is configurable; decisions normally take well under a millisecond (spike S1), and a deadline of 50 milliseconds is RECOMMENDED.

### 6.6 Responses and reasons

`decision` is `true` only with reason `policy.permit`. The `context` always carries a `reason` and the list of determining `policies` (White Tower policy IDs, each once, in ascending order). It carries `bundle_version`, the version of the bundle that decided: always with `policy.permit`, `policy.forbid`, `policy.no_permit`, `error.evaluation` and the reasons of the catalog check, never with the gate's reasons, and optionally with `error.timeout`, `error.unknown_agent` and `error.invalid_request`. `obligations` is reserved and always empty: decisions are booleans in `v1alpha1`.

| Reason | Decision | Meaning | Determining policies |
| --- | --- | --- | --- |
| `policy.permit` | allow | At least one policy permits, none forbids | The permitting policies |
| `policy.forbid` | deny | A policy forbids | The forbidding policies |
| `policy.no_permit` | deny | No policy applies | None |
| `gate.no_state`, `gate.lease_expired`, `gate.halted`, `gate.fleet_halted`, `gate.lifecycle`, `gate.no_bundle`, `gate.evidence_full` | deny | The gate is closed (section 5.4) | None |
| `catalog.blocked`, `catalog.unknown`, `catalog.not_approved`, `catalog.not_enabled`, `catalog.definition_changed`, `catalog.digest_mismatch` | deny | The catalog check denied the tool or the model (section 6.9) | None |
| `error.evaluation` | deny | The evaluation reported an error | The policies that failed |
| `error.timeout` | deny | The evaluation exceeded its deadline | None |
| `error.unknown_agent` | deny | The request is for an agent the bundle is not for, or the enforcement point cannot establish an agent in its scope (EP-11) | None |
| `error.invalid_request` | deny | The request does not match the profile | None |

- **Requests outside the profile.** Before it evaluates, an enforcement point checks that the request is inside the profile: its schema, and sections 6.2 to 6.4, 6.7 and 6.11. It denies a request outside it with `error.invalid_request`, even when the engine would detect it.
- **Which reason wins.** After the gate (section 5.4) come, in this order: `error.unknown_agent`, which a subject whose type is not `agent` also gets; for the tool and model actions, the catalog check (section 6.9); then `error.invalid_request`; then `error.timeout`, once the deadline has passed; then rules 1 to 4 of section 6.5.

### 6.7 Policy languages

**`v1alpha1` is Cedar only** (open question Q5, spike S1, and the review of RFC-0001): its "forbid overrides permit" and default deny are exactly rules 1 to 3, and both engines tested, `cedar-go` and `cedarpy`, give the same results on every vector. Cedar runs inside the enforcement point, or beside it in an embedded policy engine (section 2). Policies are static Cedar policies, with entity tags and the `datetime` and `duration` extensions, as `cedar-go` 1.8.0 and `cedarpy` 4.12.1 implement them, and no templates.

- **Schema.** [`whitetower.cedarschema`](../../api/policy/whitetower.cedarschema), namespace `WhiteTower`, declares the entity types (`Agent`; `Tool`, with the properties of section 6.3, whose parent is its `McpServer`; `Model`, whose `provider`, `name` and `endpoint` are required; and the reserved `Dataset`, `Skill` and `Url`), the nine actions and the context types. The context of `tool.expose` requires `calls_decided`, and that of `model.invoke` may carry `digest`.
- **Mapping.** The principal is `WhiteTower::Agent::"<agent-id>"`, with the subject's properties as attributes and its labels as tags. The action is `WhiteTower::Action::"<name>"`. The resource is the entity type of its resource type, with its ID and properties; for agent actions, it is the principal itself. An MCP tool's parent is its server, `WhiteTower::McpServer::"<key>"`, so that a policy can name a whole server: `resource in WhiteTower::McpServer::"github"`. The context holds `time` as a `datetime`, the optional strings, `calls_decided` and `digest`, and `args` as a record of per-tool records, whose arrays are sets. A number that is not an integer in the range of Cedar's `Long` makes the request invalid (section 6.4).
- **One policy set per bundle.** The enforcement point parses every policy of the bundle into one Cedar policy set, once per bundle, and reports each Cedar statement as its policy's White Tower ID.
- **Fixed values.** The core refuses a policy that compares an attribute whose values the profile fixes, such as `risk_tier` or `environment`, with a value outside them (plan P1-06): such a comparison would silently never match, or always.
- **Agent-specific policies need not name their agent.** A bundle holds only its agent's specific policies, so they apply to that agent alone. The validator warns when an agent-specific policy names another principal.
- **Each bundle has its own schema.** The base schema declares `ToolArgs` empty. The core generates each bundle's schema from it, declaring in `ToolArgs` one optional record per tool, with the arguments that the catalog declares for that tool and their types (section 6.11), for example `type ToolArgs = { "github/create_pull_request"?: { "base"?: String } };`. The arguments of the agent's own tools appear only in that agent's schema. Enforcement points fill only those arguments. The core validates policies against the generated schema, in strict mode, before approval (POL-07), and ships it in the bundle.

**Rego waits for Phase 2.** The review of RFC-0001 found the wrapper drafted for it failing open in several cases on OPA 1.21, so `v1alpha1` has no Rego, and section 12 lists what its mapping must settle. The wrapper leaves `api/policy`, whose files are normative (section 1), and stays as a sketch for that work.

### 6.8 Decision points

A decision point is a `policy-engine` module that others call, rather than one embedded in an enforcement point. **`v1alpha1` has none:** a policy engine's manifest declares `embedded: true`. What follows is an informative preview of `v1beta1`, where the Phase 2 gateways need decision points. A decision point exposes the AuthZEN Access Evaluation API (`POST /access/v1/evaluation`, with discovery at `/.well-known/authzen-configuration`) with this profile, and declares it as an endpoint (`protocol: authzen-1.0`) in its manifest. The enforcement point that calls it still checks its own gate first, and treats an unreachable decision point as a denial (`error.timeout`). Section 12 lists what `v1beta1` must settle first.

### 6.9 The catalog check

For `tool.invoke`, `tool.expose` (section 6.10) and `model.invoke`, an enforcement point checks the agent's catalog (section 7.7) after `error.unknown_agent` and before `error.invalid_request` (section 6.6). It denies with the first reason that applies:

| Order | Condition | Reason |
| --- | --- | --- |
| 1 | A block covers the server, the tool or the model (section 5.10) | `catalog.blocked` |
| 2 | The bundle's catalog does not list it | `catalog.unknown` |
| 3 | Its status is `discovered` | `catalog.not_approved` |
| 4 | It is not enabled for the agent | `catalog.not_enabled` |
| 5 | The tool's definition, as the agent has it now, differs from the pinned one | `catalog.definition_changed` |
| 6 | A digest is pinned for the model, and the runtime's digest differs or is unknown | `catalog.digest_mismatch` |

Blocks come first, so they also cover entries the bundle does not list. The check needs the agent's bundle, so it follows `error.unknown_agent`; the arguments' types, and what transforms can read, come from the catalog, so `error.invalid_request` follows it (EP-19). For `tool.result` and `model.result`, which an enforcement point SHOULD evaluate (section 6.3), only row 1 applies: a block issued while a call runs keeps its result from the agent and its model.

- **EP-16. Catalog check.** Apply the catalog check to every `tool.invoke`, `tool.expose` and `model.invoke`, and its first row to every `tool.result` and `model.result` evaluated. Resolve the tool or the model by its reference at the time of the call, never by its name alone. Anything that cannot be resolved is `catalog.unknown`. A decision with a `catalog.*` reason carries `bundle_version`, because the catalog is part of the bundle, and no determining policies (section 6.6). It names tooling that the catalog does not list by its name as the agent sees it, with the SHA-256 of its reference, and a block by its ID (section 8.5).

What passes the check is enabled for the agent. Its resource's ID is then its key, and its properties come from the catalog, never from the agent (section 6.3). Policies can forbid more; they can never reach what is not enabled. The core seeds a global policy, named `wt-catalog`, that permits the tool and model actions, so that an enabled entry is usable unless a policy forbids it (plan P1-06):

```cedar
permit (
  principal,
  action in [
    WhiteTower::Action::"tool.expose", WhiteTower::Action::"tool.invoke", WhiteTower::Action::"tool.result",
    WhiteTower::Action::"model.invoke", WhiteTower::Action::"model.result"
  ],
  resource
);
```

The steering committee approves it like any global policy, and may narrow it, for example to non-production credentials. Every bundle carries a catalog file (section 7.7), so an enforcement point that does not know catalogs rejects the bundle rather than apply the permit without the check.

### 6.10 Exposure and provider-run tools

`tool.expose` is the offer of a tool to a model, in a model request. Its resource is the tool, and its context carries `calls_decided`: true when every call of the tool will be decided as `tool.invoke` before it runs. That holds for the tools the agent runs, and for a provider-run tool only while the provider submits each of its calls to the agent for approval (EP-18). A usage rule forbids exposing a tool whose calls are not decided (section 6.11), so that no rule is approved and then never applied.

- **EP-17. Exposure.** Before each model call, evaluate `tool.expose` for every tool the request offers, with `calls_decided` set as above, and remove the denied ones from the request. When a denied tool cannot be removed:
  - deny the model call if the tool is provider-run, because the provider would call it without passing through the agent;
  - deny the model call if the denial is `catalog.definition_changed`;
  - otherwise, the enforcement point SHOULD deny the model call.

  Exposure decisions MAY be reused until the bundle, the agent's state, the blocks, the tool's definition or whether its calls are decided change, or until the instance registers again, since its registration gives the subject's environment (I-7). A model call therefore normally costs no evaluation. An exposure decision is recorded when it is evaluated; reusing it writes nothing. Policies on `tool.expose` therefore SHOULD NOT read the context, except `calls_decided`: its other fields, such as the time and the task, change between the model calls that reuse a decision.

A changed, possibly poisoned, description never reaches the model. Where the framework allows it, neither does any tool the agent may not use.

**Provider-run tools.** The enforcement point sees a provider-run tool twice: declared in the model request, and in the response once it has run.

- **EP-18. Provider-run tools.**
  - Narrow each declared remote MCP server to the tools enabled for the agent, for example by setting the declaration's list of allowed tools.
  - Deny the model call when it would let the provider call a tool that is not enabled.
  - Where the provider can submit each call of a provider-run tool to the agent for approval, have it do so for every such tool that a usage rule of the bundle names (the tools that the `@rule` annotations of its policies list, section 6.11), and MAY for the others. Evaluate `tool.invoke` for each submitted call, with its arguments, and answer with the decision.
  - Record the provider-run calls that a response reports as `action.executed` events with origin `provider`.
  - When a response lists a provider-run MCP tool whose definition differs from the pinned one, deny its exposure from then on (`catalog.definition_changed`).

The provider lists a remote server's tools itself, so the enforcement point learns of a changed definition only from a response, after the model may have seen it once. The [threat model](../security/threat-model.md) records this residual (T-79), and its assumption that model providers run only the tools a request declares, and report the calls they made (A-7).

### 6.11 Arguments and usage rules

Policies see two sets of a tool's arguments: those that the usage rules of the agent's effective policy set use, and those a reviewer declared for the tool in the catalog. The core lists them in the catalog file (`args`, section 7.7) and declares them in the bundle's Cedar schema (section 6.7). A policy version with a statement that reads any other argument is refused when it is submitted: enforcement points never fill that argument, so the condition could never hold.

- **Declarations stay stable.** A declaration that an active policy version reads cannot be withdrawn, and a declared argument's type cannot change while an active usage rule uses it. A new definition that gives the argument another type can still be approved; a value that does not fit the declared type then denies the call (EP-19).
- **One record per tool.** `context.args` holds one record per tool, keyed by the tool's key, with the declared arguments inside: `context.args["github/create_pull_request"]["base"]`. Per-tool records keep types unambiguous: `id` can be a number for one tool and a string for another. The arguments of the agent's own tools (`agent/<name>`) are declared only in that agent's schema, because the same name can mean other arguments in another agent: global policies, and their usage rules, cannot read them.
- **Naming.** An argument is named by its path in the call's arguments, for example `options.base` for a nested field. When a transform applies, a colon and the transform's name follow: `path:path`, `url:url_host`. A path goes through objects only, never into an array's elements, and a property whose name contains `.` or `:` cannot be declared, so that a name reads only one way.
- **Types** come from the tool's input schema: strings, integers and booleans, and arrays of strings or of integers, which become sets. A transform applies to a string, and to each element of an array of strings.

| Transform | Value |
| --- | --- |
| `lowercase` | The string, with ASCII letters in lowercase |
| `path` | The path, cleaned as below |
| `url_host` | The host of a URL, read as below |
| `email_domain` | The domain of an address, read as below |

A value that a transform cannot read denies the call (EP-19). The three that read structure refuse what parsers read differently, since a tool reads its arguments with its own parser: a rule must see what the tool will do.

**`path`** cleans a path lexically. Once backslashes are slashes, it gives what Go's `path.Clean` gives; Python's `posixpath.normpath` differs, keeping a leading `//`, so it would let `//etc/passwd` past a rule on `/etc/*`.

1. A value with a control character (U+0000 to U+001F, U+007F) cannot be read: a server written in C stops at a NUL, and would open another file than the one the rule saw.
2. Backslashes become slashes.
3. The path is split at slashes. Empty segments and `.` are dropped. `..` removes the segment before it, unless that segment is a `..` kept at the start; with no segment before it, `..` is dropped in an absolute path and kept in a relative one.
4. A path that starts with a slash is absolute, and is written with one leading slash; a relative one is written without. An empty result is `/` for an absolute path and `.` for a relative one. Drive letters and UNC names are ordinary segments: `C:\Windows\..` becomes `C:`.

For example, `//srv/./data/../../etc/passwd` becomes `/etc/passwd`, and `a/../../x` becomes `../x`.

**`url_host`** reads the host of a URL. Parsers disagree on some URLs: Python's `urllib.parse` reads `http://evil.com\@good.com/` as `good.com`, while requests and Node's WHATWG parser read `evil.com`.

1. Leading and trailing spaces and C0 control characters (U+0000 to U+001F) are ignored, as WHATWG's and Python's parsers do. A control character (U+0000 to U+001F, U+007F) anywhere else cannot be read.
2. The URL starts with a scheme (RFC 3986, section 3.1) and `//`, whatever the scheme. A value without them, such as `example.com`, cannot be read: tools complete it in different ways.
3. The authority runs to the first `/`, `?` or `#`. A backslash, or whitespace as Unicode's White_Space property defines it, in the authority cannot be read.
4. User information is ignored: the host follows the last `@` of the authority, as every parser reads it.
5. A port, after the host and a colon, is 1 to 5 digits, and at most 65535: a colon with nothing after it cannot be read.
6. An IPv6 address, in brackets, is written as section 4 of RFC 5952 says, in brackets. One with a zone ID cannot be read, and neither can one written with a dotted part or in the IPv4-mapped range (`::ffff:0:0/96`): both are other spellings of an IPv4 address, which stacks write differently (`[::ffff:7f00:1]` in Node, `[::ffff:127.0.0.1]` in Go and in Python 3.13).
7. Any other host that has a `%` cannot be read. The rest is converted to A-labels as WHATWG's "domain to ASCII" does without strictness: UTS #46, non-transitional, without the STD3 rules, so that underscores pass, and with joiners and Bidi checked. An A-label that does not decode cannot be read. The host is then in lowercase and loses one trailing dot; one with an empty label, a leading dot included, or with any character but letters, digits, `.`, `-` and `_`, cannot be read.
8. A host whose last label is then a number (decimal digits, or `0x` and any hexadecimal digits) is an IPv4 address, and must be four decimal numbers from 0 to 255 without leading zeros: `0x7f.1`, `2130706433` and `127.1`, which parsers and resolvers take to 127.0.0.1, cannot be read.

**`email_domain`** reads the domain of an address.

1. Leading and trailing spaces (U+0020) are ignored. A control character anywhere, a tab included, cannot be read.
2. The value is an address; `Display Name <address>`, whose name may be empty, with no quote, angle bracket, `@`, `,`, `;`, `:`, parenthesis, square bracket or backslash in the name; or `"Quoted Name" <address>`, with no quote or backslash between the quotes.
3. The address has exactly one `@`, and a local part that is not empty and has no whitespace, quote, parenthesis, angle bracket, square bracket, backslash, `,`, `;` or `:`. A `,` or `;` cannot be read: several addresses in one string, of which a rule would see only one.
4. The domain is read as `url_host` reads a host (its steps 7 and 8), but neither an IPv6 address nor a domain literal (`[192.0.2.1]`) nor a domain whose last label is a number can be read.

Legitimate values that these rules refuse are rare: a URL without a scheme, a quoted local part, a domain literal. A tool that takes several recipients in one string has those calls denied by any rule on `email_domain`; one that takes them as an array does not.

- **EP-19. Arguments.** Fill only the declared arguments, and apply their transforms. A value that does not fit its declared type, or that a transform cannot read (a URL without a host, for example), denies the call with `error.invalid_request`. Values never reach evidence (section 8.3).

**Usage rules.** A usage rule forbids a pattern of use of one or more tools, and is enforced on every call: a tool with a rule is offered to a model only when each of its calls will be decided (section 6.10). Rules live in ordinary policies, global or agent-specific, which are approved like any other policy text, and the core generates their Cedar statements:

| Field | Meaning |
| --- | --- |
| `id` | Unique within its policy |
| `description` | Why the pattern is forbidden, for reviewers |
| `tools` | Tool keys |
| `when` | Conditions. The rule forbids a call when all of them hold |

Each condition has the following fields:

| Field | Meaning |
| --- | --- |
| `arg` | The argument's path, for example `branch` or `options.base` |
| `transform` | Optional: a transform from the table above |
| `op` | The operator, from the table below |
| `values` | The values to compare with |
| `if_absent` | `match` (the default: a missing argument counts as matching, so the rule fails closed) or `no_match` |

| Operator | Holds when |
| --- | --- |
| `equals`, `not_equals` | The value is, or is not, the single value given |
| `in`, `not_in` | The value is, or is not, one of the values. For an array: at least one element is in them, or at least one element is not |
| `matches`, `not_matches` | The string matches one of the patterns, or matches none of them. Patterns are Cedar `like` patterns, where `*` matches any sequence of characters |
| `less_than`, `greater_than` | The integer is smaller, or larger, than the value |

Each operator takes some types only, since Cedar cannot test each element of a set against a pattern or a bound:

| Argument type | Operators |
| --- | --- |
| String | `equals`, `not_equals`, `in`, `not_in`, `matches`, `not_matches` |
| Integer | `equals`, `not_equals`, `in`, `not_in`, `less_than`, `greater_than` |
| Boolean | `equals`, `not_equals` |
| Set of strings or of integers | `in`, `not_in` |

`values` is never empty, and holds exactly one value for `equals`, `not_equals`, `less_than` and `greater_than`. Its values have the argument's type, or are patterns for `matches` and `not_matches`. Transforms apply to strings and to sets of strings. The generator refuses any other rule.

A rule compiles to two Cedar `forbid` statements per tool. Each is annotated with `@rule`, the canonical JSON of the rule's ID and description, the statement's tool and the rule's conditions, so that an annotation grows with the conditions, never with the number of tools. One statement forbids the calls that match the conditions; the other forbids offering the tool to a model while its calls are not decided:

```cedar
@rule("{\"description\":\"Pushes to main go through pull requests\",\"id\":\"no-push-to-main\",\"tool\":\"github/push_files\",\"when\":[{\"arg\":\"branch\",\"op\":\"in\",\"values\":[\"main\",\"master\"]}]}")
forbid (
  principal,
  action == WhiteTower::Action::"tool.invoke",
  resource == WhiteTower::Tool::"github/push_files"
) when {
  if context has args && context.args has "github/push_files" && context.args["github/push_files"] has "branch"
  then ["main", "master"].contains(context.args["github/push_files"]["branch"])
  else true
};

@rule("{\"description\":\"Pushes to main go through pull requests\",\"id\":\"no-push-to-main\",\"tool\":\"github/push_files\",\"when\":[{\"arg\":\"branch\",\"op\":\"in\",\"values\":[\"main\",\"master\"]}]}")
forbid (
  principal,
  action == WhiteTower::Action::"tool.expose",
  resource == WhiteTower::Tool::"github/push_files"
) unless {
  context.calls_decided
};
```

- **Generated text is checked.** The statements of one policy whose annotations carry a rule's ID make up the rule: they carry the same description and conditions, and both statements of each of its tools. When a policy version is submitted, the core regenerates each statement that carries `@rule` from its annotation, and refuses the version unless every statement equals, once parsed, what the generator produces, and every rule is whole. The annotation's JSON is written as a Cedar string, its quotes and backslashes escaped with a backslash. The generator takes each argument's type from the catalog's declarations, because a condition compiles differently for a string and for a set. Each statement carries its rule, so the policy text is the only source of truth.
- **Evidence names the rule.** An enforcement point reads a statement's rule from its annotation: a decision names each rule that decided by its policy and its rule ID (section 8.5), so the audit log says "denied by `no-push-to-main`".
- **Limits.** Cedar's `like` is the only pattern language, so rules can use no regular expressions. Rules are stateless: sequences of calls and counts per task are left to Phase 2. A path is cleaned lexically, so symbolic links on the server are not resolved: path rules are safe as allow-lists, `not_matches` on the directories a tool may use, since a relative path or a symbolic link escapes a deny-list such as `matches "/etc/*"`.

## 7. Policy bundles

### 7.1 Contents

A bundle is a manifest, its signature and its files (format `whitetower.bundle.v1`, schema [`bundle-manifest.schema.json`](../../api/policy/bundle-manifest.schema.json)):

| Manifest field | Meaning |
| --- | --- |
| `format` | `whitetower.bundle.v1` |
| `agent_id`, `version` | The agent, and a version that only grows |
| `created_at` | When the core built it |
| `combining_algorithm` | `wt-deny-overrides-v1` |
| `language` | `cedar`, the only language of `v1alpha1` (section 6.7) |
| `cedar_schema` | Required: the Cedar schema the policies were validated against, at `schema.cedarschema` |
| `catalog` | The agent's catalog file, at `catalog.json` (section 7.7). The core always includes it, and an enforcement point decides on a bundle without one as with an empty catalog |
| `policies` | Each policy's ID, name, version, scope (`global` or `agent`), path and SHA-256 |

Policy files live at `policies/<scope>/<policy-id>.cedar`. A bundle holds no files other than those its manifest lists.

### 7.2 Signature

- The signed bytes are the **RFC 8785 canonical JSON** of the manifest, transported exactly as signed.
- The JWS signing input is `BASE64URL(protected header)`, a period, and `BASE64URL(manifest bytes as received)`, as RFC 7515 defines it: the payload is detached, never unencoded (RFC 7797).
- The signature is a **JWS compact serialization with a detached payload** (RFC 7515, appendix F): `<protected header>..<signature>`. The protected header has exactly three members, in any order: `alg` (`EdDSA`), `kid` (the key ID) and `typ` (`whitetower-bundle+jws`), with an Ed25519 key (RFC 8037). The key ID is RECOMMENDED to be the key's RFC 7638 thumbprint.
- `EdDSA` stays, although RFC 9864 deprecates it for the fully specified `Ed25519`, under that RFC's exception for a key fixed to one curve: the key here is always Ed25519, and go-jose and most JOSE libraries accept only `EdDSA`. A later version may move to `Ed25519` through `BundleKey.algorithm`.
- The core signs with its bundle key, separate from its token and checkpoint keys.

### 7.3 Delivery and keys

- Governance state refers to the bundle by version, manifest hash and size; `GetBundle` returns it.
- **EP-11** requires the bundle keys to come from configuration: that is the enforcement point's trust root. `GetBundleKeys` lists the active, next and retired keys, so operators can distribute the next key before a rotation. An enforcement point MUST NOT trust a key only because `GetBundleKeys` lists it.
- Enforcement points SHOULD take their bundle keys as a JWK Set (RFC 7517) of `OKP` keys on the `Ed25519` curve (RFC 8037).
- Removing a key from an enforcement point's configuration revokes it there. Whenever the configured keys change, at start or on a reload, the enforcement point MUST verify its active bundle again, and a bundle that no configured key verifies does not stay active: the gate closes with `gate.no_bundle`.

### 7.4 Verification

An enforcement point verifies a bundle with these steps, in this order, and activates it only if all pass:

1. **V1. Size.** The size announced in the state and the actual size are at most 2 MiB, in at most 1,000 files.
2. **V2. Signature.** The signature is a detached JWS whose header is exactly as in section 7.2, its key ID is trusted, and it verifies over the manifest bytes as received.
3. **V3. Reference.** The SHA-256 of the manifest bytes equals the one in the governance state.
4. **V4. Manifest.** In this order: a manifest that is not an object, that has an unknown or a missing member, or a member of the wrong type, is `invalid_manifest`; a format, combining algorithm or language that is not supported is `unsupported`, even when the schema's constant also fails; an agent or a version other than the state's is `invalid_manifest`. A Cedar manifest names its schema (`cedar_schema`), and the `catalog` member names the catalog file (section 7.7).
5. **V5. Files.** Each policy's path is built from its entry's own ID and scope and the language, `policies/<scope>/<policy-id>.cedar`, with no duplicates; the Cedar schema sits at `schema.cedarschema` only, and the catalog file at `catalog.json` only: any other path is malformed. Every listed file is present with its hash, and no other file is present.
6. **V6. No rollback.** The version is newer than the active one. The same version with the same manifest hash is already active: there is nothing to do.
7. **V7. Policies and catalog.** Every policy parses as a static policy of the Cedar that section 6.7 names; a template is `parse_error`. The catalog file parses against its schema (section 7.7), or is `parse_error` too. Validating policies against the Cedar schema is the core's job (POL-07): an enforcement point MUST NOT reject a bundle because a policy fails that validation, and it may log it and SHOULD report `HEALTH_DEGRADED`.

The [bundle vectors](../../test/conformance/vectors/bundles/README.md) cover each step with signed examples.

### 7.5 Rejection reasons

| Reason | Step |
| --- | --- |
| `oversized` | V1 |
| `unknown_key`, `signature` | V2 |
| `manifest_mismatch` | V3 |
| `invalid_manifest`, `unsupported` | V4 |
| `missing_file`, `file_hash`, `extra_file` | V5 (a malformed path is `invalid_manifest`) |
| `older_version` | V6 |
| `parse_error` | V7 |

### 7.6 Activation

- The new bundle, its catalog file included, replaces the old one atomically: a decision uses one bundle or the other, never a mix.
- The outcome is acknowledged (`BundleAcknowledgement`) and emitted as `whitetower.bundle.activated.v1` or `whitetower.bundle.rejected.v1`.
- A rejected bundle leaves the previous one active; with none, the gate stays closed (`gate.no_bundle`).
- An enforcement point MUST NOT retry a rejected version with the same manifest hash: it waits for a new reference in the state, unless its bundle keys have changed since it rejected that version (section 7.3).

### 7.7 The catalog file

Every bundle carries its agent's catalog file, `catalog.json`, listed in the manifest like the Cedar schema (`catalog`, with its path and SHA-256). It is activated with the policies, atomically, and holds the entries enabled for the agent and those observed for it (section 4.10), and the deployment's redaction rules:

```json
{
  "format": "whitetower.catalog.v1",
  "redaction": { "url_prefixes": ["https://mcp.example.net/s/"], "flags": ["pat"] },
  "servers": [
    { "key": "github", "reference": "https://api.githubcopilot.com/mcp/", "transport": "http", "status": "approved" }
  ],
  "tools": [
    {
      "key": "github/create_pull_request", "server": "github", "name": "create_pull_request",
      "kind": "mcp", "origin": "agent", "status": "approved", "enabled": true,
      "definition": "4d1c…", "read_only": false, "destructive": false, "open_world": true,
      "args": [{ "name": "base", "path": ["base"], "type": "String" }]
    }
  ],
  "models": [
    {
      "key": "gpu-01/llama3.1-8b", "provider": "ollama", "endpoint": "http://gpu-01.internal:11434/",
      "name": "llama3.1:8b", "status": "approved", "enabled": true, "digest": "46e0…"
    }
  ]
}
```

- **Status and enablement.** `status` comes from the catalog and is `discovered` or `approved`; `enabled` comes from the agent's enablement. An agent is enabled to use tools and models, so servers carry no `enabled` field, and a tool of an MCP server can be approved only once its server is. Blocks never appear in the file: they travel in the watch stream (section 5.10).
- **Pinned values.** `definition` and `digest` are pinned when the entry, or its new definition or digest, is approved.
- **Classification.** `read_only`, `destructive` and `open_world` are set by the reviewer. They start from the tool's MCP annotations, or, when those are absent, from the protocol's conservative defaults: not read-only, destructive, open world. Annotations are hints from the server; the catalog's values have been reviewed.
- **Arguments.** `args` lists the tool's arguments that policies may see (section 6.11): each with its name, which is its key in `context.args`; its path, as the array of the property names that lead to it; its transform, when it has one; and its type.
- **Redaction rules.** `redaction` carries the deployment's redaction rules (EP-14): URL prefixes, after each of which the next path segment is a secret, and flag names whose values are secrets, beyond those EP-14 lists. Some services put an account's secret in a URL's path, as Zapier's MCP server does. A change of the rules rebuilds every bundle.
- **Size.** The core keeps every bundle within the limit of V1 (2 MiB). The entries enabled for the agent come first: a request to enable an entry that would take the agent's bundle over the limit is refused, with that reason. Entries observed but not enabled are listed while they fit, those seen most recently first; one left out is denied as `catalog.unknown`, the decision it would get anyway, with a less precise reason. A tool takes a few hundred bytes of the file: an agent with 300 tools has a file of about 130 KiB, while one at the limits of a report (section 4.10) would need from about 1.8 MiB, with short references, to 4.5 MiB. When the enabled entries and the policies alone do not fit, the core publishes no bundle: the agent keeps the one it has, and the console says why.
- **An empty catalog.** The file is there even when nothing is observed or enabled for the agent. An enforcement point treats a bundle without one as an empty catalog: every tool and model action is then `catalog.unknown`.
- **Format.** The file is a closed document (section 10), `whitetower.catalog.v1`, whose JSON Schema is in [`api/policy/`](../../api/policy/README.md).
- **Verification.** Step V4 knows the manifest's `catalog` member, step V5 requires its file, and step V7 parses the file against its schema (`parse_error`). An enforcement point that does not support catalogs rejects such a bundle (`invalid_manifest`, since the member is unknown to it): it keeps its last valid bundle or, with none, stays closed, and it never activates a bundle that carries a catalog (section 7.6).

## 8. Events

### 8.1 Overview

Every event ends in the tamper-evident audit log: sealed into its Merkle tree, covered by signed checkpoints and exported ([ADR-0006](../adr/0006-tamper-evident-audit-log.md)). Modules deliver theirs through `EventService.Publish`; the core writes its own in the transaction of each change (AUD-01). The catalog, [`api/events/catalog.json`](../../api/events/catalog.json), lists every type with its schema and an example; CI validates them.

### 8.2 Envelope

Events are **CloudEvents 1.0 in the JSON format**, and I-JSON (section 1), validated by [`cloudevent.schema.json`](../../api/events/cloudevent.schema.json):

| Attribute | Rule |
| --- | --- |
| `specversion` | `1.0` |
| `id` | Unique within the source; UUIDv7 RECOMMENDED |
| `source` | The evidence stream: `/core`, `/agents/<agent-id>/ep/<stream-id>` for an enforcement point inside an agent, `/modules/<module>/<stream-id>` for other modules. `<module>` is the module's slug (`metadata.name`). `<stream-id>` names an evidence buffer: the instance creates it with its buffer and stores it there, at least 64 random bits in lowercase hexadecimal, never a host, pod, cluster or instance name. The instance key of I-8 can reuse it |
| `type` | A catalog type, `whitetower.<area>.<event>.v<N>` |
| `time` | When it happened, at the source |
| `subject` | The agent ID, when the event is about one agent (the catalog says when it is required) |
| `datacontenttype` | Optional: `application/json`, which its absence means in the JSON format |
| `data` | An object, valid against the type's schema |
| `wtseq` | Required from modules, absent from the core: the event's position in its source, as a decimal string (`"1"`, `"2"` and so on, without gaps). A string, because CloudEvents integers are limited to 32 bits; not the standard `sequence` extension, since decimal strings without padding do not sort as numbers |
| `traceparent`, `tracestate` | The W3C trace context (CloudEvents distributed tracing extension), when the action has a trace. `traceparent` may have any version but `ff`. Both follow the privacy sections of W3C Trace Context (its section 6) and of CloudEvents |
| `wtorigtype` | For events translated by an adapter, the original type, for example AGT's `ai.agentos.tool.blocked` |
| `wtrequestid` | From the core only: the ID of the request that made the change, as the core's logs and its `X-Request-Id` header give it |
| `dataschema` | Optional in `v1alpha1`. A later contract version may require it, with stable URLs, once the project has a domain of its own, which question Q6 decided on 2026-09-30 it does not have for now |

Other extension attributes are allowed and kept, since they are part of the evidence.

**Narrower than CloudEvents 1.0.** The envelope's schema refuses some events that CloudEvents allows, and common SDK defaults fail it. Each failure is `REJECTED` for good (section 8.4):

- `time` has exactly three fractional digits and ends in `Z`. Write it with a fixed layout, such as `2006-01-02T15:04:05.000Z` in Go: Go's `RFC3339Nano` drops trailing zeros, and Python's `isoformat()` writes six digits;
- no attribute is null, although the JSON format lets an encoder write an unset attribute as null;
- an extension's name has at most 20 characters, and its value is a string, an integer or a boolean;
- `id` has at most 128 characters.

### 8.3 Personal data

Events are minimized by design (NFR-20, domain model section 7):

- People appear only as pseudonymous principal IDs, never as names or email addresses.
- Decision events record the **names** of a call's arguments, or nothing, or, in the hashed mode, the HMAC-SHA-256, in lowercase hexadecimal, of the canonical JSON (section 1) of the arguments object as the tool receives it, with a key the deployment holds and that key's ID (`key_id`), as configured. They never record argument values in `v1alpha1`.
- A resource ID longer than 512 characters, or an argument name longer than 128, is recorded as its SHA-256, marked as such.
- Tooling is named by its key or, when the catalog does not list it, by its name as the agent sees it, with the SHA-256 of its reference (`reference_sha256`, section 4.10). Events never carry a reference in clear, a description or a schema. The hash keeps the reference's text out, but it is not a pseudonym: a local path that can be guessed can be checked against it.
- Values that a module copies from the agent or its framework, such as `task_id` or an extension attribute, follow the first rule. A framework's run or thread ID is recorded only when the deployment declares it opaque; otherwise it is recorded as its HMAC, or not at all.
- Every `detail` field carries fixed text or codes: never messages, values, paths or names.
- Prompts, model outputs and tool results are never recorded in `v1alpha1`.
- Failed calls record the error's type, never its message.
- Halt reasons are free text written by people: they stay in the core's events and are never sent to modules.

### 8.4 Delivery

- **At least once.** The core de-duplicates on source and ID, and recognizes an event by them for at least 28 days: a retried batch is safe.
- **I-12. In order, one call at a time.** An instance MUST send each source's events in `wtseq` order, and send an event only once every earlier event of its source has a result (`ACCEPTED`, `DUPLICATE` or `REJECTED`), so that at most one `Publish` call that carries a given source is in flight. After a failure, whatever its code, it sends those events again, in batches of its choosing, before any later event of the source.
- **Findings.** The core records a gap as soon as an event arrives past the next expected position of its source, and the finding stays (AUD-02). It also records a finding when a source's `wtseq` repeats, or goes back, under a new event ID.
- **Stable sources.** A source identifies an evidence stream, not a process: an instance that keeps its buffer across restarts keeps its source and continues its sequence. A new buffer starts a new source at 1. A source has exactly one writer, and is not bound to the instance that first wrote it.
- **Backlog.** An instance SHOULD report `HEALTH_DEGRADED` once its oldest undelivered event is older than a threshold, and reports `HEALTH_UNHEALTHY` while its gate is closed with `gate.evidence_full` (section 4.9).
- **Results.** The core decides each event on its own. It checks de-duplication first, so a retry of an event it accepted stays `DUPLICATE`, even once its agent has left the scope. An event outside the rules of section 4.3, of a type the module does not emit, from a source it does not own or about an agent outside its scope, is `REJECTED` with its reason, and the other events of the batch are still decided. `ACCEPTED` and `DUPLICATE` events leave the buffer. A `REJECTED` event can never be accepted: the instance MUST NOT retry it, MUST log it and SHOULD report `HEALTH_DEGRADED`. The gap it leaves stays visible in the audit log.
- **Durability (EP-8).** An enforcement point writes each decision to a durable local buffer before the action proceeds, sized for at least 24 hours at 10 events per second (NFR-08), and closes its gate when the buffer is full.

### 8.5 Catalog

| Type | Emitted by | Subject | When |
| --- | --- | --- | --- |
| `whitetower.decision.made.v1` | Enforcement points | Required | A governed call or interaction was decided, allowed or denied, with the decision's `bundle_version` (section 6.6), the usage rules that decided, each by its policy and rule IDs, and the resource's origin. A denial of the catalog check also names, for tooling the catalog does not list, its `reference_sha256`, and for a block, its `block_id` (EP-16) |
| `whitetower.action.executed.v1` | Enforcement points | Required | An allowed call finished: succeeded, failed or cancelled; or a provider-run call that a model's response reports, with origin `provider` and no `decision_id` (EP-18). Tooling that the catalog does not list carries its `reference_sha256` |
| `whitetower.instance.started.v1` | Any module | Optional | An instance started and registered |
| `whitetower.instance.halted.v1` | Enforcement points | Required | A halt was applied, layer by layer |
| `whitetower.bundle.activated.v1` | Enforcement points | Required | A bundle was verified and activated |
| `whitetower.bundle.rejected.v1` | Enforcement points | Required | A bundle was refused |
| `whitetower.lease.expired.v1` | Enforcement points, runtime control | Required | An instance lost the core for longer than an agent's lease: one event per agent |
| `whitetower.quarantine.applied.v1` | Runtime control | Required | A halted agent's workloads were isolated |
| `whitetower.quarantine.lifted.v1` | Runtime control | Required | The isolation was removed after a release |
| `whitetower.agent.created.v1` | Core | Required | Lifecycle transition T1 |
| `whitetower.agent.lifecycle_changed.v1` | Core | Required | Lifecycle transitions T2 to T14 |
| `whitetower.policy.version_approved.v1` | Core | For agent-specific policies | A committee approved a policy version |
| `whitetower.halt.issued.v1` | Core | For agent halts | A halt was issued |
| `whitetower.halt.released.v1` | Core | For agent halts | A halt was released |
| `whitetower.audit.checkpoint.v1` | Core | None | The audit log signed a checkpoint |

Who emits each type binds: a module emits only the types whose emitters include one of its capabilities (MAN-6). The core emits more types, for every other state change (AUD-01). They follow the same envelope and are defined by the plans that own them; modules do not consume events in `v1alpha1`.

## 9. Conformance

### 9.1 Test vectors

Language-neutral files in [`test/conformance/vectors/`](../../test/conformance/vectors/):

| Vectors | Cases | What they check |
| --- | --- | --- |
| [`combination.json`](../../test/conformance/vectors/combination.json) | 20 | Rules 1 to 4 of the combining algorithm, subject attributes and tags, time, tool arguments, determining policies, invalid requests, and whether each policy passes the validator |
| [`fail-closed.json`](../../test/conformance/vectors/fail-closed.json) | 13 | Every gate condition, and the order of reasons |
| [`bundles/`](../../test/conformance/vectors/bundles/README.md) | 15 | Every verification step, with signed bundles |

They pass on two independent stacks: Go with `cedar-go` 1.8.0 (`go test ./test/conformance`), and Python with `cedarpy` 4.12.1 and `cryptography` ([`check_vectors.py`](../../test/conformance/python/check_vectors.py)).

Step 12 of [P0-03](../plans/phase-0/P0-03-module-contracts.md) adds the vectors of RFC-0002, which both stacks must pass, and their rows join this table with their counts:

- `tooling.json`: references, their string forms and normalized URLs, redaction with the deployment's rules, and definition hashes, with integers beyond 2^53, `null` members, repeated names and lone surrogates (section 4.10);
- `catalog-check.json`: the catalog check, its order and its place among the reasons, blocks included, on results too (section 6.9);
- `exposure.json`: exposure, with calls decided and not decided (section 6.10);
- `arguments.json`: the transforms, with the values each one cannot read, missing arguments and types (section 6.11), among them the cases of RFC-0002's check of URL and address parsers, in [`inputs/url-and-address-check.json`](../../test/conformance/vectors/inputs/url-and-address-check.json);
- `usage-rules.json`: the operators each type takes, the statements the generator produces, and the decisions they give (section 6.11);
- in `bundles/`, bundles with a catalog file (section 7.7).

The combination vectors that use a tool or a model gain a catalog, and their resource IDs become keys.

### 9.2 The kit

The kit plays the core for a module under test: a fake core that speaks the module API (registry, watch with scripted state and leases, bundles, acknowledgements, events) and a driver that exercises the module through the small HTTP protocol of [`driver-protocol.md`](../../test/conformance/driver-protocol.md). Because the kit speaks the module API over the network, it tests a module written in any language. The skeleton in [`test/conformance/kit`](../../test/conformance/README.md) runs scenarios S-01 and S-17 end to end against a stub enforcement point in Go; plan P1-07 completes it. For an enforcement point that serves several agents, the kit runs the halt, lease and bundle scenarios with two agents in scope, and the driver names the agent of each decision. One rule times every timed scenario: the kit times on its own clock, from when the fake core sends, never from what the module reports; it judges only the module's share of a target, and allows 1 second for transport and polling. For S-32, the kit also plays a model provider, at the endpoint that the driver gives the agent's model, and scripts the tools it lists, the calls it submits for approval and those it reports (plan P1-07).

### 9.3 Scenarios

| Scenario | Obligations | Status |
| --- | --- | --- |
| S-01 Start closed: nothing is allowed before state, lease and a verified bundle | EP-1, EP-7 | Implemented |
| S-02 Every gate condition denies, with its reason. The kit runs it once with each environment that its fake core returns at registration: with `production`, a `validated` or `ready` agent stays closed with `gate.lifecycle`. The kit also removes the agent from the state while its lease is valid, and brings it back before the next renewal: the module allows nothing in between, and allows again only after a renewal once the agent is back | EP-2, EP-6, I-11, fail-closed vectors | Designed |
| S-03 The combination vectors give the expected decisions, with their `bundle_version` | EP-2, section 6 | Designed |
| S-04 Lease expiry denies with `gate.lease_expired`, and applies the halt mode, no later than the TTL plus 1 second after the last fresh renewal | EP-3 | Designed |
| S-05 A halt closes the gate, and the gate's acknowledgement arrives within 1 second of the fake core sending the halt. The later layers follow with honest outcomes: the interruption within the bound of NFR-04, and, in the `terminate` mode, the end of the process after the grace period. The kit runs it once with each environment that its fake core returns at registration, `production` and `non_production`, and once in the `terminate` mode | EP-4, section 5.1 | Designed |
| S-06 A fleet halt halts the agent although its own state is unchanged. The kit runs it once with each environment that its fake core returns at registration, `production` and `non_production` | EP-4, section 5.1 | Designed |
| S-07 Reconnecting while halted stays halted. The kit also restarts the module during a halt in the `terminate` mode: the module stays up and closed until the release | EP-1, EP-4, EP-9, section 5.5 | Designed |
| S-08 A release reopens only with a valid lease and bundle | EP-5 | Designed |
| S-09 The bundle vectors are rejected with the right reasons, and the previous bundle stays active. The fake core's `GetBundleKeys` also lists the untrusted key that signs the `unknown-key` vector, and the module must still reject that vector with `unknown_key`. When the driver reloads the module's bundle keys without the key that signed the active bundle, the module verifies its bundle again and closes its gate with `gate.no_bundle` | EP-7, EP-11 | Designed |
| S-10 Events validate against the catalog, with a gapless `wtseq`, and survive a restart. Every allowed call that finishes yields `whitetower.action.executed.v1`. The fake core holds a `Publish` response, and no later event of that source may arrive meanwhile; it fails a call with `RESOURCE_EXHAUSTED`, then one with `UNAVAILABLE`, and the same events must come first after each. After the driver replaces the module's buffer, a new source starts at 1, and two instances of the module write distinct sources. The kit restarts the module while the fake core is unreachable, and the denials it records meanwhile must validate. When the driver stops the module, the kit reports one that deregisters before it has delivered its buffer, without failing it | EP-8, I-5, I-12, section 8.2 | Designed |
| S-11 A full evidence buffer closes the gate, and the module reports `HEALTH_UNHEALTHY` while it is full | EP-8, section 4.9 | Designed |
| S-12 Reconnection uses jittered backoff bounded by the lease, resets after a renewal, and resumes from the last version applied, even when a renewal passed versions that carried nothing for the stream. The module reconnects after a stream cut in the middle of a message, the first one included. When it resumes, it applies a change that carries an agent state older than the version it resumed from, and a snapshot just past that version, which replaces its state. A reconnection within the lease keeps deciding on the last state applied. The kit also black-holes the core, through a TCP proxy that drops traffic without closing the connection, and then refuses connections for over two minutes: the module finds the silent stream and reconnects on a new connection, and its retries stay within the cap of I-4. The fake core also refuses a registration with `PERMISSION_DENIED` and then accepts it, and ends an established stream with `PERMISSION_DENIED` and then accepts the next: the module ends its leases at once, allows nothing meanwhile, and is back within the cap of I-4. A stream body that ends without an end-of-stream message is a cut, and the module resumes. Of the backoff, the kit checks that no wait exceeds the smaller of 30 seconds and a third of the TTL, plus slack; that after a renewal the next wait is within 0.5 seconds, plus slack, with only a warning while that first step is a SHOULD; and that waits vary, as jitter makes them | EP-9, I-4, I-9, sections 4.6 and 5.2 | Designed |
| S-13 Unknown fields and values never open anything. A halt that carries an unknown field also closes the gate and is acknowledged, in the encoding the module uses (binary protobuf or JSON); the kit's fake core scripts it in P1-07.2. For a runtime-control module, an unknown field in a halt never lifts or narrows its layer | EP-10, RC-2 | Designed |
| S-14 A runtime-control module never lifts a layer without a current state | RC-2, RC-3 | Designed |
| S-15 A runtime-control module acknowledges per agent, with the workloads isolated. As the driver starts and stops workloads, the module's heartbeats report as served agents those that have workloads it controls | RC-4, RC-6, I-6 | Designed |
| S-16 Registration refuses an unknown contract version. When the fake core answers `UNIMPLEMENTED` for the version the module tries first, the module registers through another version it supports, or stays closed and retries | CORE-3, I-3, section 4.6 | Designed |
| S-17 Stale renewals, a minute old, a minute in the future or without the core's time, renew nothing: the lease runs out, with `gate.lease_expired` no later than the TTL plus 1 second after the last fresh renewal, and a fresh renewal renews it again | EP-3, section 5.3 | Implemented |
| S-18 A report makes nothing usable | CORE-10, EP-16 | Designed |
| S-19 Unknown, discovered, disabled and blocked tooling is denied with its reason, before policies | EP-16 | Designed |
| S-20 A block denies within the halt propagation target, timed as section 9.2 says, without a new bundle, and is acknowledged once applied. The result of a call in flight when it arrives does not reach the agent, where the module evaluates `tool.result`, and a snapshot that no longer carries the block lifts it | EP-15, CORE-12 | Designed |
| S-21 A tool whose definition changed is denied and not exposed | EP-16, EP-17 | Designed |
| S-22 Only exposed tools reach the model; a provider-run tool that cannot be removed fails the model call | EP-17, EP-18 | Designed |
| S-23 Arguments follow the vectors | EP-19 | Designed |
| S-24 Reports carry no secrets | EP-13, EP-14 | Designed |
| S-25 An enforcement point puts in the subject of its decisions the environment its registration returned, which the fake core sets. The kit runs it once with each environment, `production` and `non_production`. With no environment, or one the module does not know, the module allows nothing | I-7 | Designed |
| S-26 The module calls only a core whose certificate chains to the trust anchors from its configuration. The fake core first serves a certificate that does not chain to the anchor in `WT_CONFORMANCE_CA_FILE`, then one that does: a call made while it serves the first, or no registration once it serves the second, fails the module. An enforcement point inside an agent authenticates as that agent and serves it only. A call without a token that the fake token endpoint issued to that agent, or one that concerns a second agent that the kit adds to the state, fails the module. The fake core then serves a certificate that chains to the anchor but is not valid for the host of `WT_CONFORMANCE_CORE_URL`: a call made while it serves it fails the module | I-1, EP-11 | Designed |
| S-27 The module registers before any other call, and again after the driver restarts it: a call before a registration fails it. The kit's tokens expire within a minute, and the fake core ends each stream when its token expires (CORE-1). The kit reports whether the module follows two recommendations, and fails it on neither. One is to deregister before the restart. The other is to open a replacement stream with a fresh token before the old token expires, resuming from the last version applied, and close the old stream once the new one has delivered a message at or above that version. An enforcement point that deregisters closes its gate first: a call it allows after its deregistration fails it. While the module rolls its token over, the fake core also plays two replicas one read apart, in both orders: a module whose gate reopens after a halt, or whose state acknowledgement goes backwards, fails. The driver starts a second process of the module, and the two must register with different keys; after the restart, the kit reports a module whose key changed, without failing it | I-2, I-5, I-8, section 5.2 | Designed |
| S-28 The module sends heartbeats at the interval the core sets. The fake core sets a short interval at registration and a shorter one in a heartbeat response: a heartbeat that comes later than the interval in force, plus a tolerance, fails the module. While the kit changes the agent's state for more than a minute, an enforcement point acknowledges the state version it applied at least every 60 seconds: a longer gap, or a version above the last one the kit sent, fails it | I-6, EP-12 | Designed |
| S-29 A runtime-control module applies its layer to every halted agent in scope, and emits its events, valid against the catalog, when it applies or lifts the layer. With three agents in scope, each running a workload, the kit halts the first with an agent halt, the second with a selector halt, then all three with a fleet halt. It has the driver start a workload for a halted agent after its halt, then releases every halt. A workload of a halted agent left uncovered beyond a tolerance, a layer applied or lifted without its event, or an isolated workload that cannot reach the core's machine listener and token endpoint, fails the module | RC-1, RC-5, RC-7 | Designed |
| S-30 Values out of range never open anything. The fake core sends a lease TTL of an hour, which lasts 300 seconds; a zero and an absent one, which renew nothing; a snapshot whose first part lacks the fleet state, which the module refuses, keeping its state and reconnecting; heartbeat responses without an interval or with zero, after which the module keeps the interval in force; and a state that stops naming a bundle, which closes the gate with `gate.no_bundle` | I-6, EP-7, sections 5.2 and 5.3 | Designed |
| S-31 The module gets its tokens as section 4.2 says, from the kit's fake token endpoint: it reads the issuer's metadata and refuses metadata with another issuer, sends the client ID of its identity and an assertion whose `aud` is the issuer identifier alone, and asks for the module API's resource. When the endpoint refuses an assertion with a 400, the module logs the error and retries at the cap of I-4; when it answers 503, the module retries with the backoff of section 4.7 | I-10 | Designed |
| S-32 Provider-run tools follow EP-18, with a model provider that the kit plays. Declared remote servers reach the provider narrowed to the tools enabled for the agent, and a request that would let it call another tool is denied. The calls it submits for approval are decided as `tool.invoke`, with their arguments, and answered with the decision, and a tool that a usage rule names is offered only while its calls are submitted. The calls its responses report yield `action.executed` with origin `provider`, and a response that lists a tool whose definition changed stops the tool's exposure | EP-17, EP-18 | Designed |

S-18 to S-24 and S-32 come from [RFC-0002](../rfcs/0002-mcp-servers-tools-and-models.md); S-25 to S-31 were numbered while it was a draft.

## 10. Versioning and compatibility

- **Identifiers.** The contract version is `v1alpha1`, then `v1beta1`, then `v1`. It is the protobuf package and the manifest's `apiVersion`. Event types carry their own version (`.v1`), and so do the bundle format (`whitetower.bundle.v1`), the catalog file (`whitetower.catalog.v1`) and the combining algorithm (`wt-deny-overrides-v1`).
- **A published version never changes incompatibly.** A breaking change creates the next version (for example `v1alpha2`), which the core serves next to the previous one:
  - alpha: at least one minor release of the core with both versions;
  - beta: two minor releases or six months, whichever is longer;
  - `v1`: twelve months.
- **Additive changes stay in the version:** new fields, enum values, methods, event types and optional event data. What a reader does with what it does not know depends on the document:
  - **Open documents:** protobuf messages, in both encodings, and the extension attributes of CloudEvents. Readers ignore unknown fields. A JSON decoder discards unknown fields and unknown enum names, and a discarded enum reads as its `UNSPECIFIED` value, with that value's stated meaning (EP-10).
  - **Closed documents:** each JSON document with a schema, whose reader refuses what it does not know. Event data, event types and the module manifest are read by the core, which gets a change first: a module sends one only to a core that has it, so a module's release is never newer than its core's (the compatibility matrix below). The bundle manifest gains a member only as `whitetower.bundle.v2`, or in a new contract version, since V4 refuses unknown members, and the catalog file only as `whitetower.catalog.v2`, since V7 parses it against its schema. In the decision documents, an unknown member or value denies. A value that the core sends and a module repeats in its events, such as a halt's scope, needs a fallback in the event's schema before its enumeration grows.
- **Additive changes only fail closed.** A new field, record or value may add a restriction, or narrow a halt, within the version only if an instance that ignores it denies or halts more (section 5.1); a change that would make such an instance allow or halt less is a breaking change. So is a new enum value whose fail-closed meaning would stop the instances that do not know it, such as an environment, a lifecycle state that opens the gate, or a kind of block, which denies every tool and model call where it is unknown (EP-15). The blocks record is such a record too: an enforcement point that ignored it would allow what blocks deny (section 5.10). A method added within a version is optional for modules.
- **An event type changes incompatibly only as a new type** (`.v2`); emitters may send both during a migration.
- **Every change to `api/proto`, `api/events`, `api/manifest` or `api/policy`, or to what a conformance vector expects, needs an RFC** (GOVERNANCE.md). A new vector for a rule this specification already states needs none.
- **Draft until tagged.** `v1alpha1` is a draft until RFC-0001 is accepted and `contracts/v0.1.0` is tagged. CI compares the protobuf files with the latest `contracts/v*` tag (`buf breaking`, FILE rules), so changes during the review are free and changes after it are checked.
- **Compatibility matrix.** Each release documents, for the core and for each module, the contract versions supported:

  | Core | Contract versions | ep-python | k8s-quarantine | mock-module |
  | --- | --- | --- | --- | --- |
  | 0.1.x | v1alpha1 | 0.1.x | 0.1.x | 0.1.x |

## 11. Security considerations

| Threat | What the contracts do |
| --- | --- |
| A compromised enforcement point lies in its acknowledgements or evidence | Layers are reported separately and never overstate (section 5.5); halts also stop token issuance for every audience but the module API (CORE-8); network quarantine acts outside the agent's process (RC-1); the console flags instances that keep emitting actions after a halt (P1-08) |
| Stolen agent credentials | The thief can act only as that agent: its scope is one agent, its state carries no personal data (CORE-9), its halts stop token issuance for every audience but the module API, and revoking the credential stops new tokens for the module API too. Tokens already issued stay valid until they expire, as at every audience ([ADR-0010](../adr/0010-built-in-agent-token-issuer.md)), so the credential's instances stop within a token's remaining lifetime plus the lease TTL |
| A forged or tampered bundle | Signed with a key from the enforcement point's configuration (section 7.3), bound to the state's hash, verified step by step (section 7.4) |
| Replaying an older bundle | Versions only grow, also after a restore or a failover (CORE-18), and the state names the one to use (V3, V6) |
| Impersonating the core | TLS with trust anchors from configuration, and a certificate valid for the host of the core's configured URL, also when the instance dials an address it kept (I-1) |
| A stolen bundle key | Removing it from each enforcement point's configuration revokes it, and an enforcement point verifies its active bundle again whenever its keys change (section 7.3). Using the key also needs a way to deliver bundles |
| Cutting enforcement points off the core | They fail closed when their lease expires (section 5.3): an attacker can stop agents, never free them. This trade-off is accepted in ADR-0005 |
| Holding the stream back, so that renewals keep leases alive while halts arrive late | Renewals carry the core's time, and an instance ignores one more than its tolerance before or after its own clock (section 5.3): past the tolerance, leases run out |
| A stale replica, or the second stream of a token rollover, undoing a halt | The core never sends state older than the client's (CORE-5), and renewals mean "current" (CORE-6); an instance never lowers the version it applied, whichever stream or replica a message comes from (section 5.2) |
| An instance claims a version the core never issued, to raise false alerts of lost changes or to load the halt path | The core answers with a snapshot (CORE-5) and takes the claim as no evidence of lost changes; a claim far beyond its latest version is refused |
| An enforcement point deregisters and keeps acting on its lease | It closes its gate first (I-5); without a stream, its lease runs out within its TTL |
| Flooding the audit log | Rate limits, the limits of section 4.8, and publication restricted to declared types and owned sources (section 4.3) |
| An agent's tooling reports mislead reviewers or flood the catalog | Reports never authorize (CORE-10); limits, a rate limit, and a bound on what waits for review (CORE-13) |
| A tool's description changes after approval, to steer the model | Approval pins the definition's hash; a changed definition is denied and never offered to the model (EP-16, EP-17) |
| Secrets in reported URLs and command lines | Redaction by the enforcement point and again by the core, with the deployment's rules (EP-14, CORE-11) |
| Arguments written to slip past a usage rule | Transforms that refuse what parsers read differently, and path rules used as allow-lists (section 6.11) |
| The model provider runs tools outside the agent | Exposure decided before every model call, declarations narrowed, calls submitted for approval (EP-17, EP-18) |
| Blocks slow halts down | Blocks travel in their own record, never in the fleet record, at most 500 (section 5.10) |
| Personal data leaking into evidence | Minimization rules of section 8.3 |
| Unknown values opening the gate | EP-10 |

The [threat model](../security/threat-model.md) (plan P0-04) analyzes these boundaries in depth.

## 12. Open questions for the review

| Question | Proposal |
| --- | --- |
| Should enforcement points learn rotated bundle keys from the core? | Not in `v1alpha1`: keys come from configuration. If enforcement points learn keys from the core in `v1beta1`, a new key is never trusted on the word of the online key alone: it needs an offline root, with a threshold and an expiry, as in TUF, or a hold-down period, as in RFC 5011 |
| Stable URLs for `dataschema`, and the Kubernetes label prefix | Wait for a domain of the project's own, which question Q6 decided on 2026-09-30 it does not have for now |
| What must decision points settle before `v1beta1`? | Where a decision point gets its bundles, and how it is bound to the enforcement points it serves; how they authenticate to it; the reasons for an answer other than 200 and for one outside the response schema; and its scenarios |
| What must a Rego mapping settle before Phase 2? | One package per file, named by the policy's ID and checked at V7; a `deny` that is defined and not `false` forbids; strict errors from built-in functions; a rule for writing policies about missing members; the response checked against its schema; one bundle per evaluation; the version of Rego's syntax; and Rego vectors on both reference stacks |
| Do the rules of the blocks record, and EP-15's acknowledgement, hold with real enforcement points? | A live test with several enforcement points in a real environment, the end-to-end test of plan P1-09 (its step 14), confirms them; its findings go to the review that precedes `v1beta1` (section 5.10) |

## Appendix A. JSON examples

Examples use the Connect protocol (version 1) with JSON. Field names are the protobuf JSON names, 64-bit integers are strings, durations are strings such as `"30s"`, and enumerations are their names. Every call carries `Authorization: Bearer <token>`. A unary call is a `POST` with `Content-Type: application/json` and its message as the body; a method without side effects may also be called with `GET`. `Watch`, a server stream, is a `POST` over HTTP/2 with `Content-Type: application/connect+json`: its request and each of its messages travel in an envelope, a flags byte and a four-byte length before each JSON message, and the stream ends with an end-of-stream envelope that carries the error, if any, and the trailers, under HTTP status 200. The examples show each message without its envelope. The Connect wire writes the codes of section 4.6 in lower snake case, such as `permission_denied`. The examples of `ReportTooling`, `ReportDefinitions` and the blocks record follow their protobuf (plan P0-03, step 12).

**`RegistryService.RegisterInstance`**, `POST /whitetower.module.v1alpha1.RegistryService/RegisterInstance`

```json
{
  "module": "ep-python",
  "manifestSha256": "9f2c4be1d0a8f3e6c7b5a4d3e2f1c0b9a8d7e6f5c4b3a2918f7e6d5c4b3a2f10",
  "moduleVersion": "0.1.0",
  "instanceKey": "5b0e3c8a-2f71-4d96-a3b4-9c1e7f20d815",
  "contractVersions": ["v1alpha1"],
  "agentIds": ["0192f1c2-7a3b-7c4d-8e5f-000000000001"],
  "info": { "host": "invoice-triage-7d9f-2", "components": { "python": "3.13.1", "langgraph": "1.2.0" } }
}
```

```json
{ "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051", "contractVersion": "v1alpha1", "heartbeatInterval": "30s", "environment": "ENVIRONMENT_PRODUCTION" }
```

**`RegistryService.Heartbeat`**

```json
{ "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051", "health": "HEALTH_HEALTHY" }
```

```json
{ "heartbeatInterval": "30s" }
```

**`RegistryService.DeregisterInstance`**

```json
{ "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051", "reason": "rolling update" }
```

```json
{}
```

**`GovernanceService.Watch`** is a server stream. The request:

```json
{ "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051", "sinceVersion": "0" }
```

Then the stream's messages, in order: a snapshot in one part, a renewal, and a halt.

```json
{
  "version": "918",
  "snapshotPart": {
    "first": true,
    "last": true,
    "fleet": { "version": "12" },
    "agents": [{
      "agentId": "0192f1c2-7a3b-7c4d-8e5f-000000000001",
      "version": "915",
      "slug": "invoice-triage",
      "lifecycleState": "LIFECYCLE_STATE_ACTIVE",
      "bundle": { "version": "42", "manifestSha256": "d330970434583a6fe6908fb8a6111422c0fc01c789581480af3c43c6632a625e", "sizeBytes": "4241" },
      "leaseTtl": "30s",
      "haltMode": "HALT_MODE_INTERRUPT",
      "attributes": {
        "kind": "in_house", "riskTier": "high", "dataCategories": ["customer data"],
        "labels": { "team": "finance" }, "ownerId": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"
      }
    }]
  }
}
```

```json
{ "version": "918", "leaseRenewal": { "serverTime": "2026-09-29T10:15:02.118Z" } }
```

```json
{
  "version": "920",
  "change": {
    "agents": [{
      "agentId": "0192f1c2-7a3b-7c4d-8e5f-000000000001",
      "version": "920",
      "slug": "invoice-triage",
      "lifecycleState": "LIFECYCLE_STATE_SUSPENDED",
      "halts": [{ "haltId": "0192f1c3-0d4e-7a10-9b2c-000000000040", "scope": "HALT_SCOPE_AGENT", "issuedAt": "2026-09-29T10:16:40.502Z" }],
      "bundle": { "version": "42", "manifestSha256": "d330970434583a6fe6908fb8a6111422c0fc01c789581480af3c43c6632a625e", "sizeBytes": "4241" },
      "leaseTtl": "30s",
      "haltMode": "HALT_MODE_INTERRUPT",
      "attributes": { "kind": "in_house", "riskTier": "high", "dataCategories": ["customer data"], "labels": { "team": "finance" }, "ownerId": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1" }
    }]
  }
}
```

When the token that opened the stream expires (CORE-1), the stream ends with this end-of-stream message:

```json
{ "error": { "code": "unauthenticated", "message": "token expired" } }
```

**`GovernanceService.Acknowledge`**: the gate at once, then the interruption's outcome.

```json
{
  "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051",
  "acknowledgements": [{
    "acknowledgementId": "5b1f7c2e-4a3d-4e8f-9b6a-2c1d0e9f8a7b",
    "agentId": "0192f1c2-7a3b-7c4d-8e5f-000000000001",
    "halt": {
      "haltId": "0192f1c3-0d4e-7a10-9b2c-000000000040",
      "layers": [{ "layer": "HALT_LAYER_GATE_CLOSED", "outcome": "LAYER_OUTCOME_DONE", "afterReceipt": "0.000012s", "observedAt": "2026-09-29T10:16:40.611Z" }]
    }
  }]
}
```

```json
{
  "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051",
  "acknowledgements": [{
    "acknowledgementId": "8c2e1d4f-6b5a-4c3d-8e2f-1a0b9c8d7e6f",
    "agentId": "0192f1c2-7a3b-7c4d-8e5f-000000000001",
    "halt": {
      "haltId": "0192f1c3-0d4e-7a10-9b2c-000000000040",
      "layers": [
        { "layer": "HALT_LAYER_IN_FLIGHT_INTERRUPTED", "outcome": "LAYER_OUTCOME_NOT_DONE", "afterReceipt": "10s", "detail": "blocking tool still running" },
        { "layer": "HALT_LAYER_PROCESS_TERMINATED", "outcome": "LAYER_OUTCOME_NOT_APPLICABLE", "afterReceipt": "10s", "detail": "halt mode interrupt" }
      ]
    }
  }]
}
```

The response is `{}`. A network quarantine module reports `HALT_LAYER_NETWORK_QUARANTINED` with `"workloads": 3`; a bundle acknowledgement carries `"bundle": { "version": "42", "manifestSha256": "…", "outcome": "BUNDLE_OUTCOME_ACTIVATED" }`; a state acknowledgement carries `"state": { "version": "920" }`.

**`PolicyService.GetBundle`**, which also accepts GET because it has no side effects:

```json
{ "agentId": "0192f1c2-7a3b-7c4d-8e5f-000000000001", "version": "42" }
```

```json
{
  "bundle": {
    "manifest": "eyJhZ2VudF9pZCI6IjAxOTJmMWMyLTdhM2ItN2M0ZC04ZTVmLTAwMDAwMDAwMDAwMSIs…",
    "signature": "eyJhbGciOiJFZERTQSIsImtpZCI6Img4OE1LRjRYdGk5eDhEaW9raUp1S0xPcHMtbXMxZldPVUw4ZVpVTTVaSFEiLCJ0eXAiOiJ3aGl0ZXRvd2VyLWJ1bmRsZStqd3MifQ..mxj9S_TCa7sOIWNrMOhkNgqZegtb8ssrNOsV7_Mnhnrnkz8g-XB2Hup0SKbnoXJ4aQtnNqjIbrJ1K_PgCGHACA",
    "files": [
      { "path": "policies/agent/0192f1c2-7a3b-7c4d-8e5f-000000000202.cedar", "content": "QGlkKCJpbnZvaWNlLXRyaWFnZS10b29scyIp…" }
    ]
  }
}
```

**`PolicyService.GetBundleKeys`**

```json
{}
```

```json
{ "keys": [{ "keyId": "h88MKF4Xti9x8DiokiJuKLOps-ms1fWOUL8eZUM5ZHQ", "algorithm": "EdDSA", "publicKey": "…", "status": "BUNDLE_KEY_STATUS_ACTIVE" }] }
```

**`EventService.Publish`**, with each event's JSON as base64 bytes:

```json
{ "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051", "events": ["eyJzcGVjdmVyc2lvbiI6IjEuMCIsImlkIjoiMDE5MmYxZDAt…"] }
```

```json
{ "results": [{ "status": "EVENT_STATUS_ACCEPTED" }] }
```

**`MetaService.GetServerInfo`**

```json
{}
```

```json
{ "version": "0.1.0", "contractVersions": ["v1alpha1"] }
```

## Appendix B. Requirements covered

| Requirement | Where |
| --- | --- |
| MOD-01 manifest and schema | Section 3 |
| MOD-02 approval, heartbeats, health | Sections 3.2 and 4.9 |
| MOD-03 versions, negotiation, breaking-change checks, RFCs | Sections 4.5 and 10 |
| MOD-04 watch stream with leases | Section 5 |
| MOD-05 conformance kit | Section 9 |
| MOD-08 replacing a module without changing the core | The whole contract; engine mappings in [engine-mappings.md](engine-mappings.md) |
| POL-03 combination semantics | Section 6.5 |
| POL-05 signed, versioned bundles and drift | Sections 7 and 5.7 (EP-7, EP-12) |
| POL-06 decision input model | Section 6 |
| KIL-01 to KIL-04, KIL-07, KIL-10 | Sections 5.1 and 5.3 to 5.8 |
| AUD-02 idempotent ingestion, sequences, gaps | Section 8.4 |
| NFR-20 privacy | Section 8.3 and CORE-9 |
| CAT-01 tooling reports, CAT-10 no secrets in them | Section 4.10 |
| CAT-04 organization-wide blocks, and NFR-24, their propagation | Section 5.10 and scenario S-20 |
| CAT-05 catalog check, CAT-06 usage rules, CAT-07 provider-run tools | Sections 6.9 to 6.11 and 7.7 |
