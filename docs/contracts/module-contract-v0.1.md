# Module contracts v0.1

| | |
| --- | --- |
| **Status** | Draft for review in [RFC-0001](../rfcs/0001-module-contracts-v0.1.md). Contract version `v1alpha1` |
| **Date** | 2026-09-29; updated 2026-09-30 (fresh lease renewals, from the [threat model](../security/threat-model.md)) and 2026-10-02 (how message sizes are measured, from P1-01) |
| **Plan** | [P0-03](../plans/phase-0/P0-03-module-contracts.md) |
| **Machine-readable parts** | [`api/proto/whitetower/module/v1alpha1/`](../../api/proto/whitetower/module/v1alpha1/), [`api/manifest/`](../../api/manifest/README.md), [`api/events/`](../../api/events/README.md), [`api/policy/`](../../api/policy/README.md) |
| **Conformance** | [`test/conformance/`](../../test/conformance/README.md) |
| **Related** | [ADR-0004](../adr/0004-api-and-contract-formats.md), [ADR-0005](../adr/0005-edge-enforcement-with-leases.md), [ADR-0006](../adr/0006-tamper-evident-audit-log.md), [ADR-0011](../adr/0011-own-python-enforcement-point.md), [domain model](../architecture/domain-model.md), [lifecycle](../architecture/lifecycle.md) |

These contracts let any product be wrapped as a White Tower module: an enforcement point inside an agent, a gateway, a policy engine or a component that isolates workloads. A module that follows them can replace another without any change to the core (MOD-08).

The contracts have six parts: the capability taxonomy (section 2), the module manifest (3), the module API (4), the governance state with its leases and halts (5), the decision profile (6), the policy bundle format (7) and the event catalog (8). Section 9 describes how conformance is checked, section 10 how the contracts evolve, and section 11 what they protect against.

---

## 1. Conventions

- **Keywords.** MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in capitals.
- **Obligations are numbered**, so tests and reviews can name them: `I-n` for every module instance, `EP-n` for enforcement points, `RC-n` for runtime-control modules, `MAN-n` for how the core handles manifests, and `CORE-n` for what the core guarantees in return. The obligations of modules each have a conformance scenario (section 9.3).
- **Formats.** JSON is UTF-8. Timestamps are RFC 3339, in UTC, with milliseconds (`2026-09-29T10:15:02.118Z`). Identifiers are lowercase UUIDs (UUIDv7 when White Tower creates them). Hashes are lowercase hexadecimal SHA-256.
- **Terms** are those of the [domain model](../architecture/domain-model.md#2-glossary).
- **The machine-readable files are normative for syntax, and this document for behavior.** A disagreement between them is a bug in the contract. Until it is fixed, implementations follow whichever reading denies more.

## 2. Capabilities

A module declares one or more capabilities in its manifest. Four are specified in `v1alpha1`; eight more are reserved, so later phases can specify them without renaming anything.

| Capability | Status in `v1alpha1` | What the core expects from it | Module API it uses | Events it emits |
| --- | --- | --- | --- | --- |
| `enforcement-point` | Specified | Applies governance to the agents it serves at runtime: a gate before every governed call, policy decisions, halts, evidence | All services | Decisions, actions, halts, bundles, leases |
| `policy-engine` | Specified | Evaluates decision requests with the profile and the combining algorithm of section 6. Embedded in an enforcement point, or a decision point that others call through AuthZEN | None when embedded | None of its own |
| `runtime-control` | Specified | Acts on halts outside the agents' processes, for example the network quarantine of KIL-10. Evaluates no policy | Registry, `Watch`, `Acknowledge`, `Publish` | Quarantine events, leases |
| `event-source` | Specified | Publishes the event types its manifest declares | Registry, `Publish` | Those it declares |
| `mcp-gateway` | Reserved, Phase 2 | An enforcement point for tool calls through MCP | | |
| `llm-gateway` | Reserved, Phase 2 | An enforcement point for model calls, with quotas and cost | | |
| `skills-repository` | Reserved, Phase 2 | Reviewed, signed skills for agents | | |
| `harness` | Reserved, Phase 2 | Enforced execution environments; stopping workloads on a halt | | |
| `observability` | Reserved, Phase 2 | Consumes events for dashboards and analytics | | |
| `identity-source` | Reserved, Phase 2 | External issuers of agent identities | | |
| `compliance` | Reserved, Phase 3 | Evidence packages and GRC export | | |
| `discovery` | Reserved, Phase 3 | Finds agents that are not in the inventory | | |

The charter's eight module types all have a place: the policy engine is `policy-engine`; the MCP and LLM gateways are `mcp-gateway` and `llm-gateway`, and will also declare `enforcement-point`; the skills repository, observability, compliance and discovery have their own names; the harness or sandbox is `harness`, and will also declare `runtime-control`.

## 3. Module manifest

### 3.1 Format

A manifest is a YAML or JSON document with `apiVersion: whitetower/v1alpha1` and `kind: ModuleManifest`, validated by [`module-manifest.schema.json`](../../api/manifest/module-manifest.schema.json). [Examples](../../api/manifest/examples/) exist for the mock module, the Python enforcement point and the network quarantine module.

| Field | Meaning |
| --- | --- |
| `metadata.name` | The module's slug, unique in a deployment |
| `metadata.version`, `vendor`, `license`, `homepage`, `description`, `displayName` | What the console shows; the version is SemVer 2.0 and the license an SPDX expression |
| `spec.contractVersions` | Contract versions the module implements |
| `spec.identity` | `agent`: instances run inside an agent's process and authenticate as that agent. `module`: instances authenticate with the module's own identity |
| `spec.agents` | Which agents instances serve: `self` (the agent they run in), `bound` (agents an operator binds to the module), `all` (every agent, through one binding to all agents) |
| `spec.capabilities` | The capabilities, each with its own settings: intervention points, halt modes and layers for an enforcement point; languages and combining algorithms for a policy engine; layers and platforms for runtime control |
| `spec.events.emits`, `spec.events.consumes` | Event types the module publishes, and consumes (always empty in `v1alpha1`) |
| `spec.permissions` | What instances may do through the module API (section 3.3) |
| `spec.endpoints` | Endpoints others may call, such as an AuthZEN decision point (section 6.8). None are required in `v1alpha1` |
| `spec.configSchema` | A JSON Schema of the module's own configuration |

### 3.2 Registration and approval

An operator registers a manifest and another step approves it (MOD-02). The core stores the manifest and the SHA-256 of its RFC 8785 canonical JSON. Instances present that hash when they register.

- **MAN-1.** The core MUST refuse a manifest that does not validate against the schema, which includes one that declares a reserved capability.
- **MAN-2.** The core MUST refuse the registration of an instance whose module is not approved, or whose `manifest_sha256` differs from the approved manifest's.
- **MAN-3.** Any change to an approved manifest MUST be approved again before instances that run it can register.
- **MAN-4.** Revoking a module MUST end its instances' streams and refuse their calls from then on.

### 3.3 Permissions

| Permission | Allows |
| --- | --- |
| `governance.watch` | `Watch` for the agents in the instance's scope |
| `governance.acknowledge` | `Acknowledge` for the agents in the instance's scope |
| `policy.bundles.read` | `GetBundle` for the agents in the instance's scope, and `GetBundleKeys` |
| `events.publish` | `Publish` for the types in `spec.events.emits` |

An enforcement point needs all four; a runtime-control module needs `governance.watch` and `governance.acknowledge`; an event source needs `events.publish`. The schema enforces these combinations.

## 4. Module API

### 4.1 Transport

- The module API is served by the core's machine listener with **ConnectRPC**. The Connect, gRPC and gRPC-Web protocols are equivalent; messages may be binary protobuf or JSON. The definitions are in [`api/proto/whitetower/module/v1alpha1/`](../../api/proto/whitetower/module/v1alpha1/).
- The listener uses TLS 1.2 or later (1.3 preferred) and HTTP/2, which `Watch` needs. Mutual TLS is optional.
- **I-1.** An instance MUST verify the core's certificate against trust anchors from its configuration.

### 4.2 Authentication

- Every call carries `Authorization: Bearer <access token>`. Tokens come from the core's token endpoint (`/oauth2/token`): the client credentials grant with `private_key_jwt` client authentication (RFC 7523), for the module API as audience (resource indicator, RFC 8707). They are JWTs (RFC 9068) valid for 5 minutes by default and 15 at most ([ADR-0010](../adr/0010-built-in-agent-token-issuer.md)).
- **Identities.** An enforcement point that runs inside an agent's process (`identity: agent`) authenticates **as that agent** (`spiffe://<trust-domain>/agent/<agent-id>`). Any other instance authenticates as its module (`spiffe://<trust-domain>/module/<module-id>`).
- **CORE-1.** The core MUST end a `Watch` stream, with `UNAUTHENTICATED`, no later than the expiry of the token that opened it.
- **I-2.** An instance SHOULD open a replacement stream with a fresh token before its token expires, resuming from the last version it applied, and only then close the old stream.

### 4.3 Authorization

An instance's **scope** is the set of agents it may act on: its own agent for `identity: agent`, and otherwise the agents bound to its module (every agent, for a binding to all agents).

| Method | Enforcement point inside an agent | Other module instances |
| --- | --- | --- |
| `RegistryService.*` | Its own instance | Their own instances |
| `GovernanceService.Watch` | Its agent | Their scope |
| `GovernanceService.Acknowledge` | Its agent | Their scope |
| `PolicyService.GetBundle` | Its agent's bundles | Bundles of agents in their scope, with `policy.bundles.read` |
| `PolicyService.GetBundleKeys` | Yes | With `policy.bundles.read` |
| `EventService.Publish` | Types in `emits`, from a source under `/agents/<its agent>/ep/`, about its agent | Types in `emits`, from a source under `/modules/<module>/`, about agents in their scope |
| `MetaService.GetServerInfo` | Yes | Yes |

- **CORE-2.** The core MUST answer `PERMISSION_DENIED` to any call outside these rules, and MUST check them on every call, not only at registration.

### 4.4 Services

| Method | Purpose | Idempotency |
| --- | --- | --- |
| `RegistryService.RegisterInstance` | Announce an instance: module, manifest hash, version, instance key, supported contract versions, agents served. Registering again with the same key updates the instance | Idempotent |
| `RegistryService.Heartbeat` | Report health, and the set of agents served when it changed | Idempotent |
| `RegistryService.DeregisterInstance` | Leave cleanly, so the instance shows as disconnected rather than lost | Idempotent |
| `GovernanceService.Watch` | Stream the governance state of the instance's scope (section 5) | Server stream |
| `GovernanceService.Acknowledge` | Report halt layers, bundle activations and the state version applied | Idempotent through `acknowledgement_id` |
| `PolicyService.GetBundle` | Download one version of an agent's bundle (section 7) | No side effects |
| `PolicyService.GetBundleKeys` | List the bundle signing keys: active, next and retired | No side effects |
| `EventService.Publish` | Deliver a batch of events (section 8) | Idempotent through each event's source and ID |
| `MetaService.GetServerInfo` | The core's version and the contract versions it supports | No side effects |

JSON examples of every method are in appendix A.

### 4.5 Version negotiation

- The protobuf package carries the contract version: `whitetower.module.v1alpha1`.
- **CORE-3.** `RegisterInstance` MUST select the highest version that both sides support and return it. With no common version, the core MUST answer `FAILED_PRECONDITION`, listing the versions it supports.
- **I-3.** An instance MUST use only the selected version for the rest of its session.

### 4.6 Errors

| Code | Meaning | What the client does |
| --- | --- | --- |
| `UNAUTHENTICATED` | Token missing, expired or invalid | Get a new token, then retry |
| `PERMISSION_DENIED` | Outside the instance's scope or permissions; module not approved or revoked | Do not retry until the configuration changes; stay closed |
| `INVALID_ARGUMENT` | Malformed request | Do not retry the same request |
| `FAILED_PRECONDITION` | No common contract version; manifest hash mismatch; instance not registered | Fix the cause (for example register again), then retry |
| `NOT_FOUND` | Unknown bundle version | Wait for the next state; do not retry the same version |
| `RESOURCE_EXHAUSTED` | Rate limit or backpressure; or a message over the limits of section 4.8 | Retry with backoff, but never a message over the limits as it is |
| `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `ABORTED` | Transient | Retry with backoff |
| `INTERNAL`, `UNKNOWN` | Server error | Retry with backoff |

### 4.7 Retries and backoff

- **I-4.** Instances MUST retry with exponential backoff and full jitter. The backoff's cap MUST NOT exceed 30 seconds, nor a third of the shortest lease TTL the instance holds, so that once the core returns every instance is back within one renewal interval. The backoff MUST return to its first step once a session has received a lease renewal. The first wait SHOULD be a random duration up to 0.5 seconds, each later cap doubling. (Spike S2: with a 30-second cap, a five-second outage of the whole core left 6 to 8% of 1,000 enforcement points failed closed; with this rule, none.)
- Retrying is always safe: acknowledgements carry an `acknowledgement_id` chosen by the instance, and events are de-duplicated on their source and ID.

### 4.8 Limits

A message's size is that of its encoding in the call, binary protobuf or JSON, once decompressed: a client that compresses its messages, or accepts compressed ones, gains no room. The core refuses a larger request with `RESOURCE_EXHAUSTED`, and never sends a larger message.

| Limit | `v1alpha1` |
| --- | --- |
| Size of a request or response message | 4 MiB |
| Size of a `Watch` message | 1 MiB; the core splits larger snapshots into parts |
| Acknowledgements per request | 100 |
| Events per `Publish` | 500, and 4 MiB in total |
| Size of one event | 64 KiB |
| Size of a bundle | 2 MiB, at most 1,000 files |
| Heartbeat interval | Set by the core, 30 seconds by default |
| Lease TTL | 10 to 300 seconds, per agent |
| Lease renewal interval | A third of the shortest TTL in scope, and at most 30 seconds |
| Age of a lease renewal when it arrives | At most 5 seconds by default, on the instance's clock; an instance may configure another tolerance |

### 4.9 Instances

- **I-5.** An instance MUST register before any other call, and SHOULD deregister when it stops on purpose.
- **I-6.** An instance MUST send heartbeats at the interval the core sets. A runtime-control instance reports as served agents those that have workloads it controls.
- **CORE-4.** The core MUST show an instance as lost once it has sent no heartbeat and held no stream for longer than its lease TTL, and MUST count it in the status of the halts it had to acknowledge.

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

### 5.2 The watch stream

- **CORE-5.** When `since_version` is 0, or when the core cannot send every change since it, the core MUST start with a snapshot. It MAY send a snapshot at any time, and MUST NOT send a snapshot or a change older than `since_version`.
- A **snapshot** is one or more `SnapshotPart` messages with the same version: the first has `first` set and carries the fleet state, the last has `last` set. Agents missing from a snapshot are out of scope.
- **Changes** follow in strictly increasing version order. Each carries the complete new state of every agent that changed or entered the scope, the new fleet state when it changed, and the agents that left the scope.
- **CORE-6.** The core MUST send a `LeaseRenewal` right after each complete snapshot, then at least at the renewal interval of section 4.8, and only when it has sent every change it knows of. A renewal therefore always means "your state is current". Every renewal carries `server_time`, the core's clock when it sends it (section 5.3).
- **CORE-7.** The core MUST end a stream it cannot keep up to date, for example a client too slow to read, rather than let it fall behind. The client's lease then expires if it cannot reconnect.

### 5.3 Leases

- A renewal renews the lease of every agent in scope. Each lease then lasts that agent's `lease_ttl`, measured on the client's **monotonic clock** from the moment it received the renewal.
- **Only a fresh renewal counts.** An instance ignores a renewal without `server_time`, or whose `server_time` is older than a tolerance on its own clock: 5 seconds by default (section 4.8). Such a renewal renews nothing, and while an instance receives only those, it SHOULD report `HEALTH_DEGRADED` in its heartbeats. Something on the path that holds the stream back can then delay it by the tolerance at most: beyond that, leases run out and the gate closes, instead of halts arriving late ([threat model](../security/threat-model.md), T-32). The check relies on synchronized clocks (ASM-04), as token expiry does; the lease itself is still measured on the monotonic clock.
- There is no lease before the first renewal of a session. An agent that enters the scope through a change gets its lease from the next renewal; the core SHOULD send one right after such a change.
- **When a lease expires, the agent is treated as halted**: the enforcement point denies everything and applies the agent's halt mode (KIL-04), and emits `whitetower.lease.expired.v1`. It opens again when it has a current state and a new lease.

### 5.4 The gate

An enforcement point checks its gate before every governed call and interaction, then evaluates policies (section 6). The gate is closed, with the first reason that applies in this order:

| Order | Condition | Reason |
| --- | --- | --- |
| 1 | No complete snapshot applied since the instance started | `gate.no_state` |
| 2 | The agent's lease has expired, or it never had one | `gate.lease_expired` |
| 3 | An agent or selector halt covers the agent | `gate.halted` |
| 4 | A fleet halt is active | `gate.fleet_halted` |
| 5 | The lifecycle state is not `validated`, `ready` or `active`, including unknown values | `gate.lifecycle` |
| 6 | No verified bundle is active for the agent | `gate.no_bundle` |
| 7 | The evidence buffer cannot accept another event | `gate.evidence_full` |

The [fail-closed vectors](../../test/conformance/vectors/fail-closed.json) cover every row.

### 5.5 Halts

When an agent becomes halted, the enforcement point:

1. **Closes the gate at once**, before anything else and before acknowledging. From then on, every governed call and interaction is denied (KIL-01).
2. **Applies the halt mode** to work already in flight:
   - `block`: nothing more; the work in flight finishes.
   - `interrupt`: interrupts the work in flight through the framework's own cancellation, where the framework allows it.
   - `terminate`: interrupts, then ends the agent's process after a grace period (10 seconds by default). An unknown mode is treated as `interrupt`.
3. **Acknowledges each layer** with its outcome: `done`, `not_done` (attempted, not achieved, such as a blocking call still running), `not_applicable` (nothing in flight, or the mode excludes the layer) or `failed`. Each report carries the time since the halt was received, on the monotonic clock. The gate is acknowledged as soon as it is closed; later layers follow in further acknowledgements.
4. **Emits** `whitetower.instance.halted.v1` with the same layers.

Drill halts are handled exactly like real halts. Every halt ID that covers the agent, including a fleet halt, is acknowledged for that agent.

A runtime-control module acknowledges its own layer (`network_quarantined`, with the number of workloads isolated) per agent, once the layer is in place.

### 5.6 Releases

When no halt covers the agent any more, the gate reopens only if every other condition of section 5.4 holds. A release never reinstates a suspended agent: that is a lifecycle transition, which reaches the enforcement point as a new lifecycle state.

### 5.7 Obligations of enforcement points

- **EP-1. Start closed.** Allow nothing until the instance has registered, applied a complete snapshot, received a lease renewal and activated a verified bundle for the agent.
- **EP-2. Decide locally, gate first.** For every governed call and interaction, check the gate (section 5.4), then evaluate the agent's bundle with the profile and the combining algorithm of section 6. Never call the core synchronously to decide.
- **EP-3. Leases.** Keep one lease per agent on a monotonic clock, renewed only by fresh renewals; when it expires, deny everything and apply the halt mode (section 5.3).
- **EP-4. Halts.** When the agent or the fleet is halted, close the gate at once, apply the halt mode, and acknowledge each layer honestly (section 5.5).
- **EP-5. Releases.** Reopen only when no halt covers the agent and every other gate condition holds (section 5.6).
- **EP-6. Lifecycle.** Open the gate only in the `validated`, `ready` and `active` states.
- **EP-7. Bundles.** Fetch the bundle the state refers to, verify it (section 7.4), activate it atomically and acknowledge the outcome. Keep the last valid bundle when a new one is rejected, and never allow anything without one.
- **EP-8. Evidence.** Record each decision durably before the action proceeds; publish events at least once, in order, from a stable source (section 8.4). Close the gate when the evidence buffer cannot accept another event.
- **EP-9. Reconnection.** Reconnect with the backoff of section 4.7, resuming from the last version applied, and accept a snapshot at any time.
- **EP-10. Unknown content.** Ignore unknown fields. Treat an unknown lifecycle state as closing the gate, an unknown halt scope as a halt, and an unknown halt mode as `interrupt`. Never let an unknown value open anything.
- **EP-11. Identity and trust.** An enforcement point inside an agent's process authenticates as that agent and serves it only. Take the core's trust anchors and the bundle keys from configuration.
- **EP-12. State acknowledgements.** Acknowledge the state version applied at least every 60 seconds while it changes, so the console can show instances that lag behind.

### 5.8 Obligations of runtime-control modules

- **RC-1.** Apply the module's layer to every agent in scope that is halted, whether by an agent, selector or fleet halt, including workloads started after the halt.
- **RC-2.** Never lift a layer without a current state from the core showing the agent running: not after a restart, and not while disconnected.
- **RC-3.** When the lease expires, keep every layer in place, apply no new one, and emit `whitetower.lease.expired.v1`. A module MAY offer, off by default, to apply its layer to every agent in scope when its lease expires.
- **RC-4.** Acknowledge each halt per agent with the layer, its outcome and the number of workloads covered. Report `done` only once the layer is in place, and `not_applicable` when the agent has no workloads the module controls.
- **RC-5.** Emit the module's events when a layer is applied or lifted.
- **RC-6.** Report, through heartbeats, the agents that have workloads the module controls.

### 5.9 What the core guarantees

Besides CORE-1 to CORE-7:

- **CORE-8.** A halt is committed, and the stream updated, without waiting for any module. Token issuance for the halted agents stops in the same transaction, except for tokens for the module API, which their enforcement points still need to acknowledge the halt, deliver their evidence and learn of the release ([ADR-0010](../adr/0010-built-in-agent-token-issuer.md)).
- **CORE-9.** Governance state carries no personal data other than the owner's pseudonymous principal ID.

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
  "resource": { "type": "tool", "id": "send_email", "properties": { "kind": "function" } },
  "context": { "time": "2026-09-29T10:15:02.118Z", "task_id": "run-7f41" }
}
```

```json
{ "decision": false, "context": { "reason": "policy.forbid", "policies": ["0192f1c2-7a3b-7c4d-8e5f-000000000101"], "bundle_version": 42 } }
```

### 6.2 The subject

The subject is always the agent (`type: agent`). The enforcement point builds it from its state and its credential, never from the agent's input:

| Property | Source | Cedar |
| --- | --- | --- |
| `id` | The agent ID | The principal's ID |
| `slug`, `kind`, `risk_tier`, `data_categories`, `owner` | Governance state (`slug`, `attributes`) | Attributes of the same names |
| `environment` | The environment of the credential the enforcement point runs with (`production` or `non_production`) | Attribute `environment` |
| `labels` | Governance state (`attributes.labels`) | Entity tags: `principal.getTag("team")` |

### 6.3 Actions and resources

The eight actions match the intervention points agents actually have. Microsoft AGT's policy runtime names them differently; the mapping is one to one.

| Action | AGT intervention point | Resource type | Evaluation |
| --- | --- | --- | --- |
| `agent.start` | `agent_startup` | `agent`, the agent itself | SHOULD, where the framework has the hook |
| `input.receive` | `input` | `agent` | SHOULD |
| `model.invoke` | `pre_model_call` | `model` | MUST |
| `model.result` | `post_model_call` | `model` | SHOULD |
| `tool.invoke` | `pre_tool_call` | `tool` | MUST |
| `tool.result` | `post_tool_call` | `tool` | SHOULD |
| `output.emit` | `output` | `agent` | SHOULD |
| `agent.stop` | `agent_shutdown` | `agent` | SHOULD |

An enforcement point declares the actions it evaluates in its manifest. Every action is denied by default, so a deployment that evaluates the lifecycle actions usually permits them with a global policy (plan P1-06 seeds one).

| Resource type | ID | Properties |
| --- | --- | --- |
| `tool` | The tool's name as the agent sees it | `kind` (required: `function`, `mcp`, `http` or `other`), `server` (the MCP server's ID, for MCP tools) |
| `model` | The model's name | `provider` |
| `agent` | The requesting agent's ID: an agent action concerns the agent itself | None |
| `mcp_server`, `dataset`, `skill`, `url` | Reserved for later actions | None |

A request whose resource type does not match its action, or whose agent action names another agent, is invalid and denied (`error.invalid_request`).

### 6.4 The context

| Property | Rule |
| --- | --- |
| `time` | Required: when the request was made, on the enforcement point's clock. Policies can use it, for example for business hours |
| `task_id` | The task or run the request belongs to |
| `trace_id` | The W3C trace ID, 32 hexadecimal characters |
| `on_behalf_of` | Reserved for per-task delegated credentials (AID-08). MUST be absent in `v1alpha1` |
| `args` | Tool actions only. The arguments a deployment declares in its `ToolArgs` extension of the Cedar schema (section 6.7), and nothing else. Values are strings, booleans, integers, arrays and objects |

### 6.5 The combining algorithm `wt-deny-overrides-v1`

For every request, the applicable global policies and the agent-specific policies of the requesting agent are evaluated together (requirements, section 5.4.1):

1. If any applicable policy, global or agent-specific, forbids the request, the decision is **deny**. An agent-specific policy cannot override a global denial.
2. Otherwise, if at least one applicable policy permits it, the decision is **allow**.
3. Otherwise the decision is **deny** (default deny).
4. Any error, an evaluation that exceeds its deadline, a missing or unverifiable bundle, an unknown agent, a request outside the profile, an expired lease or a halt results in **deny**.

**Rule 4 is stricter than Cedar.** Cedar skips a policy whose evaluation fails and decides with the others, so a failing `forbid` can leave a `permit` standing. White Tower denies instead: if the evaluation reports any error, the decision is `deny` with reason `error.evaluation`. Vector C-14 checks it. Validation before approval (section 6.7) prevents such errors in practice.

- **EP-2** requires every enforcement point to bound evaluation time. The deadline is configurable; decisions normally take well under a millisecond (spike S1), and a deadline of 50 milliseconds is RECOMMENDED.

### 6.6 Responses and reasons

`decision` is `true` only with reason `policy.permit`. The `context` always carries a `reason` and the list of determining `policies` (White Tower policy IDs), and carries `bundle_version` whenever policies were evaluated. `obligations` is reserved and always empty: decisions are booleans in `v1alpha1`.

| Reason | Decision | Meaning | Determining policies |
| --- | --- | --- | --- |
| `policy.permit` | allow | At least one policy permits, none forbids | The permitting policies |
| `policy.forbid` | deny | A policy forbids | The forbidding policies |
| `policy.no_permit` | deny | No policy applies | None |
| `gate.no_state`, `gate.lease_expired`, `gate.halted`, `gate.fleet_halted`, `gate.lifecycle`, `gate.no_bundle`, `gate.evidence_full` | deny | The gate is closed (section 5.4) | None |
| `error.evaluation` | deny | The evaluation reported an error | The policies that failed |
| `error.timeout` | deny | The evaluation exceeded its deadline | None |
| `error.unknown_agent` | deny | The request is for an agent the bundle is not for | None |
| `error.invalid_request` | deny | The request does not match the profile | None |

### 6.7 Policy languages

**Cedar is the primary language** (open question Q5, spike S1): its "forbid overrides permit" and default deny are exactly rules 1 to 3, and both engines tested, `cedar-go` and `cedarpy`, give the same results on every vector.

- **Schema.** [`whitetower.cedarschema`](../../api/policy/whitetower.cedarschema), namespace `WhiteTower`, declares the entity types (`Agent`, `Tool`, `Model`, and the reserved `McpServer`, `Dataset`, `Skill`, `Url`), the eight actions and the context types.
- **Mapping.** The principal is `WhiteTower::Agent::"<agent-id>"`, with the subject's properties as attributes and its labels as tags. The action is `WhiteTower::Action::"<name>"`. The resource is the entity type of its resource type, with its ID and properties; for agent actions, it is the principal itself. The context holds `time` as a `datetime`, the optional strings, and `args` as a record. A number that is not an integer makes the request invalid.
- **One policy set per bundle.** The enforcement point parses every policy of the bundle into one Cedar policy set, once per bundle, and reports each Cedar statement as its policy's White Tower ID.
- **Agent-specific policies need not name their agent.** A bundle holds only its agent's specific policies, so they apply to that agent alone. The validator warns when an agent-specific policy names another principal.
- **`ToolArgs` is the one extension point.** The base schema declares it empty. A deployment declares the arguments its policies need, for example `type ToolArgs = { recipient_domain?: String };`, and enforcement points fill only those. The core validates policies against the extended schema, in strict mode, before approval (POL-07), and ships the schema in the bundle.

**Rego is the second language**, for engines that run it natively (Phase 2). Each policy is one package under `data.whitetower.policies`, with boolean rules `deny` and `allow`; the input document is the AuthZEN request. The standard wrapper [`decision.rego`](../../api/policy/rego/decision.rego) implements the combining algorithm and produces the response; checked with OPA 1.21. An evaluation error, or an undefined response, is a denial.

### 6.8 Decision points

A `policy-engine` module that is not embedded in an enforcement point is a decision point. It MUST expose the AuthZEN Access Evaluation API (`POST /access/v1/evaluation`, with discovery at `/.well-known/authzen-configuration`) with this profile, and declare it as an endpoint (`protocol: authzen-1.0`) in its manifest. The enforcement point that calls it still checks its own gate first, and treats an unreachable decision point as a denial (`error.timeout`). No MVP component needs a decision point; the Phase 2 gateways will.

## 7. Policy bundles

### 7.1 Contents

A bundle is a manifest, its signature and its files (format `whitetower.bundle.v1`, schema [`bundle-manifest.schema.json`](../../api/policy/bundle-manifest.schema.json)):

| Manifest field | Meaning |
| --- | --- |
| `format` | `whitetower.bundle.v1` |
| `agent_id`, `version` | The agent, and a version that only grows |
| `created_at` | When the core built it |
| `combining_algorithm` | `wt-deny-overrides-v1` |
| `language` | `cedar` or `rego`: every policy of a bundle has the same language |
| `cedar_schema` | The Cedar schema the policies were validated against, at `schema.cedarschema` |
| `policies` | Each policy's ID, name, version, scope (`global` or `agent`), path and SHA-256 |

Policy files live at `policies/<scope>/<policy-id>.<language>`. A bundle holds no other files.

### 7.2 Signature

- The signed bytes are the **RFC 8785 canonical JSON** of the manifest, transported exactly as signed.
- The signature is a **JWS compact serialization with a detached payload** (RFC 7515, appendix F): `<protected header>..<signature>`. The protected header is exactly `{"alg":"EdDSA","kid":"<key ID>","typ":"whitetower-bundle+jws"}`, with an Ed25519 key (RFC 8037). The key ID is RECOMMENDED to be the key's RFC 7638 thumbprint.
- The core signs with its bundle key, separate from its token and checkpoint keys.

### 7.3 Delivery and keys

- Governance state refers to the bundle by version, manifest hash and size; `GetBundle` returns it.
- **EP-11** requires the bundle keys to come from configuration: that is the enforcement point's trust root. `GetBundleKeys` lists the active, next and retired keys, so operators can distribute the next key before a rotation. An enforcement point MUST NOT trust a key only because `GetBundleKeys` lists it.

### 7.4 Verification

An enforcement point verifies a bundle with these steps, in this order, and activates it only if all pass:

1. **V1. Size.** The size announced in the state and the actual size are at most 2 MiB, in at most 1,000 files.
2. **V2. Signature.** The signature is a detached JWS whose header is exactly as in section 7.2, its key ID is trusted, and it verifies over the manifest bytes as received.
3. **V3. Reference.** The SHA-256 of the manifest bytes equals the one in the governance state.
4. **V4. Manifest.** The manifest parses with no unknown field; its format, combining algorithm and language are supported; its agent and version are those of the state.
5. **V5. Files.** Every policy path has the expected form, scope and extension, with no duplicates; every listed file is present with its hash; no other file is present.
6. **V6. No rollback.** The version is newer than the active one. The same version with the same manifest hash is already active: there is nothing to do.
7. **V7. Policies.** Every policy parses. An enforcement point MAY also validate them against the bundled schema.

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

- The new bundle replaces the old one atomically: a decision uses one bundle or the other, never a mix.
- The outcome is acknowledged (`BundleAcknowledgement`) and emitted as `whitetower.bundle.activated.v1` or `whitetower.bundle.rejected.v1`.
- A rejected bundle leaves the previous one active; with none, the gate stays closed (`gate.no_bundle`).
- An enforcement point MUST NOT retry a rejected version with the same manifest hash: it waits for a new reference in the state.

## 8. Events

### 8.1 Overview

Every event ends in the tamper-evident audit log: sealed into its Merkle tree, covered by signed checkpoints and exported ([ADR-0006](../adr/0006-tamper-evident-audit-log.md)). Modules deliver theirs through `EventService.Publish`; the core writes its own in the transaction of each change (AUD-01). The catalog, [`api/events/catalog.json`](../../api/events/catalog.json), lists every type with its schema and an example; CI validates them.

### 8.2 Envelope

Events are **CloudEvents 1.0 in the JSON format**, validated by [`cloudevent.schema.json`](../../api/events/cloudevent.schema.json):

| Attribute | Rule |
| --- | --- |
| `specversion` | `1.0` |
| `id` | Unique within the source; UUIDv7 RECOMMENDED |
| `source` | The evidence stream: `/core`, `/agents/<agent-id>/ep/<stream-id>` for an enforcement point inside an agent, `/modules/<module>/<stream-id>` for other modules |
| `type` | A catalog type, `whitetower.<area>.<event>.v<N>` |
| `time` | When it happened, at the source |
| `subject` | The agent ID, when the event is about one agent (the catalog says when it is required) |
| `datacontenttype` | `application/json` |
| `data` | An object, valid against the type's schema |
| `wtseq` | Required from modules, absent from the core: the event's position in its source, as a decimal string (`"1"`, `"2"` and so on, without gaps). A string, because CloudEvents integers are limited to 32 bits |
| `traceparent`, `tracestate` | The W3C trace context (CloudEvents distributed tracing extension), when the action has a trace |
| `wtorigtype` | For events translated by an adapter, the original type, for example AGT's `ai.agentos.tool.blocked` |
| `dataschema` | Optional in `v1alpha1`; it becomes required, with stable URLs, once the project settles its domain (open question Q6) |

Other extension attributes are allowed and kept, since they are part of the evidence.

### 8.3 Personal data

Events are minimized by design (NFR-20, domain model section 7):

- People appear only as pseudonymous principal IDs, never as names or email addresses.
- Decision events record the **names** of a call's arguments, or nothing, or an HMAC-SHA-256 of the canonical arguments with a key the deployment holds, as configured. They never record argument values in `v1alpha1`.
- Prompts, model outputs and tool results are never recorded in `v1alpha1`.
- Failed calls record the error's type, never its message.
- Halt reasons are free text written by people: they stay in the core's events and are never sent to modules.

### 8.4 Delivery

- **At least once.** The core de-duplicates on source and ID; a retried batch is safe.
- **In order.** An instance publishes each source's events in `wtseq` order. The core records a gap in a source's sequence as an audit finding (AUD-02).
- **Stable sources.** A source identifies an evidence stream, not a process: an instance that keeps its buffer across restarts keeps its source and continues its sequence. A new buffer starts a new source at 1.
- **Results.** `ACCEPTED` and `DUPLICATE` events leave the buffer. A `REJECTED` event can never be accepted: the instance MUST NOT retry it, MUST log it and SHOULD report `HEALTH_DEGRADED`. The gap it leaves stays visible in the audit log.
- **Durability (EP-8).** An enforcement point writes each decision to a durable local buffer before the action proceeds, sized for at least 24 hours at 10 events per second (NFR-08), and closes its gate when the buffer is full.

### 8.5 Catalog

| Type | Emitted by | Subject | When |
| --- | --- | --- | --- |
| `whitetower.decision.made.v1` | Enforcement points | Required | A governed call or interaction was decided, allowed or denied |
| `whitetower.action.executed.v1` | Enforcement points | Required | An allowed call finished: succeeded, failed or cancelled |
| `whitetower.instance.started.v1` | Any module | Optional | An instance started and registered |
| `whitetower.instance.halted.v1` | Enforcement points | Required | A halt was applied, layer by layer |
| `whitetower.bundle.activated.v1` | Enforcement points | Required | A bundle was verified and activated |
| `whitetower.bundle.rejected.v1` | Enforcement points | Required | A bundle was refused |
| `whitetower.lease.expired.v1` | Enforcement points, runtime control | Optional | An instance lost the core for longer than its lease |
| `whitetower.quarantine.applied.v1` | Runtime control | Required | A halted agent's workloads were isolated |
| `whitetower.quarantine.lifted.v1` | Runtime control | Required | The isolation was removed after a release |
| `whitetower.agent.created.v1` | Core | Required | Lifecycle transition T1 |
| `whitetower.agent.lifecycle_changed.v1` | Core | Required | Lifecycle transitions T2 to T14 |
| `whitetower.policy.version_approved.v1` | Core | For agent-specific policies | A committee approved a policy version |
| `whitetower.halt.issued.v1` | Core | For agent halts | A halt was issued |
| `whitetower.halt.released.v1` | Core | For agent halts | A halt was released |
| `whitetower.audit.checkpoint.v1` | Core | None | The audit log signed a checkpoint |

The core emits more types, for every other state change (AUD-01). They follow the same envelope and are defined by the plans that own them; modules do not consume events in `v1alpha1`.

## 9. Conformance

### 9.1 Test vectors

Language-neutral files in [`test/conformance/vectors/`](../../test/conformance/vectors/):

| Vectors | Cases | What they check |
| --- | --- | --- |
| [`combination.json`](../../test/conformance/vectors/combination.json) | 20 | Rules 1 to 4 of the combining algorithm, subject attributes and tags, time, tool arguments, determining policies, invalid requests, and whether each policy passes the validator |
| [`fail-closed.json`](../../test/conformance/vectors/fail-closed.json) | 13 | Every gate condition, and the order of reasons |
| [`bundles/`](../../test/conformance/vectors/bundles/README.md) | 15 | Every verification step, with signed bundles |

They pass on two independent stacks: Go with `cedar-go` 1.8.0 (`go test ./test/conformance`), and Python with `cedarpy` 4.12.1 and `cryptography` ([`check_vectors.py`](../../test/conformance/python/check_vectors.py)).

### 9.2 The kit

The kit plays the core for a module under test: a fake core that speaks the module API (registry, watch with scripted state and leases, bundles, acknowledgements, events) and a driver that exercises the module through the small HTTP protocol of [`driver-protocol.md`](../../test/conformance/driver-protocol.md). Because the kit speaks the module API over the network, it tests a module written in any language. The skeleton in [`test/conformance/kit`](../../test/conformance/README.md) runs scenario S-01 end to end against a stub enforcement point in Go; plan P1-07 completes it.

### 9.3 Scenarios

| Scenario | Obligations | Status |
| --- | --- | --- |
| S-01 Start closed: nothing is allowed before state, lease and a verified bundle | EP-1, EP-7 | Implemented |
| S-02 Every gate condition denies, with its reason | EP-2, EP-6, fail-closed vectors | Designed |
| S-03 The combination vectors give the expected decisions | EP-2, section 6 | Designed |
| S-04 Lease expiry denies and halts within the TTL plus a tolerance | EP-3 | Designed |
| S-05 A halt closes the gate and is acknowledged layer by layer, within the NFR-03 target | EP-4 | Designed |
| S-06 A fleet halt halts the agent although its own state is unchanged | EP-4 | Designed |
| S-07 Reconnecting while halted stays halted | EP-1, EP-4, EP-9 | Designed |
| S-08 A release reopens only with a valid lease and bundle | EP-5 | Designed |
| S-09 The bundle vectors are rejected with the right reasons, and the previous bundle stays active | EP-7 | Designed |
| S-10 Events validate against the catalog, with a gapless `wtseq`, and survive a restart | EP-8 | Designed |
| S-11 A full evidence buffer closes the gate | EP-8 | Designed |
| S-12 Reconnection uses jittered backoff bounded by the lease, resets after a renewal, and resumes from the last version | EP-9, I-4 | Designed |
| S-13 Unknown fields and values never open anything | EP-10 | Designed |
| S-14 A runtime-control module never lifts a layer without a current state | RC-2, RC-3 | Designed |
| S-15 A runtime-control module acknowledges per agent, with the workloads covered | RC-4 | Designed |
| S-16 Registration refuses an unknown contract version | CORE-3, I-3 | Designed |
| S-17 Stale renewals, a minute old or without the core's time, renew nothing: the lease runs out within its TTL, and a fresh renewal renews it again | EP-3, section 5.3 | Implemented |

## 10. Versioning and compatibility

- **Identifiers.** The contract version is `v1alpha1`, then `v1beta1`, then `v1`. It is the protobuf package and the manifest's `apiVersion`. Event types carry their own version (`.v1`), and so do the bundle format (`whitetower.bundle.v1`) and the combining algorithm (`wt-deny-overrides-v1`).
- **A published version never changes incompatibly.** A breaking change creates the next version (for example `v1alpha2`), which the core serves next to the previous one:
  - alpha: at least one minor release of the core with both versions;
  - beta: two minor releases or six months, whichever is longer;
  - `v1`: twelve months.
- **Additive changes stay in the version:** new fields, enum values, methods, event types and optional event data. Readers ignore unknown fields; unknown enum values take their fail-closed meaning (EP-10).
- **An event type changes incompatibly only as a new type** (`.v2`); emitters may send both during a migration.
- **Every change to `api/proto`, `api/events`, `api/manifest` or `api/policy` needs an RFC** (GOVERNANCE.md).
- **Draft until tagged.** `v1alpha1` is a draft until RFC-0001 is accepted and `contracts/v0.1.0` is tagged. CI compares the protobuf files with the latest `contracts/v*` tag (`buf breaking`, FILE rules), so changes during the review are free and changes after it are checked.
- **Compatibility matrix.** Each release documents, for the core and for each module, the contract versions supported:

  | Core | Contract versions | ep-python | k8s-quarantine | mock-module |
  | --- | --- | --- | --- | --- |
  | 0.1.x | v1alpha1 | 0.1.x | 0.1.x | 0.1.x |

## 11. Security considerations

| Threat | What the contracts do |
| --- | --- |
| A compromised enforcement point lies in its acknowledgements or evidence | Layers are reported separately and never overstate (section 5.5); halts also stop token issuance for every audience but the module API (CORE-8); network quarantine acts outside the agent's process (RC-1); the console flags instances that keep emitting actions after a halt (P1-08) |
| Stolen agent credentials | The thief can act only as that agent: its scope is one agent, its state carries no personal data (CORE-9), its halts stop token issuance for every audience but the module API, and revoking the credential stops that too |
| A forged or tampered bundle | Signed with a key from the enforcement point's configuration (section 7.3), bound to the state's hash, verified step by step (section 7.4) |
| Replaying an older bundle | Versions only grow, and the state names the one to use (V3, V6) |
| Impersonating the core | TLS with trust anchors from configuration (I-1) |
| Cutting enforcement points off the core | They fail closed when their lease expires (section 5.3): an attacker can stop agents, never free them. This trade-off is accepted in ADR-0005 |
| Holding the stream back, so that renewals keep leases alive while halts arrive late | Renewals carry the core's time, and an instance ignores one older than its tolerance (section 5.3): past the tolerance, leases run out |
| A stale replica undoing a halt | The core never sends state older than the client's (CORE-5), and renewals mean "current" (CORE-6) |
| Flooding the audit log | Rate limits, the limits of section 4.8, and publication restricted to declared types and owned sources (section 4.3) |
| Personal data leaking into evidence | Minimization rules of section 8.3 |
| Unknown values opening the gate | EP-10 |

The [threat model](../security/threat-model.md) (plan P0-04) analyzes these boundaries in depth.

## 12. Open questions for the review

| Question | Proposal |
| --- | --- |
| Should enforcement points learn rotated bundle keys from the core? | Not in `v1alpha1`: keys come from configuration. A key rollover statement signed by the current key could come in `v1beta1` |
| Which tool arguments may policies see? | Only those a deployment declares in `ToolArgs`; how deployments manage that extension is settled in P1-06 |
| Do quarantined pods keep cluster DNS? | Decided by the [threat model](../security/threat-model.md) (DC-7): no, by default. The enforcement point reconnects to the core's last resolved addresses; where the CNI has DNS-aware rules, an option may allow the core's name only |
| Stable URLs for `dataschema`, and the Kubernetes label prefix | Depend on the project's domain (open question Q6) |
| When do decision points become mandatory for gateways? | With the Phase 2 gateways, in `v1beta1` |
| Rego package naming and a Rego engine | Phase 2, with the second policy engine |

## Appendix A. JSON examples

Examples use the Connect protocol with JSON. Field names are the protobuf JSON names, 64-bit integers are strings, durations are strings such as `"30s"`, and enumerations are their names. Every call carries `Authorization: Bearer <token>` and `Content-Type: application/json`.

**`RegistryService.RegisterInstance`**, `POST /whitetower.module.v1alpha1.RegistryService/RegisterInstance`

```json
{
  "module": "ep-python",
  "manifestSha256": "9f2c4be1d0a8f3e6c7b5a4d3e2f1c0b9a8d7e6f5c4b3a2918f7e6d5c4b3a2f10",
  "moduleVersion": "0.1.0",
  "instanceKey": "invoice-triage-7d9f-2",
  "contractVersions": ["v1alpha1"],
  "agentIds": ["0192f1c2-7a3b-7c4d-8e5f-000000000001"],
  "info": { "host": "invoice-triage-7d9f-2", "components": { "python": "3.13.1", "langgraph": "1.2.0" } }
}
```

```json
{ "instanceId": "0192f1c2-9e00-7c4d-8e5f-000000000051", "contractVersion": "v1alpha1", "heartbeatInterval": "30s" }
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
| KIL-01, KIL-03, KIL-04, KIL-07, KIL-10 | Sections 5.3 to 5.8 |
| AUD-02 idempotent ingestion, sequences, gaps | Section 8.4 |
| NFR-20 privacy | Section 8.3 and CORE-9 |
