# RFC-0002: MCP servers, tools and models

| | |
| --- | --- |
| **Status** | Draft |
| **Authors** | @J466Y |
| **Review period** | At least two weeks from the day it is announced, with at least one external reviewer |
| **Related** | [RFC-0001](0001-module-contracts-v0.1.md) and its open question on tool arguments; [module contracts](../contracts/module-contract-v0.1.md), sections 4 to 8; requirements INV-07, POL-05, POL-06, MOD-06, KIL-01, UI-02 ([requirements](../requirements/mvp-requirements.md)); plans [P1-06](../plans/phase-1/P1-06-policy-model-and-distribution.md), [P1-07](../plans/phase-1/P1-07-module-registry-and-api.md), [P1-08](../plans/phase-1/P1-08-kill-switch.md), [P1-09](../plans/phase-1/P1-09-python-enforcement-point.md), [P1-10](../plans/phase-1/P1-10-web-console.md), [P1-11](../plans/phase-1/P1-11-cli.md); [ADR-0005](../adr/0005-edge-enforcement-with-leases.md), [ADR-0011](../adr/0011-own-python-enforcement-point.md); [threat model](../security/threat-model.md) |

## Summary

White Tower learns which MCP servers, tools and models each agent has, including the tools a model provider runs on the agent's behalf. It keeps them in a catalog, where people approve or block them and enable them agent by agent. Policies then forbid patterns of use, such as a file path outside a directory or a push to the main branch. The enforcement point reports what it finds, checks every tool and model call against the catalog before evaluating policies, and hides from the model the tools it may not use. If you build an enforcement point, or write policies about tools, this RFC affects you.

## Motivation

An agent can do what its tools let it do. Those tools come from wherever its developers configured them:

- functions in the agent's code;
- MCP servers it launches or connects to;
- tools its model provider runs during a model call.

Adding an MCP server to an agent's configuration widens what the agent can do, and today nobody reviews it.

Endpoint security suites now list the local agents on a device and the MCP servers configured for each, and can block an agent or a server for the whole organization. That tells an organization what exists. It does not decide what each agent may do with it. Nor does it govern the agents an organization runs on its own infrastructure, with its own models.

The `v1alpha1` decision profile already names MCP tools (`kind: mcp`, `server`), but it leaves three things undefined:

- how a server is identified;
- where policies learn what a tool is;
- which tool arguments policies may see (RFC-0001 left this open).

Without them, policies about tools are lists of names that any configuration change can sidestep.

The maintainer decided on 2026-10-13:

- **What an agent can do is delimited by its MCP servers, tools and models.** They are discovered, approved or blocked, and enabled per agent.
- **How it may use them is delimited by policies**, with usage rules that forbid patterns of use. Skills, which teach a model how to use its tools, cannot be enforced, so the skills repository leaves Phase 2.
- **Both are part of the MVP.** P1-04, P1-06 and P1-09 have not started, so designing this in now costs least.

## Proposal

### 1. Principles

1. **Reports inform; they never authorize.** What an enforcement point reports about an agent's tooling fills the catalog. Only people, through approvals, make anything usable.
2. **The catalog says what; policies say how.** A tool or model must be enabled for the agent before any policy is evaluated. Policies can forbid more; they can never reach what is not enabled.
3. **Restricting takes effect at once; permitting needs a second person.** Blocking an entry, or disabling it for an agent, is immediate. Approving, enabling and unblocking need someone other than the person who asked (HUM-04).
4. **Blocks never slow halts.** Organization-wide blocks reach enforcement points through the watch stream, as halts do, but in their own record.
5. **The enforcement point decides alone.** Everything it needs arrives in the signed bundle and the watch stream; it never calls the core to decide (EP-2).

### 2. Terms

| Term | Meaning |
| --- | --- |
| MCP server | A server that speaks the Model Context Protocol. It is either local (`stdio`, a process the agent launches) or remote (`http`, streamable HTTP or SSE) |
| Tool | Something a model can call. Its **kind** is `function` (the agent's own code), `mcp` (a tool of an MCP server), `builtin` (defined by the model provider, such as web search), `http` or `other` |
| Origin | Who runs the tool: `agent` (the agent's process, or an MCP server the agent connects to) or `provider` (the model provider, during a model call: its built-in tools, and the remote MCP servers it calls for the agent) |
| Model | A model the agent calls: provider, endpoint, name and, for self-hosted runtimes, the digest of its weights |
| Catalog | The organization's list of MCP servers, tools and models. Each **entry** is `discovered`, `approved` or `blocked` |
| Reference | How an enforcement point identifies an entry at runtime (section 3) |
| Key | The entry's name in policies and in the console, assigned by the core: `github`, `github/create_issue`, `agent/send_email`, `provider.openai/web_search`, `gpu-01/llama3.1-8b` |
| Definition | What the model sees of a tool: its name, description and schemas. Approval pins its hash |
| Observed | The entries an enforcement point reported for an agent |
| Enabled | The entries an agent may use, approved for that agent |
| Block | An organization-wide denial of a server, a tool or models, effective at once |
| Usage rule | A forbidden pattern of use of a tool, written in a policy (section 8) |

### 3. References, keys and definitions

**References.** An enforcement point MUST compute references exactly as follows, so that they match the catalog's:

| Entry | Reference |
| --- | --- |
| Remote MCP server, called by the agent or by its model provider | The server's URL without user information, query or fragment, with the scheme and host in lowercase, the default port left out, and an empty path written as `/` |
| MCP server hosted by the model provider and named by an ID rather than a URL | `connector:<provider>/<connector ID>` |
| Local MCP server | `stdio:` followed by the RFC 8785 canonical JSON of the array of its command and arguments, as configured, after the redaction of EP-14 |
| Tool | Its server's reference and the tool's name. A function, `http` or `other` tool: its name alone. A built-in tool: the provider and the tool's type |
| Model | The provider (the framework's name for it, such as `openai`, `anthropic` or `ollama`), the base URL of the endpoint, normalized like a remote server's and absent for the provider's public endpoint, and the model's name as requested |

**Keys.** The core assigns each entry a key the first time it sees the entry. A key is unique in the catalog and never changes once the entry is approved:

- **Servers:** a slug of lowercase letters, digits and hyphens, at most 63 characters, derived from the name the server announces or from its host.
- **Tools:** `<server key>/<tool name>`. Two server keys are reserved: `agent`, for the agent's own tools, and `provider.<provider>`, for a provider's built-in tools.
- **Models:** a slug of their provider or endpoint, a slash, and a slug of their name.

**Definitions.** A definition hash is the lowercase hexadecimal SHA-256 of the RFC 8785 canonical JSON of the following, leaving out absent members:

- **MCP tool:** the members `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations`, as the server lists the tool.
- **Function, `http` or `other` tool:** its name and the JSON Schema of its parameters, as the framework presents them to the model. Their descriptions belong to the agent's own code, which its owner controls ([threat model](../security/threat-model.md), A-6).
- **Built-in tool:** its declaration in the model request, without credentials.

### 4. Discovery

#### 4.1 `RegistryService.ReportTooling`

A new method of the registry service, idempotent:

| Field | Meaning |
| --- | --- |
| `instance_id` | The reporting instance |
| `agent_id` | The agent the tooling belongs to, in the instance's scope |
| `servers` | Each MCP server: reference, transport (`stdio` or `http`), origin, the name and version it announces, and a display form (its URL or command line, redacted) |
| `tools` | Each tool: kind, origin, its server's reference, name, title, description, input and output schemas, annotations and definition hash |
| `models` | Each model: provider, endpoint, name and, when the runtime reports one, digest |

A report is complete: it replaces the instance's previous report for that agent.

- **EP-13. Report tooling.** Report the agent's tooling as soon as it is known; the first report SHOULD come before the gate first opens. Report again whenever it changes, for example when:
  - an MCP server connects, or announces a changed tool list (`notifications/tools/list_changed`);
  - a model is called for the first time;
  - a model request declares a provider-run tool not reported yet.

  Report what the agent is configured with, not only what it has called.
- **EP-14. Redact.** Never report environment variables, HTTP headers, authorization values or any other credential. Remove user information, query and fragment from URLs, including URLs passed as command-line arguments. Replace with `<redacted>` the value of any command-line argument that follows a flag, or is written `--flag=value`, when the flag's name contains, in any case, `token`, `secret`, `password`, `passwd`, `key`, `auth`, `credential` or `cookie`.

#### 4.2 What the core does

- **CORE-10.** The core MUST treat reports as observations. A report MUST NOT approve, enable or unblock anything, and MUST NOT change an approved definition.
- **CORE-11.** The core MUST apply the redaction of EP-14 again before storing a report, and MUST NOT copy reported descriptions or schemas into audit events.
- **New entries.** A reference the catalog does not have becomes a `discovered` entry. When a tool's reported definition differs from the approved one, the approved definition stays pinned and the new one waits for review.
- **Observations.** For each agent, the core keeps the entries observed and when each was last seen. The console can then show tooling waiting for a decision, and enabled tooling the agent no longer has.
- **Limits (contracts, section 4.8).**
  - A report holds at most 256 servers, 4,096 tools and 256 models.
  - Each description is at most 16 KiB, and each schema at most 64 KiB.
  - The core MAY refuse, with `RESOURCE_EXHAUSTED`, more than one report per instance every 10 seconds.

### 5. The catalog in the bundle

Each agent's bundle carries a catalog file, `catalog.json`, listed in the bundle manifest like the Cedar schema (`catalog`, with its path and SHA-256). It is activated with the policies, atomically, and holds the entries enabled for the agent and those observed for it:

```json
{
  "format": "whitetower.catalog.v1",
  "servers": [
    { "key": "github", "reference": "https://api.githubcopilot.com/mcp/", "transport": "http", "status": "approved" }
  ],
  "tools": [
    {
      "key": "github/create_pull_request", "server": "github", "name": "create_pull_request",
      "kind": "mcp", "origin": "agent", "status": "approved", "enabled": true,
      "definition": "4d1c…", "read_only": false, "destructive": false, "open_world": true,
      "args": [{ "name": "base", "path": "base", "type": "String" }]
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

- **Status and enablement.** `status` comes from the catalog, and `enabled` from the agent's enablement.
- **Pinned values.** `definition` and `digest` are pinned when the entry, or its new definition, is approved.
- **Classification.** `read_only`, `destructive` and `open_world` are set by the reviewer. They start from the tool's MCP annotations, or, when those are absent, from the protocol's conservative defaults: not read-only, destructive, open world. Annotations are hints from the server; the catalog's values have been reviewed.
- **Arguments.** `args` lists the tool's arguments that policies may see (section 7.5).
- **Verification.** Step V4 accepts the manifest's `catalog` field, and step V5 requires its file. An enforcement point that does not support catalogs rejects such a bundle (`invalid_manifest`) and stays closed.

### 6. Blocks

A block denies, for every agent and at once, one of:

- an MCP server and all its tools;
- a single tool;
- a model;
- every model of a provider or of an endpoint.

Blocks name references, not keys, so an enforcement point applies them without waiting for a new bundle.

How blocks travel:

- **In their own record of the watch stream.** A snapshot carries every active block (`Block`: block ID, what it covers, issue time), and changes carry the blocks added and removed. Blocks take their versions from the same sequence as the rest of the state, so a lease renewal still means "your state is current" (CORE-6).
- **CORE-12.** A block is committed, and the stream updated, without waiting for any bundle, as for halts (CORE-8).
- **EP-15. Blocks.** Apply a block as soon as it arrives. It denies every later call to, and exposure of, what it covers. Then acknowledge the state version that carries it, without waiting for the 60 seconds EP-12 allows, so the console shows how far each block has spread, as it does for halts.
- **Halts stay fast.** Blocks never enlarge the fleet record that fleet halts change, so a fleet halt costs the same with or without blocks. The core caps active blocks at 500, and references at 512 bytes, which keeps all blocks within one watch message. P1-08 measures halt propagation with that many blocks active.

### 7. Decisions

#### 7.1 The catalog check

For `tool.invoke`, `tool.expose` (section 7.3) and `model.invoke`, an enforcement point checks the catalog after the gate (contracts, section 5.4) and before policies. It denies with the first reason that applies:

| Order | Condition | Reason |
| --- | --- | --- |
| 1 | A block covers the server, the tool or the model | `catalog.blocked` |
| 2 | The bundle's catalog does not list it | `catalog.unknown` |
| 3 | Its status is `blocked` | `catalog.blocked` |
| 4 | Its status is `discovered` | `catalog.not_approved` |
| 5 | It is not enabled for the agent | `catalog.not_enabled` |
| 6 | The tool's definition, as the agent has it now, differs from the pinned one | `catalog.definition_changed` |
| 7 | A digest is pinned for the model, and the runtime's digest differs or is unknown | `catalog.digest_mismatch` |

- **EP-16. Catalog check.** Apply the catalog check to every `tool.invoke`, `tool.expose` and `model.invoke`. Resolve the tool or the model by its reference at the time of the call, never by its name alone. Anything that cannot be resolved is `catalog.unknown`.

What passes the check is enabled for the agent. P1-06 seeds a global policy, named `wt-catalog`, that permits the tool and model actions, so that an enabled entry is usable unless a policy forbids it:

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

The steering committee approves it like any global policy, and may narrow it, for example to non-production credentials. A bundle that carries it also carries a catalog, so an enforcement point that does not know catalogs rejects the bundle rather than apply the permit without the check.

#### 7.2 Resources and context

With a catalog, a resource's ID is its key, and its properties come from the catalog, never from the agent:

| Resource | Properties |
| --- | --- |
| `tool` | `kind`, `origin`, `name`, `read_only`, `destructive` and `open_world`; for MCP tools, also `server` (the server's key) and `transport`; for built-in tools, also `provider` |
| `model` | `provider` and `name`; for self-hosted models, also `endpoint` |

In Cedar, an MCP tool's parent is its server, `WhiteTower::McpServer::"<key>"`, so that a policy can name a whole server: `resource in WhiteTower::McpServer::"github"`. The context of `model.invoke` gains `digest`, when the runtime reports one.

#### 7.3 `tool.expose`

This RFC adds a ninth action: a tool is offered to a model.

| Action | Resource type | Evaluation |
| --- | --- | --- |
| `tool.expose` | `tool` | MUST, for every provider-run tool, and for every tool of a model request where the framework lets the enforcement point change the request's tools |

- **EP-17. Exposure.** Before each model call, evaluate `tool.expose` for every tool the request offers, and remove the denied ones from the request. When a denied tool cannot be removed:
  - deny the model call if the tool is provider-run, because the provider would call it without passing through the agent;
  - deny the model call if the denial is `catalog.definition_changed`;
  - otherwise, the enforcement point SHOULD deny the model call.

  Exposure decisions MAY be reused until the bundle, the agent's state, the blocks or the tool's definition change, so a model call normally costs no evaluation. Policies on `tool.expose` therefore SHOULD NOT depend on the time.

A changed, possibly poisoned, description never reaches the model. Where the framework allows it, neither does any tool the agent may not use.

#### 7.4 Provider-run tools

The enforcement point sees a provider-run tool twice: declared in the model request, and in the response once it has run.

- **EP-18. Provider-run tools.**
  - Narrow each declared remote MCP server to the tools enabled for the agent, for example by setting the declaration's list of allowed tools.
  - Deny the model call when it would let the provider call a tool that is not enabled.
  - Where the provider asks the agent to approve each call, evaluate `tool.invoke` with the call's arguments, and answer with the decision.
  - Record the provider-run calls that a response reports as `action.executed` events with origin `provider`.

#### 7.5 Arguments policies see

This section answers RFC-0001's open question on tool arguments.

- **Which arguments.** Policies see two sets of a tool's arguments: those that the usage rules of the agent's effective policy set use, and those a reviewer declared for the tool in the catalog. The core lists them in the catalog file (`args`) and declares them in the bundle's Cedar schema.
- **One record per tool.** `context.args` holds one record per tool, keyed by the tool's key, with the declared arguments inside: `context.args["github/create_pull_request"]["base"]`. Per-tool records keep types unambiguous: `id` can be a number for one tool and a string for another.
- **Naming.** An argument is named by its path in the call's arguments, for example `options.base` for a nested field. When a transform applies, a colon and the transform's name follow: `path:path`, `url:url_host`.

| Transform | Value |
| --- | --- |
| `lowercase` | The string, with ASCII letters in lowercase |
| `path` | The path with backslashes turned into slashes, then cleaned lexically as Go's `path.Clean` does: repeated slashes merged, `.` and `..` resolved |
| `url_host` | The host of an absolute URL, in ASCII lowercase |
| `email_domain` | What follows the last `@`, in ASCII lowercase |

- **Types** come from the tool's input schema: strings, integers and booleans, and arrays of strings or of integers, which become sets. A transform applies to each element of an array.
- **EP-19. Arguments.** Fill only the declared arguments, and apply their transforms. A value that does not fit its declared type, or that a transform cannot read (a URL without a host, for example), denies the call with `error.invalid_request`. Values never reach evidence (contracts, section 8.3).

#### 7.6 Cedar schema

The schema changes as follows. This is the draft; the other actions are unchanged.

```cedar
namespace WhiteTower {
  // The MCP server a tool belongs to.
  entity McpServer;

  entity Tool in [McpServer] {
    kind: String,          // "function", "mcp", "builtin", "http" or "other"
    origin: String,        // "agent" or "provider"
    name: String,          // the tool's name within its server
    read_only: Bool,
    destructive: Bool,
    open_world: Bool,
    server?: String,       // the server's key, for MCP tools
    transport?: String,    // "stdio" or "http", for MCP tools
    provider?: String      // for built-in tools
  };

  entity Model {
    provider?: String,
    name?: String,
    endpoint?: String      // the normalized base URL, for self-hosted models
  };

  // Generated for each bundle from the catalog's argument declarations.
  type ToolArgs = { "github/create_pull_request"?: { "base"?: String } };

  type ModelContext = {
    time: datetime,
    task_id?: String,
    trace_id?: String,
    on_behalf_of?: String,
    digest?: String
  };

  action "tool.expose" appliesTo { principal: Agent, resource: Tool, context: ToolContext };
  action "model.invoke" appliesTo { principal: Agent, resource: Model, context: ModelContext };
}
```

### 8. Usage rules

A usage rule forbids a pattern of use of one or more tools. It replaces what skills would have taught, and is enforced on every call.

| Field | Meaning |
| --- | --- |
| `id` | Unique within its policy |
| `description` | Why the pattern is forbidden, for reviewers |
| `tools` | Tool keys. The console can apply a rule to every tool of a server that has the argument |
| `when` | Conditions. The rule forbids a call when all of them hold |

Each condition has the following fields:

| Field | Meaning |
| --- | --- |
| `arg` | The argument's path, for example `branch` or `options.base` |
| `transform` | Optional: a transform from section 7.5 |
| `op` | The operator, from the table below |
| `values` | The values to compare with |
| `if_absent` | `match` (the default: a missing argument counts as matching, so the rule fails closed) or `no_match` |

| Operator | Holds when |
| --- | --- |
| `equals`, `not_equals` | The value is, or is not, the single value given |
| `in`, `not_in` | The value is, or is not, one of the values. For an array: at least one element is in them, or at least one element is not |
| `matches`, `not_matches` | The string matches, or does not match, one of the patterns. Patterns are Cedar `like` patterns, where `*` matches any sequence of characters |
| `less_than`, `greater_than` | The integer is smaller, or larger, than the value |

A rule compiles to one Cedar `forbid` statement per tool, annotated with the rule's canonical JSON:

```cedar
@rule("{\"id\":\"no-push-to-main\",\"tools\":[\"github/push_files\"],\"when\":[{\"arg\":\"branch\",\"op\":\"in\",\"values\":[\"main\",\"master\"]}]}")
forbid (
  principal,
  action == WhiteTower::Action::"tool.invoke",
  resource == WhiteTower::Tool::"github/push_files"
) when {
  if context has args && context.args has "github/push_files" && context.args["github/push_files"] has "branch"
  then ["main", "master"].contains(context.args["github/push_files"]["branch"])
  else true
};
```

- **Ordinary policies.** Rules live in ordinary policies, global or agent-specific, and follow the same approval workflow. The console edits them as forms. Each statement carries its rule in the annotation, so the policy text is the only source of truth.
- **Generated text is checked.** When a policy version is submitted, the core regenerates each statement that carries `@rule` from its annotation, and refuses the version unless the statement is exactly what the generator produces. A reviewer can therefore trust the form the console shows.
- **Evidence names the rule.** Decision events name the rules that decided (section 9), so the audit log says "denied by `no-push-to-main`".
- **Limits.**
  - Cedar's `like` is the only pattern language, so rules can use no regular expressions.
  - Rules are stateless: sequences of calls and counts per task are left to Phase 2.
  - A path is cleaned lexically, so symbolic links on the server are not resolved.

### 9. Events

New event types emitted by the core:

| Type | Subject | When |
| --- | --- | --- |
| `whitetower.catalog.discovered.v1` | None | A report brought entries the catalog did not have. The event lists their keys and references, without descriptions |
| `whitetower.catalog.approved.v1` | None | An entry, or a new definition of a tool, was approved, with the pinned hash and the classification |
| `whitetower.catalog.definition_changed.v1` | None | A reported definition differs from the approved one; the event carries both hashes |
| `whitetower.catalog.blocked.v1` | None | A block was issued, with its reason and issuer |
| `whitetower.catalog.unblocked.v1` | None | A block was lifted, with the requester and the approver |
| `whitetower.tooling.enabled.v1` | Required | Entries were enabled for an agent, with the requester and the approver |
| `whitetower.tooling.disabled.v1` | Required | Entries were disabled for an agent |
| `whitetower.tooling.observed.v1` | Required | The tooling observed for an agent changed: keys added and removed |

Events from enforcement points gain optional fields:

- `decision.made` gains the IDs of the usage rules that decided, and the resource's origin.
- `action.executed` gains the origin, and marks provider-run calls that no decision preceded.

### 10. Outside the contracts

These parts are not contract, but reviewers need them to judge the whole.

**Roles.** The permission matrix gains these rows, which P1-03 refines:

| Action | Steering | Advisory | Owner | Operator | Auditor |
| --- | :-: | :-: | :-: | :-: | :-: |
| View the catalog and each agent's tooling | ✔ | ✔ | ✔ | ✔ | ✔ |
| Approve an entry or a new definition, classify it, and declare the arguments policies see | | ✔ | | | |
| Block an entry, at once and with a reason | ✔ | ✔ | | ✔ | |
| Request to unblock | ✔ | ✔ | | ✔ | |
| Approve unblocking (not the requester) | ✔ | ✔ | | | |
| Request enabling for an agent | | ✔ | own | | |
| Approve enabling (not the requester) | | ✔ | | | |
| Disable for an agent, at once | | ✔ | own | ✔ | |

Usage rules follow the policy rows of the matrix: global rules are global policies, and agent rules are agent-specific policies.

**Console:**

- **MCP servers:** the catalog's servers, with their status, transport, tools, the agents that use them, and when they were first and last seen. A server's page shows its tools, their definitions (changes as diffs), their classification and their history, with the actions to approve, block and unblock.
- **Models:** the same for models, with endpoints and digests.
- **"MCP and Tools" on each agent:** its servers, tools and models, each marked observed, enabled or both, with switches to request enabling and to disable. The tab also shows the usage rules that apply to each tool, the enabled tooling the agent no longer has, and the tools waiting for review.
- **"MCP and Tools" on each model:** the provider-run tools seen with the model, and the agents that use them.
- **Reported text** is shown as plain text, marked as reported by the agent.

**API and CLI.** Every function is in the public API (API-01) and in `wtctl` (`wtctl catalog`, `wtctl agents tooling`).

**Agents without the enforcement point** (coverage C0 and C1). Their owners can declare their tooling in the catalog, so the inventory is complete, but nothing enforces it.

The Phase 2 MCP gateway will enforce it, as another enforcement point that uses this same catalog, its blocks and its rules, and discovers the servers agents reach through it. A network gateway cannot see local servers, in-process functions or provider-run tools. That is why the enforcement point is the MVP's control point.

**Lifecycle.** Enabling tooling is part of "policy and harness assignment", between `validated` and `ready`. Periodic reviews (INV-06) list enabled tooling the agent has not used recently, as candidates to disable.

### 11. Conformance

New vectors cover:

- references and redaction;
- the catalog check and its order;
- transforms, missing arguments and types;
- exposure.

New scenarios:

| Scenario | Obligations |
| --- | --- |
| S-18 A report makes nothing usable | CORE-10, EP-16 |
| S-19 Unknown, discovered, disabled and blocked tooling is denied with its reason, before policies | EP-16 |
| S-20 A block denies within the halt propagation target, without a new bundle, and is acknowledged once applied | EP-15, CORE-12 |
| S-21 A tool whose definition changed is denied and not exposed | EP-16, EP-17 |
| S-22 Only exposed tools reach the model; a provider-run tool that cannot be removed fails the model call | EP-17, EP-18 |
| S-23 Arguments follow the vectors | EP-19 |
| S-24 Reports carry no secrets | EP-13, EP-14 |

## Compatibility and versioning

- **Additive:**
  - the new method, action and reasons;
  - the event types, and the optional fields of existing events;
  - the blocks record of the watch stream;
  - the new properties and context fields;
  - the enumeration value `builtin`.
- **Not additive:**
  - the catalog file in bundles;
  - the required properties of tools;
  - resource IDs that are keys;
  - per-tool argument records, which replace the single `ToolArgs` record of `v1alpha1`.

  An enforcement point that does not support them rejects the new bundles and stays closed: incompatible, but safe.
- **When it lands.** No module verifies bundles or decides on tools yet (P1-09 has not started). This RFC therefore proposes to land in `v1alpha1` before `contracts/v0.1.0` is tagged (contracts, section 10: changes before the tag are free). If the tag comes first, the changes that are not additive make `v1alpha2`, served next to `v1alpha1`.
- **Vectors.** The `v1alpha1` combination vectors that pass tool arguments are rewritten with per-tool records.

## Security considerations

This RFC changes two trust boundaries:

- **TB-2** carries a new flow: tooling reports, from agents' processes into the core.
- **TB-1** shows their content to people.

Proposed additions to the threat model:

| ID | STRIDE | Threat | Mitigation |
| --- | --- | --- | --- |
| T-74 | S, T, D | An agent reports tooling it does not have, or hides tooling it has, to mislead reviewers or flood the catalog | Reports never authorize (CORE-10); limits and rate limits; new entries are inert until reviewed. Hiding a tool gains nothing, because calls are resolved when they happen and an unknown tool is denied |
| T-75 | T | Tool poisoning: a third-party server's description carries instructions for the model, or changes after approval | Reviewers see full definitions; approval pins their hash; a changed definition is denied and hidden from the model until approved (EP-16, EP-17) |
| T-76 | T, I | Reported text attacks reviewers through script injection, misleading names, or secrets left in command lines | Shown as plain text, with length limits and a strict Content Security Policy (NFR-12); redacted by the enforcement point and again by the core (EP-14, CORE-11); marked as reported |
| T-77 | S | Another server answers at an approved reference: DNS hijack, or a hijacked or unpinned package launched by `npx` | References identify, they do not authenticate. The agent's MCP client checks TLS; pinned definitions reveal changed tools; the catalog flags unpinned packages. The supply chain of MCP servers stays with the agent's owner (A-6) |
| T-78 | E | Usage rules are bypassed through how arguments are written: `..` segments, letter case, URL parser differences, missing arguments that the server fills in, unexpected types | Transforms with conformance vectors; missing arguments match by default; a value of the wrong type denies; no regular expressions. Documented limits: symbolic links, server-side defaults |
| T-79 | E, R | Provider-run tools act outside the agent's process | Exposure checked before every model call; declarations narrowed to enabled tools; each call decided where the provider asks for approval; global policies can forbid `origin == "provider"`; evidence from responses. What remains is the provider's own behavior |
| T-80 | D | Blocks or catalog changes slow halts, or flood enforcement points | Blocks travel in their own record, as deltas, with a cap; P1-08 measures halts with 500 blocks active; bundle rebuilds run in chunks (P1-06) |
| T-81 | D, E | An insider disables tools or blocks servers to disrupt agents, or undoes a block alone | Only roles that can already halt or suspend; a reason is required; everything is audited. Enabling and unblocking need a second person (HUM-04) |

**Unchanged risk.** An agent whose process is compromised can bypass its enforcement point (T-40). This RFC does not change that: the risk stays R-01, answered by network quarantine and, in Phase 2, by the gateways and the harness.

**Privacy.** Tool descriptions and schemas describe software, not people. Argument values used in decisions never reach evidence (contracts, section 8.3). URLs and command lines are redacted (EP-14, CORE-11).

**Proposed security tests:**

| ID | Test | Covers | Kind | Owner |
| --- | --- | --- | --- | --- |
| ST-75 | An enforcement point reports a new server and its tools; every call stays denied until the entries are approved and enabled | T-74 | integration | P1-16 |
| ST-76 | A server changes a tool's description; the tool is denied and hidden until its new definition is approved | T-75 | e2e | P1-09 |
| ST-77 | Canary secrets in MCP server URLs, arguments and environment never reach the core, its logs or events | T-76 | integration | P1-09 |
| ST-78 | Reported names and descriptions with markup and script render as text in the console | T-76 | e2e | P1-10 |
| ST-79 | The argument vectors (traversal, case, missing arguments, wrong types) give the expected decisions | T-78 | unit | P1-09 |
| ST-80 | A block reaches every enforcement point within the halt target and denies before policies; halts with 500 active blocks still meet NFR-03 | T-80 | integration | P1-08 |
| ST-81 | Nobody approves their own request to enable or to unblock | T-81 | integration | P1-16 |
| ST-82 | A model request that offers a provider-run tool that is not enabled, and cannot be narrowed, is denied | T-79 | unit | P1-09 |

## Alternatives

- **An MCP gateway in the MVP.**
  - In favor: it would also govern agents without the enforcement point.
  - Against: for governed agents, the enforcement point already sits on every call with no extra hop. A network gateway cannot see local servers, in-process functions or provider-run tools, and it is a new service in the data path, with its own latency and availability budget.
  - It stays in Phase 2, built on this RFC.
- **A White Tower MCP server that agents ask what they may use.** Agents would govern themselves, and nothing would be enforced.
- **The agent's reports as the source of truth.** A compromised or misconfigured agent would decide its own permissions.
- **Enablement as policy text generated for each agent.** Every switch would become a policy version waiting for approval, blocks could not take effect at once, and the generated policies would be long and hard to review. A catalog of signed data in the bundle keeps policies short and static.
- **Policies alone, without a catalog check.** A broad permit would override enablement. Enablement has to be a boundary that no policy can widen.
- **Skills to teach how.** A skill guides a model, but nothing checks that the model follows it. Usage rules are checked on every call.
- **Regular expressions in usage rules.** Cedar has only `like`, regular expression engines differ between Go and Python, and badly written expressions open the door to denial of service. Transforms cover paths, hosts and domains.
- **Blocks only through bundles.** Rebuilding every affected bundle is slower than the halt path. A record in the watch stream reaches every enforcement point as a halt does.

## Unresolved questions

1. Who approves catalog entries: the advisory committee, as proposed, or the steering committee, as for accepted providers (POL-10)?
2. Should adding a usage rule, which only restricts, take effect without approval, as blocks do?
3. Should an agent with non-production credentials be able to use every approved entry without enabling each one, to make onboarding easier?
4. Stateful rules (sequences of calls, counts per task, data flowing from one tool to another) are left to Phase 2. Which context fields should be reserved now?
5. Are the limits right: 256 servers, 4,096 tools and 256 models per report; 500 active blocks?
6. For agents without the enforcement point:
   - should the catalog import tooling from endpoint security tools (Phase 3 discovery)?
   - should it export an agent's enabled tooling to the allowlists that coding agents support?
7. Should usage rules support numbers that are not integers, through Cedar's `decimal`?

## Implementation plan

| Plan | Implements |
| --- | --- |
| P1-16 (new): MCP servers, tools and models | The catalog and its workflow, reports, enablement, blocks, the catalog file and the argument declarations in bundles, usage rules, events and API |
| P1-02 | The new event types in the event catalog |
| P1-06 | The `wt-catalog` policy, the check of `@rule` statements, and a Cedar schema per bundle |
| P1-07 | `ReportTooling`, blocks in the watch stream, the contract text, and the vectors and scenarios S-18 to S-24 |
| P1-08 | Blocks share the halt path's ordering; measuring halts with blocks active |
| P1-09 | In LangGraph and the second framework: discovery, references and redaction, the catalog check, exposure through the framework's middleware, provider-run tools, arguments and transforms |
| P1-10 | A new subplan, P1-10.7: MCP servers, Models, and the "MCP and Tools" tabs |
| P1-11 | `wtctl catalog` and `wtctl agents tooling` |

A follow-up pull request turns this into scope, once the maintainer confirms it:

- the requirements, with a new area for MCP servers, tools and models;
- the domain model, threat model and security tests;
- the plans index and the roadmap, which is re-baselined.

The skills repository leaves Phase 2. The `skills-repository` capability and the `skill` resource type stay reserved, so that nothing has to be renamed if skills return.
