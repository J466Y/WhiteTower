# RFC-0002: MCP servers, tools and models

| | |
| --- | --- |
| **Status** | Accepted provisionally on 2026-10-26 ([GOVERNANCE.md](../../GOVERNANCE.md#rfc-process)): this text at commit `2c37ac7`, after the maintainer's review (see [Review record](#review-record)). Its contract text, protobuf, schemas and vectors follow in step 12 of P0-03, before the tag `contracts/v0.1.0` |
| **Authors** | @J466Y |
| **Review period** | 2026-10-23 to 2026-10-26: the maintainer's provisional review, with no external reviewer. A review of at least two weeks, with an external reviewer, follows before the contracts leave alpha (`v1beta1`), with the findings of the live test of blocks (point 14 of the review) |
| **Related** | [RFC-0001](0001-module-contracts-v0.1.md) and its open question on tool arguments; [module contracts](../contracts/module-contract-v0.1.md), sections 4 to 8; requirements INV-07, POL-05, POL-06, MOD-06, KIL-01, UI-02, and the area this RFC adds: CAT-01 to CAT-10, NFR-24 and UI-10 ([requirements](../requirements/mvp-requirements.md#511-mcp-servers-tools-and-models-cat)); plans [P0-03](../plans/phase-0/P0-03-module-contracts.md) (step 12), [P1-16](../plans/phase-1/P1-16-mcp-servers-tools-and-models.md), [P1-06](../plans/phase-1/P1-06-policy-model-and-distribution.md), [P1-07](../plans/phase-1/P1-07-module-registry-and-api.md), [P1-08](../plans/phase-1/P1-08-kill-switch.md), [P1-09](../plans/phase-1/P1-09-python-enforcement-point.md), [P1-10](../plans/phase-1/P1-10-web-console.md), [P1-11](../plans/phase-1/P1-11-cli.md); [ADR-0005](../adr/0005-edge-enforcement-with-leases.md), [ADR-0011](../adr/0011-own-python-enforcement-point.md); [threat model](../security/threat-model.md) |

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

- **What an agent can do is delimited by its MCP servers, tools and models.** They are discovered and approved for the organization, can be blocked for it, and are enabled per agent.
- **How it may use them is delimited by policies**, with usage rules that forbid patterns of use. Skills, which teach a model how to use its tools, cannot be enforced, so the skills repository leaves Phase 2.
- **Both are part of the MVP.** P1-04, P1-06 and P1-09 have not started, so designing this in now costs least.

## Proposal

### 1. Principles

1. **Reports inform; they never authorize.** What an enforcement point reports about an agent's tooling fills the catalog. Only people, through approvals, make anything usable.
2. **The catalog says what; policies say how.** A tool or model must be enabled for the agent before any policy is evaluated. Policies can forbid more; they can never reach what is not enabled.
3. **Restricting takes effect at once; permitting needs a second person.** Blocking an entry, or disabling it for an agent, is immediate. Approving, enabling and unblocking need someone other than the person who asked (HUM-04). A usage rule restricts too, but it is policy text, so it waits for its policy's approval (section 8).
4. **Blocks never slow halts.** Organization-wide blocks reach enforcement points through the watch stream, as halts do, but in their own record.
5. **The enforcement point decides alone.** Everything it needs arrives in the signed bundle and the watch stream; it never calls the core to decide (EP-2).

### 2. Terms

| Term | Meaning |
| --- | --- |
| MCP server | A server that speaks the Model Context Protocol. It is either local (`stdio`, a process the agent launches) or remote (`http`, streamable HTTP or SSE) |
| Tool | Something a model can call. Its **kind** is `function` (the agent's own code), `mcp` (a tool of an MCP server), `builtin` (defined by the model provider, such as web search), `http` or `other` |
| Origin | Who runs the tool: `agent` (the agent's process, or an MCP server the agent connects to) or `provider` (the model provider, during a model call: its built-in tools, and the remote MCP servers it calls for the agent) |
| Model | A model the agent calls: provider, endpoint, name and, for self-hosted runtimes, the digest of its weights |
| Catalog | The organization's list of MCP servers, tools and models. Each **entry** is `discovered` or `approved`, and shows as blocked while a block covers it |
| Reference | How an enforcement point identifies an entry at runtime (section 3) |
| Key | The entry's name in policies and in the console, assigned by the core: `github`, `github/create_issue`, `agent/send_email`, `provider.openai/web_search`, `gpu-01/llama3.1-8b` |
| Definition | What the model sees of a tool: its name, description and schemas. Approval pins its hash. Built-in tools have none |
| Observed | The entries an enforcement point reported for an agent |
| Enabled | The tools and models an agent may use, approved for that agent; a server shows as enabled when one of its tools is |
| Block | An organization-wide denial of a server, a tool or models, effective at once |
| Usage rule | A forbidden pattern of use of a tool, written in a policy (section 8) |

### 3. References, keys and definitions

**References.** An enforcement point MUST compute references exactly as follows, so that they match the catalog's:

| Entry | Reference |
| --- | --- |
| Remote MCP server, called by the agent or by its model provider | The server's URL, normalized as below, after the redaction of EP-14 |
| MCP server hosted by the model provider and named by an ID rather than a URL | `connector:<provider>/<connector ID>` |
| Local MCP server | `stdio:` followed by the RFC 8785 canonical JSON of the array of its command and arguments, as configured, after the redaction of EP-14 |
| Tool | Its server's reference and the tool's name. A function, `http` or `other` tool: its name alone. A built-in tool: the provider and the tool's type |
| Model | The provider, a value of the contracts' table of model providers (section 6.3), such as `openai`, `anthropic` or `ollama`; the base URL of the endpoint the agent calls, normalized as below, even when it is the provider's default; and the model's name as requested |

**Normalized URLs.** A remote server's URL and a model's endpoint are normalized as follows, so that two enforcement points that read one URL write one reference:

1. The URL is read as the `url_host` transform reads it (section 7.5), which also gives its host, and its scheme is `http` or `https`. A URL that this cannot read, or with a backslash in its path, makes no reference: the server or the model is not reported, and its calls are `catalog.unknown`.
2. User information, query and fragment are removed.
3. The scheme is written in lowercase, the host as `url_host` gives it, and the port only when it is not the scheme's default (80 for `http`, 443 for `https`).
4. In the path, a character that RFC 3986 does not allow there is percent-encoded as UTF-8. Percent-encoding is then normalized as RFC 3986 says in section 6.2.2 (hexadecimal digits in uppercase, unreserved characters decoded), and dot segments are removed as its section 5.2.4 says. An empty path is written `/`; any other trailing slash stays as written.

For example, `HTTPS://API.Example.COM:443/mcp/./tools/../%7euser/` becomes `https://api.example.com/mcp/~user/`.

**What a reference covers.** A reference names what an enforcement point can report without secrets. It leaves out a URL's user information, query and fragment, the values that redaction replaces (EP-14), and a local server's environment variables. Configurations that differ only in those share one reference, and one approval covers them all: a server that takes its roots or its database from environment variables, or a remote server whose query names a tenant, is one entry whatever they hold.

**String form.** A server's reference is a string. A reference with several parts is written as the RFC 8785 canonical JSON of an object of those parts:

| Entry | String form |
| --- | --- |
| MCP tool | `{"name":"create_issue","server":"https://api.githubcopilot.com/mcp/"}` |
| The agent's own tool | `{"name":"send_email"}` |
| Built-in tool | `{"provider":"openai","type":"web_search"}` |
| Model | `{"endpoint":"http://gpu-01.internal:11434/","name":"llama3.1:8b","provider":"ollama"}`, and for a model of a provider's default endpoint, `{"endpoint":"https://api.openai.com/v1","name":"gpt-4o","provider":"openai"}` |

The vectors use these forms. Blocks and events name a reference by the SHA-256 of the UTF-8 bytes of its string form (sections 6 and 9).

**Keys.** The core assigns each entry a key the first time it sees the entry, and the key never changes once the entry is approved. The agent's own tools are entries of their agent: their keys are unique within the agent, because the same name in two agents is different code. Every other key is unique in the catalog:

- **Servers:** a slug of lowercase letters, digits and hyphens, at most 63 characters, derived from the name the server announces or from its host, never from a command line, whose paths can hold a user name: events carry keys in clear.
- **Tools:** `<server key>/<tool name>`. Two server keys are reserved: `agent`, for the agent's own tools, and `provider.<provider>`, for a provider's built-in tools.
- **Models:** a slug of their provider or endpoint, a slash, and a slug of their name, which keeps its dots (`gpu-01/llama3.1-8b`). For an endpoint that the core knows as its provider's default, the slug is the provider's (`openai/gpt-4o`): a table of the core's own, which shapes only the key, never the reference.

**Definitions.** A definition hash is the lowercase hexadecimal SHA-256 of the canonical JSON of the following members, leaving out those that are absent or `null`:

- **MCP tool:** the members `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations` of the tool, as the `tools/list` result carries them in the JSON-RPC message itself. SDKs turn tools into objects that add defaults or drop members, so their objects are not the input.
- **Function, `http` or `other` tool:** its name and the JSON Schema of its parameters, as the framework presents them to the model. Their descriptions belong to the agent's own code, which its owner controls ([threat model](../security/threat-model.md), A-6).

The canonical JSON is RFC 8785's, with one extension. RFC 8785 covers I-JSON, whose integers stop at 2^53 - 1 (contracts, section 1), and tool schemas often hold larger ones, such as 18446744073709551615, the bound of an unsigned 64-bit field. A library that rounds it, as `gowebpki/jcs` does (it writes 18446744073709552000), gives a hash that the other stack does not compute, and two schemas that differ only in such a number hash alike; one that refuses it makes the tool unusable. So **a number written without a fraction or an exponent is written as its exact value in decimal**, with `-0` as `0`: within ±(2^53 - 1), this is what RFC 8785 writes. Any other number is written as RFC 8785 says. A number that is not finite as a double, a member name that repeats, or a string with a lone surrogate leaves the definition without a hash. A tool without a hash is reported without one and can never be approved, so its calls are denied (`catalog.not_approved`, or `catalog.definition_changed` once another definition is pinned).

A built-in tool has no definition. The provider versions it in its type, which is part of its reference, and what a declaration configures belongs to the agent's code (A-6).

The core recomputes every hash from the members it receives (section 4.1), so the hash that approval pins is that of what reviewers saw.

### 4. Discovery

#### 4.1 `RegistryService.ReportTooling`

A new method of the registry service, idempotent. Only an instance of a module that declares the `enforcement-point` capability calls it, and only for an agent in its scope:

| Field | Meaning |
| --- | --- |
| `instance_id` | The reporting instance |
| `agent_id` | The agent the tooling belongs to, in the instance's scope |
| `servers` | Each MCP server: reference, transport (`stdio` or `http`), origin, the name and version it announces, and a display form (its URL or command line, redacted) |
| `tools` | Each tool: kind, origin, its server (MCP tools, named by the server's position in `servers`) or its provider and type (built-in tools), its name and, except for built-in tools, its definition hash, when its definition has one (section 3) |
| `models` | Each model: provider, endpoint, name and, when the runtime reports one, digest |

The core refuses as a whole, with `PERMISSION_DENIED`, a call from a module that does not declare the capability, from an instance that the caller's principal did not register, or about an agent outside the instance's scope, as CORE-2 says for the module API's other methods.

A report is complete: it replaces the instance's previous report for that agent. Its response lists the definition hashes the core does not have.

**`RegistryService.ReportDefinitions`**, also idempotent, and called by the same instances under the same rules, carries the calling instance's `instance_id` and those definitions: for each, the members that section 3 hashes, taken as section 3 says, within the contracts' message limit (section 4.8). The core recomputes each hash and stores the definition under it. A definition whose hash matches none that this instance's current reports name, for any of its agents, is refused on its own and listed in the response, and the others are still stored, as CORE-2 says for the items of a call. Definitions are content-addressed, so each is sent once, whatever the number of agents, instances and restarts. They travel apart from reports because a report carrying every description and schema could exceed the message limit many times over.

- **EP-13. Report tooling.** Report the agent's tooling as soon as it is known; the first report SHOULD come before the gate first opens. Report again whenever it changes, for example when:
  - an MCP server connects, or announces a changed tool list (`notifications/tools/list_changed`);
  - a model is called for the first time;
  - a model request declares a provider-run tool not reported yet.

  Report what the agent is configured with, not only what it has called. Then send the definitions the core asks for.

  Keep at most one report per agent in flight. Retry a report that failed, or that the core refused, with the agent's tooling as it is when the retry is sent, never as it was: each report replaces the one before it, so an older report that arrived late would undo a newer one. Leave out of a report, and log, what is over the limits of section 4.2: the servers, tools and models beyond its counts, and those whose strings, or whose definition, are over their limits. A server left out takes its tools with it. An instance that calls in JSON, whose escapes can make a report at the limits larger than the message limit, leaves out what does not fit the same way. Report `HEALTH_DEGRADED` while anything is left out (contracts, section 4.9): what is left out stays unknown, so its calls are denied (`catalog.unknown`).
- **EP-14. Redact.** Never report environment variables, HTTP headers, authorization values or any other credential. Remove user information, query and fragment from URLs, including URLs passed as command-line arguments. Replace with `<redacted>` the value of any command-line argument that follows a flag, or is written `--flag=value`, when the flag's name contains, in any case, `token`, `secret`, `password`, `passwd`, `key`, `auth`, `credential` or `cookie`.

  Apply also the deployment's redaction rules, which the catalog file carries (section 5). In a URL that, normalized as section 3 says, starts with one of their prefixes, replace the path segment that follows the prefix with `<redacted>`, and write the URL normalized, also where it is a command-line argument. Treat the flags they name, each matched exactly without its leading dashes, like those above. Apply them to everything reported and to the references computed, so that references match the catalog's. Until a bundle is active, an instance has no rules and reports without them: the core applies them (CORE-11).

#### 4.2 What the core does

- **CORE-10.** The core MUST treat reports as observations. A report MUST NOT approve, enable or unblock anything, and MUST NOT change an approved definition.
- **CORE-11.** The core MUST apply the redaction of EP-14, with the deployment's redaction rules, again before it stores or logs anything from a report, and MUST NOT copy reported descriptions, schemas or references into audit events, which name references only by their SHA-256 (section 9). When an administrator adds a rule, the core applies it to the references the catalog already holds (P1-16).
- **CORE-13.** The core MUST bound, for each agent, what the agent's reports brought that still waits for review: new entries of each kind, and new definitions and digests of known entries. Beyond the bound, it still records the report but leaves out what is new, and says how much in its response. A new entry left out stays unknown (`catalog.unknown`); a new definition or digest left out is not stored, so the tool or the model stays denied (`catalog.definition_changed`, `catalog.digest_mismatch`). Both last until reviewers approve or decline enough of what the agent brought. The bound is one report's worth by default (256 servers, 4,096 tools and 256 models, and as many new definitions as tools), and administrators can change it. A compromised agent therefore cannot make the catalog, or the reviewers' queue, grow faster than people decide.
- **New entries.** A reference the catalog does not have becomes a `discovered` entry; the agent's own tools become entries of that agent. When a tool's reported definition differs from the approved one, the approved definition stays pinned and the new one waits for review. A model's new digest is handled the same way: the pinned digest stays, and the new one waits for review.
- **Observations.** For each agent, the core keeps the entries observed and when each was last seen. The console can then show tooling waiting for a decision, and enabled tooling the agent no longer has.
- **Limits (contracts, section 4.8).**
  - A report holds at most 256 servers, 4,096 tools and 256 models.
  - References, endpoints and display forms are at most 2 KiB each, names at most 256 bytes, and versions, providers, built-in tools' types and digests at most 128 bytes, so a full report fits in the 4 MiB message limit in binary protobuf, at about 3.8 MiB. In JSON, escapes can make it larger (EP-13).
  - Each description is at most 16 KiB, each schema at most 64 KiB, each title at most 256 bytes, and each tool's annotations at most 4 KiB.
  - The core refuses as a whole, with `INVALID_ARGUMENT`, a report or a `ReportDefinitions` call over these limits: an enforcement point leaves out what does not fit them (EP-13).
  - The core MAY refuse, with `RESOURCE_EXHAUSTED`, more than one report per instance and agent every 10 seconds. The instance retries a refused report with the backoff of the contracts' other calls, no sooner than the error's `RetryInfo` says (contracts, section 4.7), and with the agent's current tooling (EP-13).

### 5. The catalog in the bundle

Each agent's bundle carries a catalog file, `catalog.json`, listed in the bundle manifest like the Cedar schema (`catalog`, with its path and SHA-256). It is activated with the policies, atomically, and holds the entries enabled for the agent and those observed for it, and the deployment's redaction rules:

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

- **Status and enablement.** `status` comes from the catalog and is `discovered` or `approved`; `enabled` comes from the agent's enablement. An agent is enabled to use tools and models, so servers carry no `enabled` field, and a tool of an MCP server can be approved only once its server is. Blocks never appear in the file: they travel in the watch stream (section 6).
- **Pinned values.** `definition` and `digest` are pinned when the entry, or its new definition or digest, is approved.
- **Classification.** `read_only`, `destructive` and `open_world` are set by the reviewer. They start from the tool's MCP annotations, or, when those are absent, from the protocol's conservative defaults: not read-only, destructive, open world. Annotations are hints from the server; the catalog's values have been reviewed.
- **Arguments.** `args` lists the tool's arguments that policies may see (section 7.5): each with its name, which is its key in `context.args`; its path, as the array of the property names that lead to it; its transform, when it has one; and its type.
- **Redaction rules.** `redaction` carries the deployment's redaction rules (EP-14): URL prefixes, after each of which the next path segment is a secret, and flag names whose values are secrets, beyond those EP-14 lists. Some services put an account's secret in a URL's path, as Zapier's MCP server does. The rules are a setting of the platform administrator (P1-16, through the API of P1-17), and a change rebuilds every bundle.
- **Size.** The core keeps every bundle within the limit of step V1 (2 MiB). The entries enabled for the agent come first: a request to enable an entry that would take the agent's bundle over the limit is refused, with that reason. Entries observed but not enabled are listed while they fit, those seen most recently first; one left out is denied as `catalog.unknown`, the decision it would get anyway, with a less precise reason. A tool takes a few hundred bytes of the file: an agent with 300 tools has a file of about 130 KiB, while one at the limits of a report (section 4.2) would need from about 1.8 MiB, with short references, to 4.5 MiB. When the enabled entries and the policies alone do not fit, the core publishes no bundle: the agent keeps the one it has, and the console says why (P1-06).
- **Every bundle carries one,** empty when nothing is observed or enabled for the agent. An enforcement point that supports catalogs treats a bundle without one as an empty catalog: every tool and model action is then `catalog.unknown`.
- **Format.** The decision profile gains a JSON Schema of the file, `whitetower.catalog.v1`.
- **Verification.** Step V4 accepts the manifest's `catalog` field, step V5 requires its file, and step V7 parses it against its schema (`parse_error`). An enforcement point that does not support catalogs rejects such a bundle (`invalid_manifest`): it keeps its last valid bundle or, with none, stays closed, and it never activates a bundle built after this RFC (contracts, section 7.6).

### 6. Blocks

A block denies, for every agent and at once, one of:

- an MCP server and all its tools;
- a single tool;
- a model;
- every model of a provider or of an endpoint.

A block of one of the agent's own tools covers that name in every agent.

Blocks name references, not keys, so an enforcement point applies them without waiting for a new bundle. They never change an entry's status and never travel in bundles, so issuing or lifting one rebuilds no bundle, and lifting one leaves the entry as it was.

How blocks travel:

- **In their own record of the watch stream.** A snapshot carries every active block, and changes carry the blocks added and the IDs of those removed. The first part of a snapshot carries the record, with the fleet state, and a snapshot's record replaces the instance's whole set of blocks. A change adds the blocks it carries, replacing one whose ID the instance knows, and removes the IDs it lists, ignoring those it does not know. Only enforcement points' streams carry the record. A block (`Block`) carries its ID, its kind (`server`, `tool`, `model`, `provider` or `endpoint`), the SHA-256 of what it covers and its issue time. What it covers is hashed as the UTF-8 bytes of its string form (section 3): the reference of a server, a tool or a model, the name of a provider, or the normalized base URL of an endpoint. Hashes keep blocks small, and keep local paths out of a record that every enforcement point receives; the references and the reasons stay in the core, which shows them. Enforcement points compute the hashes of an entry once, when a tool list or a model changes, never on each call.
- **Versions.** Blocks take their versions from the same version counter as the rest of the state ([the design of the halt path](../plans/phase-1/P1-08-kill-switch.md#progress-notes), section 2), so a lease renewal still means "your state is current" (CORE-6).
- **CORE-12.** A block is committed, and the stream updated, without waiting for any bundle, as for halts (CORE-8).
- **EP-15. Blocks.** Apply a block as soon as it arrives. It denies every later call to, exposure of, and result from what it covers (section 7.1). A block of a kind the enforcement point does not know denies every tool and model call while it is active. Then acknowledge at once a state version at or above the one that carries the block, for at least one agent the instance serves, without waiting for the 60 seconds that EP-12 allows: it covers every earlier block, and the per-agent acknowledgements of EP-12 follow at their own pace. From these acknowledgements, the console shows how far each block has spread, as it does for halts.
- **Halts stay fast.** Blocks never enlarge the fleet record that fleet halts change, so a fleet halt costs the same with or without blocks. The core caps active blocks at 500, about 40 KB in a snapshot, which keeps them within one watch message. P1-16 measures halt propagation with that many blocks active, with the harness of P1-08.

**Provisional.** The rules of the record and EP-15's acknowledgement are applied provisionally: the maintainer decided on 2026-10-26 that a live test, with real enforcement points in a real environment, confirms them before the contracts leave alpha (`v1beta1`). The end-to-end test of P1-09 runs it (its step 14), and its findings go to the review that precedes `v1beta1`.

### 7. Decisions

#### 7.1 The catalog check

For `tool.invoke`, `tool.expose` (section 7.3) and `model.invoke`, an enforcement point checks the catalog after the gate (contracts, section 5.4) and before policies. It denies with the first reason that applies:

| Order | Condition | Reason |
| --- | --- | --- |
| 1 | A block covers the server, the tool or the model | `catalog.blocked` |
| 2 | The bundle's catalog does not list it | `catalog.unknown` |
| 3 | Its status is `discovered` | `catalog.not_approved` |
| 4 | It is not enabled for the agent | `catalog.not_enabled` |
| 5 | The tool's definition, as the agent has it now, differs from the pinned one | `catalog.definition_changed` |
| 6 | A digest is pinned for the model, and the runtime's digest differs or is unknown | `catalog.digest_mismatch` |

Blocks come first, so they also cover entries the bundle does not list. A catalog denial carries the bundle's version, because the catalog is part of the bundle, and no determining policies. For `tool.result` and `model.result`, which an enforcement point SHOULD evaluate (contracts, section 6.3), only row 1 applies: a block issued while a call runs keeps its result from the agent and its model.

Among the reasons of the contracts' section 6.6, the catalog check comes after `error.unknown_agent`, since it needs the agent's bundle, and before `error.invalid_request`, since the arguments' types, and what transforms can read, come from the catalog (EP-19). The order is therefore the gate, `error.unknown_agent`, the catalog check, `error.invalid_request`, `error.timeout`, then rules 1 to 4.

- **EP-16. Catalog check.** Apply the catalog check to every `tool.invoke`, `tool.expose` and `model.invoke`, and its first row to every `tool.result` and `model.result` evaluated. Resolve the tool or the model by its reference at the time of the call, never by its name alone. Anything that cannot be resolved is `catalog.unknown`. A decision with a `catalog.*` reason carries `bundle_version`, as the policy reasons do (contracts, section 6.6), and no determining policies. It names tooling that the catalog does not list by its name as the agent sees it, with the SHA-256 of its reference, and a block by its ID (section 9).

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

The steering committee approves it like any global policy, and may narrow it, for example to non-production credentials. Every bundle carries a catalog (section 5), so an enforcement point that does not know catalogs rejects the bundle rather than apply the permit without the check.

#### 7.2 Resources and context

With a catalog, a resource's ID is its key, and its properties come from the catalog, never from the agent:

| Resource | Properties |
| --- | --- |
| `tool` | `kind`, `origin`, `name`, `read_only`, `destructive` and `open_world`; for MCP tools, also `server` (the server's key) and `transport`; for built-in tools, also `provider` |
| `model` | `provider`, `name` and `endpoint` |

In Cedar, an MCP tool's parent is its server, `WhiteTower::McpServer::"<key>"`, so that a policy can name a whole server: `resource in WhiteTower::McpServer::"github"`. The context of `model.invoke` gains `digest`, when the runtime reports one.

#### 7.3 `tool.expose`

This RFC adds a ninth action: a tool is offered to a model.

| Action | Resource type | Evaluation |
| --- | --- | --- |
| `tool.expose` | `tool` | MUST, for every provider-run tool, and for every tool of a model request where the framework lets the enforcement point change the request's tools |

Its context carries `calls_decided`: true when every call of the tool will be decided as `tool.invoke` before it runs. That holds for the tools the agent runs, and for a provider-run tool only while the provider submits each of its calls to the agent for approval (section 7.4). A usage rule forbids exposing a tool whose calls are not decided (section 8), so that no rule is approved and then never applied.

- **EP-17. Exposure.** Before each model call, evaluate `tool.expose` for every tool the request offers, with `calls_decided` set as above, and remove the denied ones from the request. When a denied tool cannot be removed:
  - deny the model call if the tool is provider-run, because the provider would call it without passing through the agent;
  - deny the model call if the denial is `catalog.definition_changed`;
  - otherwise, the enforcement point SHOULD deny the model call.

  Exposure decisions MAY be reused until the bundle, the agent's state, the blocks, the tool's definition or whether its calls are decided change, or until the instance registers again, since its registration gives the subject's environment (contracts, I-7). A model call therefore normally costs no evaluation. An exposure decision is recorded when it is evaluated; reusing it writes nothing. Policies on `tool.expose` therefore SHOULD NOT read the context, except `calls_decided`: its other fields, such as the time and the task, change between the model calls that reuse a decision.

A changed, possibly poisoned, description never reaches the model. Where the framework allows it, neither does any tool the agent may not use.

#### 7.4 Provider-run tools

The enforcement point sees a provider-run tool twice: declared in the model request, and in the response once it has run.

- **EP-18. Provider-run tools.**
  - Narrow each declared remote MCP server to the tools enabled for the agent, for example by setting the declaration's list of allowed tools.
  - Deny the model call when it would let the provider call a tool that is not enabled.
  - Where the provider can submit each call of a provider-run tool to the agent for approval, have it do so for every such tool that a usage rule of the bundle names (the tools that the `@rule` annotations of its policies list, section 8), and MAY for the others. Evaluate `tool.invoke` for each submitted call, with its arguments, and answer with the decision.
  - Record the provider-run calls that a response reports as `action.executed` events with origin `provider`.
  - When a response lists a provider-run MCP tool whose definition differs from the pinned one, deny its exposure from then on (`catalog.definition_changed`).

The provider lists a remote server's tools itself, so the enforcement point learns of a changed definition only from a response, after the model may have seen it once. The threat model records this residual (T-79).

#### 7.5 Arguments policies see

This section answers RFC-0001's open question on tool arguments.

- **Which arguments.** Policies see two sets of a tool's arguments: those that the usage rules of the agent's effective policy set use, and those a reviewer declared for the tool in the catalog. The core lists them in the catalog file (`args`) and declares them in the bundle's Cedar schema. A policy version with a statement that reads any other argument is refused when it is submitted: enforcement points never fill that argument, so the condition could never hold.
- **Declarations stay stable.** A declaration that an active policy version reads cannot be withdrawn, and a declared argument's type cannot change while an active usage rule uses it. A new definition that gives the argument another type can still be approved; a value that does not fit the declared type then denies the call (EP-19).
- **One record per tool.** `context.args` holds one record per tool, keyed by the tool's key, with the declared arguments inside: `context.args["github/create_pull_request"]["base"]`. Per-tool records keep types unambiguous: `id` can be a number for one tool and a string for another. The arguments of the agent's own tools (`agent/<name>`) are declared only in that agent's schema, because the same name can mean other arguments in another agent: global policies, and their usage rules, cannot read them.
- **Naming.** An argument is named by its path in the call's arguments, for example `options.base` for a nested field. When a transform applies, a colon and the transform's name follow: `path:path`, `url:url_host`. A path goes through objects only, never into an array's elements, and a property whose name contains `.` or `:` cannot be declared, so that a name reads only one way.

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
3. The path is split at slashes. Empty segments and `.` are dropped. `..` removes the segment before it, is dropped at the root of an absolute path, and is kept at the start of a relative one.
4. An absolute path is written with one leading slash, a relative one without. An empty result is `/` for an absolute path and `.` for a relative one. Drive letters and UNC names are ordinary segments: `C:\Windows\..` becomes `C:`.

For example, `//srv/./data/../../etc/passwd` becomes `/etc/passwd`.

**`url_host`** reads the host of a URL. Parsers disagree on some URLs: Python's `urllib.parse` reads `http://evil.com\@good.com/` as `good.com`, while requests and Node's WHATWG parser read `evil.com`.

1. Leading and trailing spaces and C0 control characters (U+0000 to U+001F) are ignored, as WHATWG's and Python's parsers do. A control character (U+0000 to U+001F, U+007F) anywhere else cannot be read.
2. The URL starts with a scheme and `//`, whatever the scheme. A value without them, such as `example.com`, cannot be read: tools complete it in different ways.
3. The authority runs to the first `/`, `?` or `#`. A backslash or whitespace in it cannot be read.
4. User information is ignored: the host follows the last `@` of the authority, as every parser reads it.
5. A port, after the host, is 1 to 5 digits, and at most 65535.
6. An IPv6 address, in brackets, is written as RFC 5952 says, in brackets. One with a zone ID cannot be read.
7. Any other host that has a `%` cannot be read. The rest is converted to A-labels as WHATWG's "domain to ASCII" does without strictness: UTS #46, non-transitional, without the STD3 rules, so that underscores pass, and with joiners and Bidi checked. An A-label that does not decode cannot be read. The host is then in lowercase and loses one trailing dot; one with an empty label, or with any character but letters, digits, `.`, `-` and `_`, cannot be read.
8. A host whose last label is then a number (decimal digits, or `0x` and hexadecimal digits) is an IPv4 address, and must be four decimal numbers from 0 to 255 without leading zeros: `0x7f.1`, `2130706433` and `127.1`, which parsers and resolvers take to 127.0.0.1, cannot be read.

**`email_domain`** reads the domain of an address.

1. Leading and trailing spaces are ignored. A control character cannot be read.
2. The value is an address; `Display Name <address>`, with no quote, angle bracket, `@`, `,`, `;`, `:`, parenthesis, square bracket or backslash in the name; or `"Quoted Name" <address>`, with no quote or backslash between the quotes.
3. The address has exactly one `@`, and its local part no whitespace, quote, parenthesis, angle bracket, square bracket, backslash, `,`, `;` or `:`. A `,` or `;` cannot be read: several addresses in one string, of which a rule would see only one.
4. The domain is read as `url_host` reads a host, but neither an IPv6 address nor a domain literal (`[192.0.2.1]`) nor a domain whose last label is a number can be read.

Legitimate values that these rules refuse are rare: a URL without a scheme, a quoted local part, a domain literal. A tool that takes several recipients in one string has those calls denied by any rule on `email_domain`; one that takes them as an array does not.

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

  // Every model has all three, from the catalog.
  entity Model {
    provider: String,
    name: String,
    endpoint: String       // the normalized base URL of the endpoint
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

  type ExposeContext = {
    time: datetime,
    task_id?: String,
    trace_id?: String,
    on_behalf_of?: String,
    calls_decided: Bool    // every call of the tool will be decided as tool.invoke
  };

  action "tool.expose" appliesTo { principal: Agent, resource: Tool, context: ExposeContext };
  action "model.invoke" appliesTo { principal: Agent, resource: Model, context: ModelContext };
}
```

### 8. Usage rules

A usage rule forbids a pattern of use of one or more tools. It replaces what skills would have taught, and is enforced on every call: a tool with a rule is offered to a model only when each of its calls will be decided (section 7.3).

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

A rule compiles to two Cedar `forbid` statements per tool. Each is annotated with `@rule`, the canonical JSON of the rule's ID and description, the statement's tool and the rule's conditions, so that an annotation grows with the conditions, never with the number of tools. One statement forbids the calls that match the conditions; the other forbids offering the tool to a model while its calls are not decided (section 7.3):

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

- **Ordinary policies.** Rules live in ordinary policies, global or agent-specific, and follow the same approval workflow: adding a rule needs the same approvals as any other policy text (unresolved question 2). The console edits them as forms. Each statement carries its rule in the annotation, so the policy text is the only source of truth.
- **Generated text is checked.** The statements of one policy whose annotations carry a rule's ID make up the rule: they carry the same description and conditions, and both statements of each of its tools. When a policy version is submitted, the core regenerates each statement that carries `@rule` from its annotation, and refuses the version unless every statement equals, once parsed, what the generator produces, and every rule is whole. The annotation's JSON is written as a Cedar string, its quotes and backslashes escaped with a backslash. A reviewer can therefore trust the form the console shows. The generator takes each argument's type from the catalog's declarations, because a condition compiles differently for a string and for a set.
- **Evidence names the rule.** Decision events name each rule that decided by its policy and its rule ID (section 9), so the audit log says "denied by `no-push-to-main`".
- **Limits.**
  - Cedar's `like` is the only pattern language, so rules can use no regular expressions.
  - Rules are stateless: sequences of calls and counts per task are left to Phase 2.
  - A path is cleaned lexically, so symbolic links on the server are not resolved. Path rules are therefore safe as allow-lists, `not_matches` on the directories a tool may use: a relative path or a symbolic link escapes a deny-list such as `matches "/etc/*"`.

### 9. Events

New event types emitted by the core:

| Type | Subject | When |
| --- | --- | --- |
| `whitetower.catalog.discovered.v1` | None | A report brought entries the catalog did not have. The event lists their keys and the SHA-256 of their references, and names the reporting instance |
| `whitetower.catalog.approved.v1` | None | An entry, a new definition of a tool or a new digest of a model was approved, with the pinned hash or digest and the classification |
| `whitetower.catalog.declined.v1` | None | A reviewer declined an entry, a new definition or a new digest, with the reason. It stays not approved, and leaves the queue of what waits for review |
| `whitetower.catalog.definition_changed.v1` | None | A reported definition or digest differs from the approved one; the event carries both hashes, or both digests, and names the reporting instance |
| `whitetower.catalog.blocked.v1` | None | A block was issued, with its ID, its kind, the SHA-256 of what it covers and the key of the entry it covers when the catalog has one, the state version that carries it, its reason and its issuer |
| `whitetower.catalog.unblocked.v1` | None | A block was lifted, with its ID, the state version, the requester and the approver |
| `whitetower.tooling.enabled.v1` | Required | Entries were enabled for an agent, with the requester and the approver |
| `whitetower.tooling.disabled.v1` | Required | Entries were disabled for an agent, with the person who disabled them and the reason |
| `whitetower.tooling.observed.v1` | Required | The tooling observed for an agent changed: keys added and removed, and the reporting instance or the person who declared it |

Events name references only by their SHA-256, so that a local server's command line, which can hold a user name, stays out of the audit log, and they carry no description or schema. The hash is not a pseudonym, though (Privacy, under Security considerations). An event lists at most 100 entries or keys, so that it stays within the 64 KiB of an event (contracts, section 4.8); more take several events. The events a report causes have the system as their actor.

Events from enforcement points gain optional fields:

- `decision.made` gains the usage rules that decided, each named by its policy ID and its rule ID, and the resource's origin.
- `decision.made` and `action.executed` gain `reference_sha256`, the SHA-256 of the string form of the resource's reference, for tooling that the catalog does not list: the resource's `id` is then its name as the agent sees it, and the hash is the one that `catalog.discovered` carries, so the console links the event to the entry. `decision.made` also gains `block_id`, for `catalog.blocked`.
- `action.executed` gains the origin. Its `decision_id` becomes optional, and is absent for the provider-run calls that no decision preceded.

### 10. Outside the contracts

These parts are not contract, but reviewers need them to judge the whole.

**Roles.** The permission matrix gains these rows, which plan P1-16 adds to `internal/authz` (the administrator, who may view, is left out of the table):

| Action | Steering | Advisory | Owner | Operator | Auditor |
| --- | :-: | :-: | :-: | :-: | :-: |
| View the catalog and each agent's tooling | ✔ | ✔ | ✔ | ✔ | ✔ |
| Approve or decline an entry, a new definition or a new digest, classify it, and declare the arguments policies see | | ✔ | | | |
| Block an entry, at once and with a reason | ✔ | ✔ | | ✔ | |
| Request to unblock | ✔ | ✔ | | ✔ | |
| Approve unblocking (not the requester) | ✔ | ✔ | | | |
| Request enabling for an agent | | ✔ | own | | |
| Approve enabling (not the requester) | | ✔ | | | |
| Disable for an agent, at once | | ✔ | own | ✔ | |
| Declare the tooling of an agent without the enforcement point | | | own | ✔ | |

Usage rules follow the policy rows of the matrix: global rules are global policies, and agent rules are agent-specific policies. A break-glass session can halt, but it cannot block (HUM-06).

**Console:**

- **MCP servers:** the catalog's servers, with their status, transport, tools, the agents that use them, and when they were first and last seen. A server's page shows its tools, their definitions (changes as diffs), their classification and their history, with the actions to approve, decline, block and unblock. A declined entry stays denied, and leaves the queue of what waits for review; reviewers can also decline at once every entry that waits for review from one agent.
- **Models:** the same for models, with endpoints and digests.
- **"MCP and Tools" on each agent:** its servers, tools and models, each marked observed, enabled or both, with switches to request enabling and to disable. The tab also shows the usage rules that apply to each tool, the enabled tooling the agent no longer has, and the tools waiting for review.
- **"MCP and Tools" on each model:** the provider-run tools seen with the model, and the agents that use them.
- **Reported text** is shown as plain text, marked as reported by the agent.

**API and CLI.** Every function is in the public API (API-01) and in `wtctl` (`wtctl catalog`, `wtctl agent tooling`). The API also compiles a usage rule into its statements, so that the console and policy-as-code repositories never need a compiler of their own.

**Agents without the enforcement point** (coverage C0 and C1). Their owners, or operators, can declare their tooling in the catalog, so the inventory is complete, but nothing enforces it.

The Phase 2 MCP gateway will enforce it, as another enforcement point that uses this same catalog, its blocks and its rules, and discovers the servers agents reach through it. A network gateway cannot see local servers, in-process functions or provider-run tools. That is why the enforcement point is the MVP's control point.

**Lifecycle.** Enabling tooling is part of "policy and harness assignment", between `validated` and `ready`. Periodic reviews (INV-06) list enabled tooling the agent has not used recently, as candidates to disable.

### 11. Conformance

New vectors cover:

- references, normalized URLs, their string forms, and redaction, with the deployment's rules;
- definition hashes, which the Go and Python stacks must compute alike, with integers beyond 2^53, `null` members, repeated names and lone surrogates;
- the catalog check, its order and its place among the reasons, blocks included, on results too;
- transforms, with the values each one cannot read, missing arguments and types;
- usage rules: the operators each type takes, the statements the generator produces, and the decisions they give;
- exposure, with calls decided and not decided;
- bundles with a catalog file.

The combination vectors that use a tool or a model gain a catalog, and their resource IDs become keys.

New scenarios:

| Scenario | Obligations |
| --- | --- |
| S-18 A report makes nothing usable | CORE-10, EP-16 |
| S-19 Unknown, discovered, disabled and blocked tooling is denied with its reason, before policies | EP-16 |
| S-20 A block denies within the halt propagation target, timed as section 9.2 of the contracts says, without a new bundle, and is acknowledged once applied. The result of a call in flight when it arrives does not reach the agent, where the module evaluates `tool.result`, and a snapshot that no longer carries the block lifts it | EP-15, CORE-12 |
| S-21 A tool whose definition changed is denied and not exposed | EP-16, EP-17 |
| S-22 Only exposed tools reach the model; a provider-run tool that cannot be removed fails the model call | EP-17, EP-18 |
| S-23 Arguments follow the vectors | EP-19 |
| S-24 Reports carry no secrets | EP-13, EP-14 |
| S-32 Provider-run tools follow EP-18, with a model provider that the kit plays. Declared remote servers reach the provider narrowed to the tools enabled for the agent, and a request that would let it call another tool is denied. The calls it submits for approval are decided as `tool.invoke`, with their arguments, and answered with the decision, and a tool that a usage rule names is offered only while its calls are submitted. The calls its responses report yield `action.executed` with origin `provider`, and a response that lists a tool whose definition changed stops the tool's exposure | EP-17, EP-18 |

S-25 to S-31 are RFC-0001's. The kit plays S-32's model provider at the endpoint that the driver gives the agent's model, and scripts the tools it lists, the calls it submits for approval and those it reports.

## Compatibility and versioning

- **Additive:**
  - the new methods, action and reasons;
  - the event types, and the optional fields of existing events;
  - the new properties and context fields;
  - the enumeration value `builtin`.
- **Not additive:**
  - the catalog file in bundles;
  - the blocks record of the watch stream, since a new record may add a restriction within the version only if an instance that ignores it denies more (contracts, section 10): an enforcement point that ignores blocks allows what they deny, and its acknowledgements of the state versions that carry them would count them as applied;
  - the required properties of tools;
  - resource IDs that are keys;
  - per-tool argument records, which replace the single `ToolArgs` record of `v1alpha1`;
  - `tool.expose` among the actions an enforcement point's manifest must declare, with `tool.invoke` and `model.invoke`;
  - a `decision_id` that `action.executed` may leave out.

  An enforcement point that does not support them rejects the new bundles. It keeps deciding with its last valid bundle, under policies the core has since replaced, or, with none, stays closed, and it reports `HEALTH_DEGRADED` while the core flags the drift (contracts, EP-7): incompatible, and safe in that it never allows what a bundle it verified did not. Blocks are the exception, since they travel outside bundles: such an instance never applies them, so if these changes make `v1alpha2` (below), the core counts a block as applied only by the instances it serves `v1alpha2`.
- **Later changes.** A new kind of block needs a new contract version: an enforcement point that does not know it denies every tool and model call while it is active (EP-15), which stops the instances that do not know it (contracts, section 10). The catalog file is a closed document (contracts, section 10): like the bundle manifest, it gains a member only as `whitetower.catalog.v2`, or in a new contract version, and step 12 names its format among the identifiers of the contracts' section 10.
- **When it lands.** No module verifies bundles or decides on tools yet (P1-09 has not started). This RFC therefore proposes to land in `v1alpha1` before `contracts/v0.1.0` is tagged (contracts, section 10: changes before the tag are free). Plan P0-03 lands it, in a step of its own (step 12), and puts the new text in new sections (4.10, 5.10, 6.9 to 6.11 and 7.7), so that no section that other documents cite changes its number. If the tag comes first, the changes that are not additive make `v1alpha2`, served next to `v1alpha1`.
- **Vectors.** The `v1alpha1` combination vectors that use a tool or a model are rewritten with per-tool records and a catalog.

## Security considerations

This RFC changes two trust boundaries and adds a third:

- **TB-2** carries new flows: tooling reports and definitions, from agents' processes into the core, and blocks, from the core to every enforcement point.
- **TB-1** shows what agents report to people, in the console and in the CLI.
- **TB-10**, new, lies between the agent's process and its MCP servers and model providers (flows F16 and F17), which the threat model did not draw. Tool definitions and results come in across it, and provider-run tools act beyond it.

Threat model version 0.1.1 recorded these additions, together with actor TA-11 (a malicious or compromised tool provider), assumption A-7 (model providers run only the tools a request declares, and report the calls they made), design changes DC-9 and DC-10, and accepted risk R-15:

| ID | STRIDE | Threat | Mitigation |
| --- | --- | --- | --- |
| T-74 | S, T, D | An agent reports tooling it does not have, or hides tooling it has, to mislead reviewers or flood the catalog | Reports never authorize (CORE-10); limits, and a rate limit per instance and agent; a bound on each agent's entries waiting for review (CORE-13, DC-10); new entries are inert until reviewed. Hiding a tool gains nothing, because calls are resolved when they happen and an unknown tool is denied |
| T-75 | T | Tool poisoning: a third-party server's description carries instructions for the model, or changes after approval | Reviewers see full definitions; approval pins their hash; a changed definition is denied and hidden from the model until approved (EP-16, EP-17) |
| T-76 | T, I | Reported text attacks reviewers through script injection, misleading names, hidden characters, or secrets left in command lines | Shown as plain text, with hidden characters made visible, length limits and a strict Content Security Policy (NFR-12); escaped by the CLI; redacted by the enforcement point and again by the core, with the deployment's rules for secrets in URL paths (EP-14, CORE-11); marked as reported. A secret passed as a positional argument, or in a URL path that no rule names, escapes them |
| T-77 | S | Another server answers at an approved reference: DNS hijack, or a hijacked or unpinned package launched by `npx` | References identify, they do not authenticate. The agent's MCP client checks TLS; pinned definitions reveal changed tools; the catalog flags local servers launched from unpinned packages. The supply chain of MCP servers stays with the agent's owner (A-6) |
| T-78 | E | Usage rules are bypassed through how arguments are written: `..` segments, letter case, URL parser differences, missing arguments that the server fills in, unexpected types | Transforms that refuse what parsers read differently, and control characters in paths, with conformance vectors; missing arguments match by default; a value of the wrong type denies; no regular expressions. Documented limits: symbolic links, relative paths against deny-lists, server-side defaults (R-15) |
| T-79 | E, R | Provider-run tools act outside the agent's process | Exposure checked before every model call; declarations narrowed to enabled tools; each call decided where the provider submits it for approval, which the enforcement point asks for the tools that usage rules name; a tool with usage rules never exposed while its calls are not decided; global policies can forbid `origin == "provider"`; evidence from responses. What remains is the provider's own behavior (A-7), and a changed definition the model sees once before the enforcement point learns of it |
| T-80 | D | Blocks or catalog changes slow halts, or flood enforcement points | Blocks travel in their own record, as hashes and deltas, with a cap of 500, and never rebuild bundles (DC-9); halts are measured with 500 blocks active; bundle rebuilds run in chunks (P1-06) |
| T-81 | D, E | An insider disables tools or blocks servers to disrupt agents, or undoes a block alone | Only roles that can already halt or suspend; a reason is required; everything is audited. Enabling and unblocking need a second person (HUM-04) |
| T-82 | E | The seeded `wt-catalog` permit applies without the catalog check: an enforcement point that predates catalogs, or a bundle without its catalog file | Every bundle carries a catalog file; the manifest's `catalog` field fails V4 where it is unknown, and V5 requires the file (section 5) |

**Unchanged risk.** An agent whose process is compromised can bypass its enforcement point (T-40), its catalog check and exposure included. This RFC does not change that: the risk stays R-01, answered by network quarantine and, in Phase 2, by the gateways and the harness.

**Privacy.** Tool descriptions and schemas describe software, not people. Argument values used in decisions never reach evidence (contracts, section 8.3). URLs and command lines are redacted (EP-14, CORE-11), but a local path can still hold a user name. The catalog keeps references for review, and shows them only to those who may view the catalog (`catalog.view`, P1-16). Events and blocks name references only by their SHA-256, which keeps their text out of the audit log and the watch stream, but is not a pseudonym (NFR-20): a path such as `/home/<user>/...` can be guessed, and its hash checked against a list of user names. Keys, which events carry in clear, never come from a command line (section 3).

**Proposed security tests:**

| ID | Test | Covers | Kind | Owner |
| --- | --- | --- | --- | --- |
| ST-75 | A tooling report never approves, enables or unblocks anything: new entries stay discovered, a changed definition or digest stays unapproved, and nothing becomes usable; beyond the bound on an agent's entries waiting for review, a report's new entries are left out and stay denied | T-74, DC-10 | integration | P1-16 |
| ST-76 | A server changes a tool's description; the tool is denied and hidden until its new definition is approved | T-75 | e2e | P1-09 |
| ST-77 | Canary secrets in MCP server URLs, in a URL path segment that a redaction rule names, in the command-line arguments that EP-14 redacts and in environment variables never reach the core's storage, its logs or events | T-76 | integration | P1-09 |
| ST-78 | Reported names and descriptions with markup and script render as text in the console, with invisible and bidirectional characters made visible | T-76 | e2e | P1-10 |
| ST-79 | The argument vectors (traversal, a leading double slash and control characters in paths, case, URL and address tricks, missing arguments, wrong types) give the expected decisions | T-78 | unit | P1-09 |
| ST-80 | With 500 active blocks, a block reaches every mock enforcement point within NFR-24, and halts of one agent and of the fleet still meet NFR-03 | T-80, DC-9 | integration | P1-16 |
| ST-81 | Nobody approves their own request to enable or to unblock | T-81 | integration | P1-16 |
| ST-82 | A model request that offers a provider-run tool that is not enabled, and cannot be narrowed, is denied; a provider-run tool that a usage rule names is not offered while its calls are not decided | T-79 | unit | P1-09 |
| ST-83 | Reported text that `wtctl` prints is escaped: no control, bidirectional or invisible character reaches the terminal | T-76 | unit | P1-11 |

ST-80 runs with the measurement harness of P1-08; whether a block denies before policies is the enforcement point's, checked by scenarios S-19 and S-20.

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
- **Blocks as a status in bundles as well.** Blocking a widely used server would rebuild most bundles, and each enforcement point would fetch and acknowledge one, just when an operator may also be halting agents. The watch stream's record is enough while the block lasts.
- **Definitions inside each report.** Every report would carry every description and schema: up to hundreds of megabytes within the limits above, sent again at every restart. Content-addressed definitions are sent once.

## Unresolved questions

The maintainer answered these questions on 2026-10-21. Plan P1-16 records the answers in its step 1, and plan P1-06 the quorum of answer 2 in its step 4.

1. Who approves catalog entries: the advisory committee, as proposed, or the steering committee, as for accepted providers (POL-10)? Answer: the advisory committee, which already validates use cases.
2. Should adding a usage rule, which only restricts, take effect without approval, as blocks do? Answer: no. Rules are policy text, and need approval like any policy version. How many distinct people of the approving committee must approve a version is a setting of the platform administrator, `policy.approval_quorum`: 1 by default for each scope, at most 5 (P1-06, step 4). An urgent restriction uses a disable or a block, which take effect at once.
3. Should an agent with non-production credentials be able to use every approved entry without enabling each one, to make onboarding easier? Answer: no. The steering committee can still narrow `wt-catalog` by environment.
4. Stateful rules (sequences of calls, counts per task, data flowing from one tool to another) are left to Phase 2. Which context fields should be reserved now? Answer: none. Adding a context field is additive.
5. Are the limits right: 256 servers, 4,096 tools and 256 models per report; references of at most 2 KiB; one report's worth of an agent's entries waiting for review; 500 active blocks? Answer: yes. The limits stay: the maintainer finds them more than enough.
6. For agents without the enforcement point:
   - should the catalog import tooling from endpoint security tools (Phase 3 discovery)?
   - should it export an agent's enabled tooling to the allowlists that coding agents support?

   Answer: neither in the MVP. Both come later, as they are not critical to the core of the platform.
7. Should usage rules support numbers that are not integers, through Cedar's `decimal`? Answer: no, integers only for now. The pilot's feedback decides whether decimals come later.

## Implementation plan

| Plan | Implements |
| --- | --- |
| P0-03, step 12 | The contract text, protobuf, schemas and vectors of this RFC, before `contracts/v0.1.0` is tagged |
| P1-16 (new): MCP servers, tools and models | The catalog and its workflow, reports and definitions, enablement, declared tooling, blocks, the redaction rules, the content of the catalog file and the argument declarations, the usage-rule form and compiler, the core event types of section 9, the API and the metrics |
| P1-06 | The catalog file and a Cedar schema in each bundle, the seeded `wt-catalog` policy, and the check of `@rule` statements at submission |
| P1-07 | `ReportTooling`, `ReportDefinitions` and the blocks record in the module API, the mock module's catalog behavior, the kit's model provider, and the scenarios S-18 to S-24 and S-32 |
| P1-08 | The halt path's design, which blocks share; the harness that measures halts with blocks active |
| P1-09 | In LangGraph and the second framework: discovery, references and redaction, the catalog check, exposure through the framework's middleware, provider-run tools, arguments and transforms |
| P1-10 | A new subplan, P1-10.7: MCP servers, Models, and the "MCP and Tools" tabs |
| P1-11 | `wtctl catalog` and `wtctl agent tooling` |

The follow-up of 2026-10-19 turned this RFC into scope, after the maintainer confirmed it: requirements version 0.3 (CAT-01 to CAT-10, NFR-24, UI-10), plan P1-16 and step 12 of P0-03, the domain model (section 3.9), threat model version 0.1.1, security tests ST-75 to ST-83, the plans index and the re-baselined roadmap. Planning also settled what this draft had left open: the string form of references, definitions sent apart from reports, entries for the agent's own tools, blocks named by hash and never a status in bundles, a bound on each agent's entries waiting for review, a way to decline entries, and the owner of each change.

The skills repository is no longer planned. The `skills-repository` capability and the `skill` resource type stay reserved, so that nothing has to be renamed if skills return.

## Review record

The maintainer alone reviewed this RFC, with no external reviewer, under the provisional acceptance of [GOVERNANCE.md](../../GOVERNANCE.md#rfc-process); a review of at least two weeks, with an external reviewer, follows before the contracts leave alpha (`v1beta1`). The review ran from 2026-10-23 to 2026-10-26. It read this RFC against the specification as RFC-0001's review left it (commit `3ca9d83`), plan P1-16, the design of the halt path ([P1-08's design note](../plans/phase-1/P1-08-kill-switch.md#progress-notes), sections 2, 4, 6 and 9), version 0.1.4 of the threat model and the requirements. Where a point turned on how real software behaves, the reviewer ran it: URL and address parsers in Python, Node, Go and curl, IDNA in the three stacks, and RFC 8785 in `gowebpki/jcs`. It raised 21 points, 8 of them major, and 3 editorial notes. The maintainer decided the major points on 2026-10-23 and the others on 2026-10-26, each on its recommended option:

| Point | Severity | Decision | Applied in |
| --- | --- | --- | --- |
| 1. A usage rule never applied to a provider-run tool whose calls the provider does not submit for approval | Major | A | Part 1 |
| 2. The `path` transform was defined by a Go library | Major | A | Part 1 |
| 3. `url_host` and `email_domain` met the differences between parsers | Major | A, narrowed after a check of what it refuses | Part 1 |
| 4. Secrets in URL paths escaped EP-14, and what a reference covers was unstated | Major | A | Part 1 |
| 5. A remote server's URL was normalized only in part | Major | A | Part 1 |
| 6. "The provider's public endpoint" was undefined | Major | A | Part 1 |
| 7. Definition hashes were taken over input that RFC 8785 does not cover | Major | B: RFC 8785, with integers written exactly | Part 1 |
| 8. A catalog file could be larger than a bundle may be | Major | A | Part 1 |
| 9. The catalog check had no place among the reasons of the contracts' section 6.6 | Minor | A | Part 2 |
| 10. The evidence of a catalog denial could not say what was denied | Minor | A | Part 2 |
| 11. The operators of usage rules had no types | Minor | A | Part 2 |
| 12. Each statement of a rule repeated the whole rule | Minor | A | Part 2 |
| 13. An argument's path could be read two ways | Minor | A | Part 2 |
| 14. The blocks record left its rules to the design of the halt path | Minor | A, provisional until a live test | Part 2 |
| 15. A block did not stop the result of a call in flight | Minor | A | Part 2 |
| 16. Three classifications of compatibility contradicted the contracts' section 10 | Minor | A | Part 3 |
| 17. A late report could undo a newer one, items over the limits were lost in silence, and some strings had no limit | Minor | A | Part 3 |
| 18. The core's side of `ReportTooling` and `ReportDefinitions` was unstated | Minor | A | Part 3 |
| 19. EP-18 had no scenario | Minor | A | Part 3 |
| 20. The Cedar schema left a model's attributes optional, and reused exposure decisions outlived what they depend on | Minor | A | Part 3 |
| 21. A reference's SHA-256 was taken for a pseudonym | Minor | A | Part 3 |

Two of them need a note:

- **Point 3.** The rules first proposed refused 15 of 42 legitimate URLs and 9 of 18 addresses: spaces in a query, user information, other schemes, display names. The maintainer asked for a check that the denials were not excessive, and the rules were narrowed until they refused 2 of the URLs and 4 of the addresses, while in 38 URL tricks and 15 address tricks no parser reached another host than theirs.
- **Point 14.** The rules of the blocks record and EP-15's acknowledgement apply provisionally (section 6). A live test with real enforcement points in a real environment, the end-to-end test of P1-09 (its step 14), confirms them, and its findings go to the review that precedes `v1beta1`.

The three parts are the commits of pull request #70, and [P0-03's progress notes](../plans/phase-0/P0-03-module-contracts.md#progress-notes) of 2026-10-23 and 2026-10-26 list what each changed. The editorial notes went into part 3.

The contract text, protobuf, schemas and vectors of this RFC follow in step 12 of P0-03, in their own pull requests before `contracts/v0.1.0` is tagged, as GOVERNANCE.md's rule 6 says. The specification text comes first, and it is the reviewer's, with the cases of point 3's check for the vectors; the protobuf, the schemas and the vectors are parts for the coding agents ([AGENTS.md](../../AGENTS.md), work queue).
