# Driver protocol

How the conformance kit tells a module under test what to do. A module ships a small **harness** for its tests: a program that starts the module against the kit's fake core and serves the endpoints below. The harness must call the module's normal code paths; it must never bypass the gate or fake an answer.

## Configuration

The kit starts the harness with these environment variables:

| Variable | Meaning |
| --- | --- |
| `WT_CONFORMANCE_CORE_URL` | Base URL of the fake core's module API |
| `WT_CONFORMANCE_CA_FILE` | PEM file with the fake core's certificate authority, the module's trust anchor |
| `WT_CONFORMANCE_BUNDLE_KEYS_FILE` | JWK Set file (RFC 7517) with the bundle keys to trust: `OKP` keys on the `Ed25519` curve (RFC 8037), each with its `kid`, as section 7.3 of the specification recommends. The kit passes `vectors/bundles/trusted-keys.json` |
| `WT_CONFORMANCE_AGENT_ID` | For an enforcement point inside an agent: the agent it serves |
| `WT_CONFORMANCE_DRIVER_ADDR` | Where the harness listens for the driver, for example `127.0.0.1:18090` |
| `WT_CONFORMANCE_EVIDENCE_CAPACITY` | Set for scenario S-11 only: how many events the module's evidence buffer holds, a small number, so that the kit can fill it. The harness gives the module a buffer of that capacity. A module that cannot take it says so in its conformance report, and S-11 is reported as not run, never as passed |

Credentials for the fake token endpoint are added with it, in plan P1-07.

The harness sets no environment. The module takes the environment of its decisions from its registration, as section 6.2 and I-7 say: the fake core returns `production` today, and plan P1-07 has it return each environment in turn, for S-25.

The module runs with its default settings, but for the capacity of its evidence buffer in S-11. Scenario S-17 sends lease renewals a minute before and after the kit's clock, beyond the largest tolerance the contract lets a module configure: 30 seconds, and 5 by default (section 5.3).

## Endpoints

All bodies are JSON.

### `POST /v1/decide`

Runs one decision through the module's normal path: gate, policies, evidence. The body is an AuthZEN evaluation request of the profile **without its subject**, which the module builds from the governance state and the environment that its registration returned (section 6.2, I-7), never from the body or its configuration. `time` may be omitted; the module then uses its clock.

```json
{
  "action": { "name": "tool.invoke" },
  "resource": { "type": "tool", "id": "agent/read_invoice", "properties": { "kind": "function" } },
  "context": { "time": "2026-09-29T10:00:00.000Z" }
}
```

The response is the AuthZEN evaluation response of the profile:

```json
{ "decision": true, "context": { "reason": "policy.permit", "policies": ["0192f1c2-7a3b-7c4d-8e5f-000000000202"], "bundle_version": 42 } }
```

### Planned for P1-07

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/work` | Start a governed action that stays in flight, `async` or `blocking`, for a given duration; returns a work ID. Used by the halt scenarios |
| `GET /v1/work/{id}` | The action's state: `running`, `interrupted` or `finished` |
| `POST /v1/restart` | Restart the module, keeping its evidence buffer. Used by the durability and reconnection scenarios |

A module that cannot support an endpoint says so in its conformance report, and the scenarios that need it are reported as not run, never as passed.
