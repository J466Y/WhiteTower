# Security test catalog

| | |
| --- | --- |
| **Status** | Draft v0.1, with [threat model v0.1](threat-model.md) |
| **Date** | 2026-09-30 |
| **Plan** | [P0-04](../plans/phase-0/P0-04-threat-model.md), step 8 |

Each test turns an abuse case of the threat model into a check that fails if the control it covers is missing. Each has one owner plan: its acceptance criteria require the test to pass, and it runs in CI from then on. Plan [P1-13](../plans/phase-1/P1-13-security-hardening-and-release.md) runs the whole catalog before the first release.

**Kinds:** unit, integration, end-to-end (e2e), fuzz, scan, review, exercise. The "Covers" column names the threats (`T-`), design changes (`DC-`) or attack trees (`AT-`) of the [threat model](threat-model.md), or a requirement.

## P1-01: Core platform skeleton

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-01 | Every listener except the operations one accepts only TLS 1.2 or later; the console listener sends HSTS | T-01 | integration |
| ST-02 | A production build refuses to start with any development-only setting: skipped TLS verification, the development IdP, insecure cookies | T-61 | integration |
| ST-03 | Canary values placed in every secret file never appear in logs, error responses, metrics or traces | T-10 | integration |
| ST-04 | The server starts and serves with the runtime role's credentials only; `whitetower migrate` is the only command that reads the migration role's | T-54, DC-3 | integration |
| ST-05 | Requests over the size limit are refused on every listener before reaching a handler | T-11, T-36 | integration |

## P1-02: Audit log

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-06 | Tamper suite: as a superuser, modify, delete, insert and reorder sealed events; verification reports each case | T-51 | integration |
| ST-07 | Rollback: remove the latest events and checkpoints; the consistency check against a checkpoint exported earlier fails | T-52, DC-8 | integration |
| ST-08 | Rewrite: rebuild the tree over altered events and sign it with another key; the consistency check against an exported checkpoint fails | T-51, T-58 | integration |
| ST-09 | A domain operation whose audit write fails is rolled back entirely | T-07 | integration |
| ST-10 | Ingestion refuses event types and sources outside the instance's own; per-instance rate limits and backpressure keep one flooding instance from slowing the others | T-27, T-36 | integration |
| ST-11 | Fuzzing of the CloudEvents parser and the ingestion path | T-36 | fuzz |
| ST-12 | Reads of the audit log are themselves audited (AUD-09) | T-03 | integration |

## P1-03: Human identity and access

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-13 | State-changing requests without a valid CSRF token are refused | T-02 | integration |
| ST-14 | Session fixation is impossible; cookie flags are set; idle and absolute expiry apply; sessions are rotated at login and revoked at logout, on deactivation and on role changes | T-01, T-19 | integration |
| ST-15 | Return URLs outside the console's own paths are refused | T-06 | integration |
| ST-16 | ID tokens with a wrong issuer or audience, an expired one, a replayed nonce or an unexpected algorithm are refused | T-13 | integration |
| ST-17 | Every role and permission pair of the matrix, including the negatives; no handler bypasses the authorization engine | T-03 | unit |
| ST-18 | Separation of duties: self-approval, self-validation, a one-person release and granting oneself a role are refused | T-04, T-16, DC-4 | integration |
| ST-19 | API tokens: scopes enforced, expiry, storage only as a hash, revocation with the principal | T-17 | integration |
| ST-20 | A break-glass session can halt agents and the fleet and read, and nothing else: not release, not change anything; it expires after one hour; attempts are rate-limited; each use raises the critical event and the alert | T-12, T-71 | e2e |
| ST-21 | SCIM refuses calls without its token; deactivations are audited and revoke sessions | T-18 | integration |
| ST-22 | Login attempts are rate-limited | T-11 | integration |

## P1-04: Inventory and lifecycle

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-23 | Every guarded lifecycle transition is refused through the API when its guard fails, including activation without the invariant and validating one's own use case | T-03, T-04 | integration |
| ST-24 | CSV exports neutralize cells that start with `=`, `+`, `-` or `@` | T-09 | unit |

## P1-05: Agent identity and credentials

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-25 | Client assertions are refused when the `jti` is replayed, when expired, with a wrong audience, when `iss` differs from `sub`, with clock skew beyond the limit, or with an unknown or revoked key | T-20 | integration |
| ST-26 | Algorithm confusion is refused, for assertions and for issued tokens: `none`, HMAC keyed with the public key, an algorithm that does not match the registered key | T-21 | integration |
| ST-27 | Tokens are issued only for configured resources; the module API refuses tokens for any other audience | T-22 | integration |
| ST-28 | Halted, suspended and retired agents get no token for any audience but the module API; halted and suspended agents still get module API tokens; retired agents get none | T-24, T-25, DC-1 | integration |
| ST-29 | The token endpoint is rate-limited per client | T-26 | integration |
| ST-30 | Fuzzing of the client assertion parser | T-21 | fuzz |

## P1-06: Policy model and distribution

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-31 | The author of a policy version can never approve it, through the API or directly in the database | T-04 | integration |
| ST-32 | The core never builds a bundle containing a policy version that is not approved | T-29 | integration |
| ST-33 | Bundles verify only with the bundle key, never with the token or checkpoint key | T-29 | unit |

## P1-07: Module registry and API

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-34 | Registration is refused for an unapproved module or a different manifest hash; revoking a module ends its streams and refuses its calls (MAN-1 to MAN-4) | T-28 | integration |
| ST-35 | Every method refuses agents outside the caller's scope, on every call and not only at registration (CORE-2) | T-27 | integration |
| ST-36 | A `Watch` stream ends when its token expires (CORE-1), and a reader that falls behind is dropped (CORE-7) | T-37 | integration |
| ST-37 | No replica ever sends state older than the client's version, including after a failover to another replica (CORE-5) | T-31 | integration |
| ST-38 | Message size limits and per-instance stream limits are enforced (contracts section 4.8) | T-36, T-37 | integration |
| ST-39 | Every lease renewal carries the core's time | T-32, DC-2 | integration |

## P1-08: Kill switch

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-40 | An acknowledgement for another agent's halt, or from another instance, is refused; repeated acknowledgements are idempotent | T-27, T-34, T-39 | integration |
| ST-41 | A halt is released only after a request and an approval by two different people, through the API and directly in the database; only a halt declared as a drill is exempt | T-04 | integration |
| ST-42 | An allow decision or an executed action timed after the acknowledged gate closing flags the instance as suspect; buffered evidence delivered later does not | T-34, T-40, DC-6 | integration |
| ST-43 | A halted agent's enforcement point keeps delivering evidence and acknowledgements after its first token expires, and learns of the release | T-25, DC-1 | e2e |
| ST-44 | Under a network partition, the enforcement point fails closed when its lease expires (fault injection) | T-69 | e2e |
| ST-45 | A halt that stays unacknowledged raises an alert after the timeout | T-32 | integration |

## P1-09: Python enforcement point

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-46 | The fail-closed vectors, and the unknown values of EP-10, all keep the gate closed | T-42 | unit |
| ST-47 | The bundle vectors pass: every rejection of V1 to V7 for its reason | T-29, T-30 | unit |
| ST-48 | A delayed stream: renewals older than the tolerance renew nothing, and the gate closes when the lease runs out | T-32, DC-2 | integration |
| ST-49 | A server whose certificate does not chain to the configured trust anchors is refused (I-1) | T-33 | integration |
| ST-50 | Decision events never carry argument values, prompts, outputs or error messages | T-44 | unit |
| ST-51 | With DNS blocked, the enforcement point reconnects to the core's last resolved addresses | T-46, DC-7 | integration |
| ST-52 | The enforcement point refuses to start with a private key file that other users can read | T-23 | unit |
| ST-53 | The package is published with trusted publishing and attestations, and the installation guide pins exact versions and hashes | T-66 | review |

## P1-10: Web console

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-54 | The Content Security Policy forbids inline scripts, external sources and framing, and the other security headers are set | T-05 | integration |
| ST-55 | Stored XSS payloads in every field an attacker can influence (agent metadata, policy text, manifests, event fields, tool names) render as inert text | T-05 | e2e |
| ST-56 | No token or session secret is readable from JavaScript or kept in web storage | T-01 | e2e |

## P1-11: CLI

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-57 | `wtctl audit verify` rejects a tampered export, and checkpoints with an unknown key or a bad signature | T-58, T-59 | integration |
| ST-58 | `wtctl audit consistency` fails against a rolled-back log | T-52, DC-8 | integration |
| ST-59 | Tokens the CLI stores are readable only by their user, and never printed | T-17 | unit |

## P1-12: Packaging and deployment

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-60 | End to end with all egress blocked: nothing tries to leave | NFR-14 | e2e |
| ST-61 | The key Secrets are mounted as files, readable only by the core's service account; no secret is passed through environment variables | T-10, T-60 | integration |
| ST-62 | In the Helm chart, the server container has no migration credentials; only the migration init container has them | T-54, DC-3 | integration |
| ST-63 | Network policies: each listener is reachable only from its own networks | T-11, T-68 | e2e |
| ST-64 | After a restore from backup, the log verifies against checkpoints exported before the backup | T-62 | e2e |

## P1-13: Security hardening and release

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-65 | OWASP ZAP baseline scan, and an API scan driven by the OpenAPI document | T-01 to T-11 | scan |
| ST-66 | `govulncheck`, OSV-Scanner and an image scan report no critical or high finding | T-63 | scan |
| ST-67 | A secret scan of the full history | T-10 | scan |
| ST-68 | Every release artifact verifies with the documented commands: signatures, SBOMs, provenance | T-64, T-65 | review |

## P1-15: Network quarantine

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-69 | A user with broad rights in the namespace can neither delete nor change a quarantine rule, nor relabel a running pod | T-45 | e2e |
| ST-70 | A pod with the agent label and the host's network is refused | T-45, DC-5 | e2e |
| ST-71 | A quarantined pod can resolve no name and reach nothing but the core, and its enforcement point still reaches the core | T-46, DC-7 | e2e |
| ST-72 | A deleted rule is re-created by reconciliation, and a lift without a release shows in the audit log | T-48 | e2e |
| ST-73 | Restarting the controller, or cutting it off from the core, never lifts a quarantine (RC-2) | T-49 | e2e |

## P1-14: Pilot and gate

| ID | Test | Covers | Kind |
| --- | --- | --- | --- |
| ST-74 | An exercise of attack trees AT-1 and AT-6 against one pilot agent: every branch ends where the threat model says | AT-1, AT-6 | exercise |
