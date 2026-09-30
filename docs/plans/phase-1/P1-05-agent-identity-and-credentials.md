# P1-05: Agent identity and credentials

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | L |
| **Depends on** | P1-04 |
| **Unblocks** | P1-07, P1-08, P1-09 |
| **Requirements** | AID-01 to AID-09, KIL-06 |
| **Decisions** | ADR-0010 |

## Goal

Every agent and module instance proves who it is with an asymmetric key, and receives short-lived tokens that White Tower issues only when governance allows it. The token endpoint becomes an enforcement point in its own right: the moment an agent is halted or suspended, it gets no new token, except for the module API, which its enforcement point still needs (DC-1 of the [threat model](../../security/threat-model.md)).

## Scope

**In:** signing keys and rotation, discovery endpoints, credential management, the token endpoint with `private_key_jwt`, the governance gate at issuance, module identities, Kubernetes workload identity federation, client helpers, security tests.

**Out:** token exchange for per-task tokens (designed here, built in Phase 2), SPIRE integration (Could), consumption of tokens by gateways (Phase 2).

## Deliverables

- `internal/agentid` and `internal/platform/keys`.
- `/oauth2/token`, `/.well-known/jwks.json` and `/.well-known/oauth-authorization-server` on the machine listener; JWKS also on the console listener, for verifiers.
- OpenAPI operations for credentials.
- Go client helper in `pkg/` and shared test vectors for the Python helper of P1-09.
- Key rotation runbook.

## Steps

### 1. Key management

A `keys` interface (sign, public JWK, key ID, rotation state) with a file backend, shared by the three signing keys of the architecture document. Only the token key (ES256) is used here; P1-06 and P1-02 use the others. Rotation publishes the next key in the JWKS before using it, with an overlap longer than the maximum token lifetime plus clock skew.

**Done when:** a rotation under load produces no verification failure (test with clients refreshing continuously).

### 2. Discovery

- RFC 8414 metadata: issuer, token endpoint, JWKS URI, grant types (`client_credentials`), client authentication methods (`private_key_jwt`) and their signing algorithms.
- The JWKS.

**Done when:** a standard OAuth client library configures itself from the metadata.

### 3. Credential management

- Register a public key (JWK or PEM; ES256 and EdDSA accepted), with an environment label (production or non-production) and an optional expiry.
- List, revoke and rotate keys; each is identified by its RFC 7638 JWK thumbprint.
- The client ID is the agent ID.
- Allowed to the agent's owner and to operators (permission matrix). Every change is audited.

**Done when:** the permission and validation tests pass, and private keys are never accepted by mistake (a PEM private key is rejected with a clear error).

### 4. Token endpoint

`POST /oauth2/token`, form-encoded, with `grant_type=client_credentials` and a `client_assertion` of type JWT bearer. The assertion must meet all of these:

- signed by a registered, active key, found by `kid`;
- `iss` and `sub` equal to the client ID;
- `aud` equal to the token endpoint;
- expiry no more than 5 minutes away;
- `iat` and `nbf` within ±60 seconds of clock skew;
- a `jti` never seen before (a replay cache in the database, cleaned by a job).

The requested `resource` (RFC 8707) must be a configured audience, such as the module API; it becomes the token's `aud`.

**Done when:** the positive path works and every negative case of step 10 is rejected.

### 5. Governance gate

The gate runs in the same transaction as issuance, or on a consistent read. It denies when:

- the agent is retired or suspended;
- its run state is halted (agent or fleet halt);
- a production credential is used by an agent that is not `active`;
- a non-production credential is used by an agent that is not `validated`, `ready` or `active`;
- the credential is revoked or expired.

**One exception keeps the halt path whole:** a token for the module API is still issued to a suspended or halted agent, whose enforcement point needs it to acknowledge the halt, deliver its evidence and learn of the release (AID-04; [threat model](../../security/threat-model.md), DC-1). It is refused for a retired agent, and for a revoked or expired credential. Decide here whether a retired agent's enforcement point gets a short period to deliver its remaining evidence.

The caller gets a generic OAuth error; the detailed reason goes to the audit log.

**Done when:** halting an agent makes its next token request for any audience but the module API fail within the same second, while its enforcement point still gets module API tokens (tests).

### 6. Access tokens

JWTs following RFC 9068:

- header: `typ: at+jwt` and `kid`;
- standard claims: `iss`, `sub` (the SPIFFE-format ID), `aud`, `client_id`, `exp` (5 minutes by default, 15 at most), `iat`, `jti`;
- White Tower claims: `wt_agent_id`, `wt_env`, `wt_risk_tier`, `wt_owner` (pseudonymous ID) and `wt_state_version`, the governance state version at issuance, useful to gateways later.

Every issuance is an audit event. The volume (about 3 per second for 1,000 agents refreshing every 5 minutes) fits NFR-07.

**Done when:** tokens verify with a standard JWT library and the published JWKS.

### 7. Module identities

Standalone module instances use the same endpoint with their own identity (`spiffe://<trust-domain>/module/<module-id>`) and credentials, created when an operator approves the module (P1-07). An enforcement point embedded in an agent's process, as the Python enforcement point is (P1-09), authenticates **as the agent** and may only serve that agent. Document both cases for P0-03 and P1-07.

**Done when:** both kinds of identity obtain tokens, and the claims tell them apart.

### 8. Kubernetes workload identity federation (Should)

- Trust configuration per cluster: the issuer URL, or a static JWKS for air-gapped clusters.
- Mapping rules from namespace and service account to agent ID.
- A projected service account token, with the token endpoint as audience, is accepted as the client assertion. It goes through the same governance gate.

**Done when:** an agent in a kind cluster gets tokens without any static key (end-to-end test).

### 9. Design note: per-task tokens (Could; built in Phase 2)

Describe how token exchange (RFC 8693) will issue per-task tokens that carry the on-behalf-of user in an `act` claim and a narrowed scope. Reserve the claim names. Link the IETF WIMSE "AI Identity Management System" draft and the OAuth identity chaining work.

**Done when:** the note is in `docs/architecture/` and reviewed.

### 10. Client helpers and security tests

- A Go helper that signs assertions and caches tokens, refreshing them early, plus shared test vectors for the Python helper of P1-09.
- Negative tests:
  - `alg: none` and HS256 with the public key used as the HMAC secret (algorithm confusion);
  - `kid` injection, wrong audience;
  - expired and long-lived assertions, `jti` replay, clock skew;
  - a revoked key;
  - halted, suspended and retired agents;
  - a non-production key used by an agent that is not yet validated.
- Fuzzing of assertion parsing.
- Rate limits per client and per IP.

**Done when:** all run in CI, with a nightly long fuzzing run.

## Acceptance criteria

- Tokens are issued only when the gate allows it; after a halt, the next request fails immediately.
- All negative tests pass, and fuzzing runs in CI.
- JWKS rotation causes no verification failure for clients that refresh.
- At MVP load (1,000 agents refreshing every 4 minutes), the token endpoint answers with p95 ≤ 100 ms.
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-05-agent-identity-and-credentials) pass: ST-25 to ST-30.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| White Tower now owns security-critical OAuth code | Narrow feature set, `go-jose`, negative tests and fuzzing, external review in P1-13 |
| Clock skew between agents and the core | ±60 s tolerance, NTP assumed (ASM-04), clear error in the audit log |
| Tokens outlive a halt by up to 5 minutes | Halts are enforced through the watch stream, not token expiry (ADR-0005) |

## Notes for implementers

- Use `go-jose` v4 with an explicit allow-list of algorithms on every parse.
- Never log assertions or tokens; log their `jti` and thumbprints instead.
- Keep the `jti` replay cache in PostgreSQL with a unique index and an expiry column; it is small because assertions live 5 minutes at most.
