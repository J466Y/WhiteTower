# P1-03: Human identity and access

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | In progress: the erasure of a person, step 13, added on 2026-10-27 (see [progress notes](#progress-notes)) |
| **Size** | M |
| **Depends on** | P1-01, P1-02 (writer) |
| **Unblocks** | P1-04, P1-10, P1-11 |
| **Requirements** | HUM-01 to HUM-09, KIL-08 (break-glass), NFR-12 |
| **Decisions** | ADR-0009 |

## Goal

People log in through the organization's IdP. Their roles come from IdP groups. Every operation is authorized in one place, against the permission matrix, with separation of duties enforced. Tokens never reach the browser, sessions can be revoked, and a break-glass path keeps the kill switch usable when the IdP is down.

## Scope

**In:** OIDC login through the backend-for-frontend, sessions, CSRF protection, principals and their status, the erasure of a person, role mapping and bindings, the authorization engine, API tokens, the CLI token exchange, SCIM, break-glass, SAML through a broker.

**Out:** the console screens (P1-10.1 and P1-10.6); the CLI side of login (P1-11); machine identities (P1-05).

## Deliverables

- `internal/authn` and `internal/authz`.
- OpenAPI operations: `/me`, principals and their erasure, role bindings, API tokens, the CLI exchange; `/auth/*` routes; `/scim/v2/Users`.
- A permission test suite generated from the matrix.
- Integration guides for Keycloak, Microsoft Entra ID and Okta.

## Steps

### 1. OIDC login through the backend-for-frontend

- Discovery from the IdP's metadata; authorization code flow with PKCE, `state` and `nonce`; confidential client with its secret read from a file (or `private_key_jwt` when the IdP supports it).
- ID token validation: issuer, audience, expiry, nonce and an allow-list of algorithms.
- The `__Host-wt_session` cookie: `HttpOnly`, `Secure`, `SameSite=Lax`.
- Logout: local, plus RP-initiated logout when the IdP supports it.
- Return URLs restricted to the console's own paths (no open redirects).

**Done when:** login and logout work against the development Keycloak, and the negative tests of step 12 pass.

### 2. Sessions and CSRF

- Server-side sessions in PostgreSQL. Session IDs are random (at least 128 bits) and stored hashed.
- Idle timeout 30 minutes and absolute lifetime 12 hours, both configurable. The session ID is rotated at login; sessions are revoked at logout, on deactivation and on role changes.
- A cleanup job removes expired sessions.
- A CSRF token bound to the session, returned by `/api/v1/me` and required in a header on every state-changing request.

**Done when:** tests cover expiry, rotation, revocation and CSRF rejection.

### 3. Principals

On login, create or update the principal (issuer, subject, name, email, groups, last login). Administrators can deactivate and reactivate principals (HUM-05, Must). Deactivation revokes the principal's sessions and emits an event that the lifecycle guard of P1-04 consumes (an owner who becomes inactive leads to automatic suspension).

**Done when:** deactivating a principal revokes their sessions before their next request.

### 4. Roles, mapping and `/me`

- **Roles:** steering, advisory, owner, user, operator, auditor, admin.
- **Mapping:** configurable from an IdP claim (the claim name is configurable, for example `groups` or `roles`) to roles.
- **Local bindings:** administrators can add role bindings inside White Tower; every binding change is audited. Nobody can grant a role to themselves (HUM-04), and a grant of steering, advisory or operator notifies the steering committee's inbox ([threat model](../../security/threat-model.md), DC-4).
- **Effective roles** are computed at login and kept in the session; changing a binding revokes the affected sessions so they refresh.
- `/api/v1/me` returns the principal, roles, permission IDs (used by the console to adapt itself) and the CSRF token.

**Done when:** a user's effective roles match the mapping and bindings in tests covering each role.

### 5. Authorization engine

- **Permission IDs**, for example `agent.propose`, `usecase.validate`, `policy.global.approve` and `halt.fleet.issue`.
- **A role-to-permission matrix** in one Go file, derived from requirements section 5.2.1.
- **Relationship checks:** owner of, delegate of, author of.
- **Separation of duties:** never the author; two distinct principals for halt releases.

The engine is called from domain services with the principal in the context, and denies by default. Table-driven tests are generated from the matrix and cover every role and permission pair.

**Done when:** all pairs are tested, including the negatives, and no handler bypasses the engine (lint rule or test).

### 6. API tokens (Should)

- Service accounts (non-human principals with an owner and a purpose) and personal access tokens.
- Tokens are high-entropy random strings with a recognizable prefix (for example `wt_pat_`), stored hashed.
- Scopes are a subset of permissions; tokens expire (90 days at most) and record when they were last used.
- Creation and revocation are audited.

**Done when:** a scoped token can do exactly what its scopes and its owner's roles allow.

### 7. CLI token exchange

The CLI logs in with a public client at the IdP (authorization code with PKCE and a loopback redirect), then exchanges the ID token at White Tower for a short-lived API token (12 hours, revocable) bound to the same principal. The exchange validates the ID token like step 1 and is audited.

**Done when:** P1-11 can log in against the development Keycloak through this endpoint.

### 8. SCIM 2.0 deprovisioning (Should)

A minimal `/scim/v2/Users` (create, read, patch with `active: false`, delete as deactivation), protected by a bearer token for the IdP. It lets Entra ID and Okta push deprovisioning, so owners who leave are detected without waiting for a manual action.

**Done when:** the SCIM endpoint passes the IdPs' validators or an equivalent test suite, and a deprovisioning reaches the lifecycle guard.

### 9. Break-glass (Should)

- Disabled by default. `whitetower breakglass init` generates a high-entropy credential that is shown once; the guide recommends splitting it between two custodians.
- Logging in at `/auth/breakglass` gives a session limited to halt operations and read access, for one hour at most.
- Every use emits a critical audit event, logs an alert and shows a banner in the console.
- Attempts are rate-limited.

**Done when:** with the IdP stopped, a break-glass session can halt an agent and the fleet, and nothing else.

### 10. SAML through a broker (Should)

Document and test Keycloak brokering a SAML IdP, so organizations with SAML-only IdPs can use White Tower (HUM-08).

**Done when:** the guide is written and was followed once end to end.

### 11. Development realm

Extend the Keycloak realm from P0-01 so it has one user per role, a user with several roles and an inactive user.

**Done when:** end-to-end tests log in as each role.

### 12. Security tests

Tests from the [P0-04 catalog](../../security/security-tests.md#p1-03-human-identity-and-access) for this plan, ST-13 to ST-22:

- CSRF, session fixation, cookie flags, open redirects;
- ID token replay (nonce), algorithm confusion in ID token validation;
- the full separation-of-duties matrix;
- rate limits on login and break-glass.

**Done when:** all pass in CI.

### 13. Erasure of a person (HUM-09)

Added on 2026-10-27 ([progress notes](#progress-notes)). People have a right to erasure (GDPR, Article 17; [framework mapping](../../security/framework-mapping.md), section 4). Events name people only by pseudonymous principal IDs, and only `principals` links an ID to a person ([domain model, section 7](../../architecture/domain-model.md#7-personal-data)). An erasure breaks that link and keeps the ID, so that the history and the sealed log stay consistent.

- **Operation.** The platform administrator erases a principal, giving a reference to the request, such as a ticket number, rather than the person's name. The operation refuses an active principal, which is deactivated first (HUM-05), and a service account, which is no person.
- **What changes**, in one transaction, with a new migration:
  - the name and the email become placeholders, and the groups are cleared;
  - the IdP subject becomes one that no IdP issues, such as `erased:<principal ID>`, so that the pair of issuer and subject stays unique;
  - the external ID is cleared, so that neither a sign-in nor SCIM finds the erased principal by it (added on 2026-11-03 with the external ID, [progress notes](#progress-notes));
  - the principal is marked erased, with the reference as the reason of its status, and the time of the change from `clock.Clock`.

  Its ID, its issuer, its last login and every record that refers to it stay. Every check that a principal is inactive treats an erased one the same way, so that an erased owner still suspends their agents (INV-05), and a service account whose responsible principal is erased stays unusable for good (the fix of 2026-10-19).
- **Final.** An erased principal is never reactivated. If the person logs in again, the login finds no principal with their external ID or their subject and creates a new one, with a new ID.
- **Audited.** The erasure records `whitetower.principal.erased.v1`, with its actor, the principal's ID and the reference, and nothing that names the person: a new core event type, with every step of AGENTS.md's checklist.
- **Nothing else to erase.** No other table holds the name, the email or the subject. Text that people wrote into sealed events, such as halt reasons and agents' names, stays until retention drops it, and so do the person's groups that `principal.created` and `principal.groups_changed` recorded (added on 2026-11-05); the domain model's section 7 asks them to keep personal data out of it.

**Done when:** after an erasure, a canary name, email, subject and external ID appear in no table and in no API response; an active principal and a service account are refused; an erased principal cannot be reactivated, and the same person logging in again gets a new principal (ST-88).

### 14. Emergency revocation (HUM-10)

Added on 2026-11-10 ([progress notes](#progress-notes), decision 9). White Tower assumes that its deployment may be compromised and its users rogue. An identity provider that was compromised and then fixed, with the same issuer and claims, changes no setting, so the hash that sessions record (decision 7) refuses nothing: the sessions created meanwhile last up to 12 hours, and the API tokens created with them up to 90 days. Deactivating people one by one needs to know who they are.

- **Operation.** The platform administrator, or the break-glass custodian, ends every session and every API token at once, giving a reason. A token's scopes cannot grant it: it checks the role, or the break-glass session, as the authorizer does for the operations a token must never reach. The OpenAPI operation comes first.
- **What it ends,** in one transaction, with the time from `clock.Clock`:
  - every session, the caller's included, unless the caller's is a break-glass session: an administrator signs in again, since the session that asks could come from the compromised provider;
  - every API token, of people and of service accounts, the CLI's tokens included.

  Principals stay active, and their role bindings stay. The SCIM token and the modules' credentials (plan P1-05) are not sessions or tokens of this kind: the runbook says to rotate the SCIM token, and P1-05 to rotate the modules' credentials, if they could have leaked.
- **Audited.** It records a new core event type, with its actor, the reason and how many sessions and tokens it ended, and every step of AGENTS.md's checklist. It raises the critical alert that a break-glass use raises.
- **If the provider is still compromised**, a new sign-in through it gets a new session. The runbook says to turn OIDC off first, which decision 7 makes refuse every session that the provider created, then to revoke, to fix the provider, and to turn OIDC on again.

**Done when:** after a revocation, every session and API token created before it is refused, a CLI token and a service account's token included, and a break-glass session that ran it stays; any other role, and a token whatever its scopes, is refused (ST-89).

## Acceptance criteria

- Login and logout work against Keycloak and against at least one commercial IdP (Entra ID or Okta), or the latter is scheduled as the first pilot task if no tenant is available.
- The permission tests cover every role and permission pair, including separation of duties.
- The security tests of step 12 pass.
- Deactivating a principal revokes their sessions immediately.
- An erasure leaves the person's name, email and IdP subject nowhere in White Tower, and keeps the history consistent (HUM-09).
- An emergency revocation ends every session and API token at once, but a break-glass session that runs it (HUM-10).
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-03-human-identity-and-access) pass: ST-13 to ST-22, ST-88 and ST-89.

## Risks and open questions

| Risk or question | Mitigation or owner |
| --- | --- |
| IdPs send groups differently (claim names, overage, nested groups) | Configurable claim; document Entra ID group overage; local bindings as fallback |
| Break-glass credential leaks | Limited permissions, one-hour sessions, loud audit and alerting, rotation procedure |
| Roles cached in sessions go stale | Binding changes revoke sessions; absolute lifetime of 12 hours |

## Notes for implementers

- `coreos/go-oidc` and `golang.org/x/oauth2` cover the OIDC client side.
- Keep the permission matrix readable by non-developers: it is reviewed by committee members during the pilot.
- Store only what the IdP sends and what White Tower needs; no profile photos, no extra claims.

## Progress notes

The plan landed in six pull requests. The first built the authorization engine and role-to-permission matrix, which API operations and domain services evaluate. A seventh adds the erasure of a person, step 13 (2026-10-27).

| Pull request | Steps | Status |
| --- | --- | --- |
| 1. Roles, permissions and authorization engine | 5, ST-17, ST-18 (partial) | Done (PR #36) |
| 2. Principals, sessions and CSRF | 2, 3, ST-13, ST-14 | Done (PR #37) |
| 3. OIDC login, role mapping and /me | 1, 4, 11, ST-15, ST-16, ST-22 | Done (PR #38) |
| 4. API tokens | 6, ST-19 | Done (PR #39) |
| 5. CLI token exchange and break-glass | 7, 9, ST-20 | Done (PR #40) |
| 6. SCIM 2.0 deprovisioning and SAML broker guide | 8, 10, ST-21 | Done (PR #41) |
| 7. Erasure of a person | 13, ST-88 | To do |
| 8. Emergency revocation | 14, ST-89 | To do |

### 2026-10-14: roles, permissions and authorization engine

- `internal/authz`: the authorization engine of White Tower.
  - Roles: `steering`, `advisory`, `owner`, `user`, `operator`, `auditor`, and `admin`, representing the 7 roles of the White Tower governance model.
  - Permissions: 24 stable permission identifiers covering all actions of the governance lifecycle and platform operations.
  - The role-to-permission matrix in `matrix.go`, derived directly from requirements section 5.2.1, with explicit scopes (`ScopeAll`, `ScopeOwn`, `ScopeActiveOnly`, `ScopeSignOff`).
  - Separation of duties (`duties.go`, HUM-04): checks for self-approval/self-validation (`CheckApproval`), two-distinct-person requirement for halt releases (`CheckHaltRelease`), and prohibition of self role-granting (`CheckRoleGrant`).
  - `Authorizer`: implements `auth.Authorizer` (`internal/platform/auth`), mapping OpenAPI operation IDs to permissions with default-deny behavior for unknown operations, unauthenticated callers, or unauthorized roles.
  - Context helpers: `ContextWithRelationship` and `RelationshipFromContext` for resource-level authorization checks.
- Wiring: wired `authz.NewAuthorizer()` in `cmd/whitetower/main.go` into `rest.Options`.
- Tests:
  - ST-17: table-driven unit test verifying every one of the 7 roles x 24 permissions (168 test cases), asserting exact allow/deny semantics and scopes.
  - ST-18: tests verifying separation of duties enforcement (self-approval refusal, single-person halt release refusal, and self-grant refusal).
  - Authorizer tests covering unauthenticated calls, unknown operations, valid role operations, and relationship checks.

### 2026-10-14: principals, sessions and CSRF (PR 2)

- Domain package `internal/authn`:
  - `SessionStore`: manages sessions in PostgreSQL table `sessions`. Generates 256-bit cryptographic tokens (RFC 6750 URL-safe base64), stores SHA-256 hashes (`id_hash`).
  - Session lifecycle: configurable idle timeout (default 30m) and absolute lifetime (default 12h) in `internal/platform/config` (`Auth.Session`). Activity slides idle expiration up to the absolute ceiling.
  - Session fixation prevention: `Rotate` replaces the session token while preserving identity and roles upon authentication state changes (ST-14).
  - Session revocation: manual revocation on logout (`Revoke`), bulk revocation on principal deactivation (`RevokeAllForPrincipal` and `RevokeAllForPrincipalTx`).
  - Cookie generation: sets `__Host-wt_session` (when TLS enabled) with `HttpOnly`, `Secure`, `SameSite=Lax`, and `Path=/`. Fallback to `wt_session` when TLS is not enabled.
  - Periodic cleanup job: `CleanupSessionsJob` registered with `jobs.Runner` to purge expired sessions.
  - CSRF protection: HMAC-SHA256 derived tokens bound to the session token. `CSRFValidator` interface and middleware in `internal/api/rest` refuse state-changing methods (POST, PUT, PATCH, DELETE) without a matching `X-CSRF-Token` or `X-WT-CSRF-Token` header (ST-13).
  - `PrincipalStore`: human principal management in PostgreSQL table `principals`. `UpsertHuman` for IdP synchronization, `GetByID`, `GetByIdentity`.
  - Principal deactivation and reactivation (HUM-05): `Deactivate` marks principal inactive, immediately revokes active sessions in the same transaction, and records audited `whitetower.principal.deactivated.v1` event. `Reactivate` restores active status and records `whitetower.principal.reactivated.v1`.
- Contracts and audit:
  - Added event schemas and examples for `whitetower.principal.deactivated.v1` and `whitetower.principal.reactivated.v1`.
  - Registered events in `api/events/catalog.json` and added fact rules in `internal/audit/facts.go`.
- Tests:
  - ST-14 in `internal/authn/session_test.go`: verified cookie attributes, session rotation, idle and absolute timeout expiration, revocation at logout, revocation on principal deactivation, and background cleanup.
### 2026-10-15: OIDC login, role mapping and /me (PR 3)

- Backend-For-Frontend (BFF) authentication flow (`internal/authn/oidc.go`):
  - Implemented `OIDCService` handling `/auth/login`, `/auth/callback`, and `/auth/logout`.
  - OpenID Connect authorization code flow with PKCE (RFC 7636, S256 code challenge and verifier).
  - State and nonce stored in ephemeral HMAC-SHA256 signed cookies (`__Host-wt_oidc` or `wt_oidc`), with 10-minute expiry, bound to the client.
  - Return URL validation (`ValidateReturnURL`, ST-15): strictly permits console-relative paths starting with `/` and refuses external schemes, authority-relative URLs (`//`), backslashes, control characters, and CRLF injections.
  - Login rate limiting (ST-22): applies token bucket rate limiting on `/auth/login` to thwart brute-force and amplification attempts.
  - ID token verification (ST-16): validates issuer against IdP discovery metadata, audience against configured ClientID, token expiration against injected clock, nonce match against signed login cookie, cryptographic signature via JWKS, and verifies signing algorithm against allowed algorithm whitelist (`AllowedAlgorithms`, defaulting to `RS256`, rejecting `none` and symmetric HMAC algs).
  - Principal provisioning: calls `PrincipalStore.UpsertHuman` on successful login to synchronize identity attributes and refuses authentication if principal status is inactive (403 Forbidden).
  - RP-initiated logout: revokes active session in PostgreSQL and clears cookies, redirecting to the IdP's `end_session_endpoint` with `post_logout_redirect_uri` when advertised.
- Role mapping (`internal/authn/roles.go`):
  - `ResolveEffectiveRoles`: maps IdP claim groups (configurable via `groups_claim`, normalizing leading slashes) using configurable `role_mapping`, merges with local `role_bindings`, validates each role against the governance model via `authz.IsValidRole`, and deduplicates into sorted effective roles.
- `/api/v1/me` and OpenAPI contracts:
  - Extended OpenAPI schema `Principal` with `permissions` (required list of permission IDs derived via `authz.PermissionsList(roles)`) and `csrfToken` (optional session CSRF token).
  - Updated `Server.GetMe` in `internal/api/rest/rest.go` to populate `permissions` and attach `csrfToken` from `authn.SessionFromContext(ctx)`.
  - Regenerated REST server, API client, and web console TypeScript definitions (`task gen:openapi`).
- Configuration:
  - Added `Auth.OIDC` section in `internal/platform/config` (`issuer`, `client_id`, `client_secret_file`, `redirect_url`, `scopes`, `groups_claim`, `role_mapping`, `allowed_algorithms`). Updated environment overrides and configuration reference documentation.
- Development realm:
  - Extended `deploy/compose/dev/keycloak/whitetower-realm.json` with user `multirole` (groups `/wt-owners`, `/wt-operators`) and user `inactive` (`enabled: false`) for integration and pilot testing (step 11).
- Server mounting:
  - Mounted `/auth/` routes on the public console listener in `internal/server/handlers.go` (`ConsoleHandler(api, auth http.Handler)`).
- Tests:
  - ST-15 in `internal/authn/oidc_test.go`: table-driven tests for open redirect prevention.
  - ST-22 in `internal/authn/oidc_test.go`: login endpoint rate limiting and recovery.
  - ST-16 in `internal/authn/oidc_test.go`: mock IdP server testing wrong issuer, wrong audience, expired token, mismatched nonce, and algorithm `none`.
  - Inactive principal login refusal and RP-initiated logout session revocation tests.
  - Unit tests in `internal/authn/roles_test.go`: role resolution, prefix normalization, invalid role ignoring, and deduplication.
  - Golden file and HTTP endpoint tests in `internal/api/rest` and `internal/api/rest/resttest` asserting `permissions` and `csrfToken`.

### 2026-10-15: API tokens and service accounts (PR 4)

- `internal/authn/tokens.go`: personal access and automation token management (`TokenStore`, HUM-03, HUM-05; ST-19).
  - High-entropy cryptographic token generation: `GenerateToken` generates 256 bits of CSPRNG entropy encoded as URL-safe base64 with `wt_pat_` prefix and 15-character display prefix.
  - Token hashing: stores exclusively SHA-256 hashes (`token_hash bytea UNIQUE`) in PostgreSQL `whitetower.api_tokens`. Raw tokens are returned once and never stored.
  - Expiry and lifetime: defaults to 30 days, configurable up to 90 days. Expired tokens are rejected (`ErrTokenExpired`).
  - Scopes: strictly validates requested scopes against the governance permission catalog and requires at least one valid scope.
  - Usage tracking: touches `last_used_at` synchronously upon every successful authentication.
  - Revocation: supports individual revocation with an audit trail, and bulk cascade-revocation when a principal is deactivated (`RevokeAllForPrincipalTx`).
- Service accounts (`internal/authn/principal.go`):
  - Non-human principals (`kind: service_account`) tied to an active responsible human principal.
  - Prevents creating service accounts with inactive or nonexistent responsible principals.
  - Cascade deactivation: deactivating a responsible human automatically deactivates associated service accounts and revokes their API tokens inside the same transaction.
- Authentication and authorization:
  - `Authenticator` (`internal/authn/authenticator.go`): accepts `Authorization: Bearer <token>`, looks up token hash via `TokenStore`, verifies active status and expiration, resolves effective roles, and populates `auth.Principal` with `Scopes`.
  - `Authorizer` (`internal/authz/authorizer.go`): enforces token scopes. If `p.Scopes` is non-nil, an operation is allowed only if permitted by both the principal's roles and present in the token's scopes (ST-19).
- REST API and OpenAPI contracts (`api/openapi/openapi.yaml`, `internal/api/rest`):
  - Added endpoints: `GET /tokens`, `POST /tokens`, `DELETE /tokens/{id}`, `GET /service-accounts`, `POST /service-accounts`.
  - Scope validation in `CreateToken`: enforces that requested token scopes must be a strict subset of the principal's effective role permissions.
  - Generated Go server, API client, and console TypeScript definitions via `task gen`.
- Audit events:
  - Added `whitetower.token.created.v1` and `whitetower.token.revoked.v1` schemas, examples, catalog entries, and facts rules. Updated `facts.json` golden file.
- Tests:
  - ST-19 in `internal/authn/tokens_test.go`: verified scope enforcement, token expiry, storage only as a hash, revocation on principal deactivation, manual revocation, service account lifecycle, and input validations.
  - REST API endpoint tests in `internal/api/rest/rest_test.go` covering creation, listing, service accounts, and revocation.

### 2026-10-15: CLI token exchange and break-glass (PR 5)

- CLI token exchange (`POST /tokens/exchange`, HUM-06, API-04; threat model T-12):
  - Validates OpenID Connect ID tokens issued for the CLI audience (`wtctl`, configurable via `auth.oidc.cli_client_id`).
  - Provisions or synchronizes the human principal record in PostgreSQL (`whitetower.principals`).
  - Evaluates effective roles via configured role mappings and local bindings, resolving permitted scopes.
  - Generates a short-lived (12-hour) personal access token (`wt_pat_`) bound to the principal.
  - Emits the audited `whitetower.token.created.v1` event with `reason: "CLI token exchange (wtctl)"`.
  - Refuses deactivated principals with 403 Forbidden (`ErrPrincipalInactive`), expired or invalid tokens with 401 Unauthorized (`ErrInvalidToken`), and missing inputs with 400 Bad Request.
- Emergency break-glass (`internal/authn/breakglass.go`, HUM-06, KIL-08; ST-20; threat model T-71):
  - Disabled by default. Configured via `auth.breakglass.enabled` and `auth.breakglass.credential_hash_file`.
  - Secret protection: credential hash file path marked as sensitive in `cmd/whitetower/security_test.go` (`TestSecretsNeverLeak`).
  - Subcommand `whitetower breakglass init`: generates 256 bits of CSPRNG entropy (`wt_bg_...`), computes salted SHA-256 hash (`$wt$1$<salt>$<hash>`), writes to hash file (`0600`), and outputs plaintext credential once.
  - Endpoint `/auth/breakglass`: rate-limited (5 attempts/min per IP/client), verifies candidate credential using constant-time comparison against the stored salted hash file.
  - Provisions custodian principal (`00000000-0000-0000-0000-000000000001`, `issuer: "whitetower:breakglass"`, `subject: "custodian"`), creates a 1-hour session (`method: "breakglass"`), records critical audit event `whitetower.breakglass.used.v1`, logs security alert (`SECURITY ALERT: break-glass emergency credential used`), and sets session cookie.
  - Enforces strict operational boundaries (ST-20): can halt agents and the fleet and read inventory and audit logs (`haltAgent`, `haltFleet`, `getMe`, `listAgents`, `getAgent`, `getAuditEvents`, `getAuditCheckpoints`, `exportAudit`), and **nothing else** (release is refused, configuration/tokens/service accounts/policies are refused).
  - Works independently of IdP availability. Session strictly expires after 1 hour.
- Audit and contracts:
  - Added event schema `api/events/schemas/whitetower.breakglass.used.v1.json`, complete example `api/events/examples/whitetower.breakglass.used.v1.json`, entry in `catalog.json`, facts indexing rule in `internal/audit/facts.go`, and updated `facts.json` golden file.
  - Added OpenAPI operation `exchangeToken` (`POST /tokens/exchange`, `security: []`) and extended `Principal` with boolean `isBreakglass`.
  - Regenerated code via `task gen:openapi`.
- Tests:
  - ST-20 in `internal/authn/breakglass_test.go`: verified emergency login flow, 1-hour session lifetime, rate limiting, critical audit event emission, ERROR alert logging, permitted emergency operations, refusal of all other operations, and session expiry.
  - `internal/authn/oidc_test.go`: `TestExchangeIDToken` (happy path 12h exchange, wrong audience refusal, expired token refusal, deactivated principal refusal).
  - `cmd/whitetower/breakglass_test.go`: `whitetower breakglass init` CLI execution, file output permissions, header output, and hash verification.
  - `internal/api/rest/rest_test.go`: `TestExchangeTokenEndpoint` and `/api/v1/me` asserting `isBreakglass: true`.

### 2026-10-16: SCIM 2.0 deprovisioning and SAML broker guide (PR 6)

- SCIM 2.0 deprovisioning (`internal/authn/scim.go`, HUM-05; ST-21; threat model T-18):
  - Implements RFC 7643 and RFC 7644 core user endpoints under `/scim/v2/Users` and `/scim/v2/Users/{id}`.
  - Dedicated authentication: protected by a bearer token loaded from `auth.scim.token_file` (configured under `auth.scim.enabled` and `auth.scim.token_file`). Unauthenticated or invalid requests receive 401 Unauthorized (`application/scim+json`).
  - Secret protection: `auth.scim.token_file` covered by `cmd/whitetower/security_test.go` (`TestEverySecretFileIsCovered` and `TestSecretsNeverLeak`).
  - User search and pagination: supports `filter=userName eq "..."`, `startIndex` (1-based), and `count` (bounded), returning standard SCIM `ListResponse`.
  - User provisioning (`POST /scim/v2/Users`): provisions human principals with conflict detection on duplicate `userName` (409 Conflict).
  - Deprovisioning (`PATCH /scim/v2/Users/{id}` with `active: false` or `DELETE /scim/v2/Users/{id}` as deactivation):
    - Sets principal status to `inactive` in PostgreSQL.
    - Revokes all active user sessions immediately in PostgreSQL (`SessionStore.RevokeAllForPrincipal`).
    - Revokes all personal access tokens (`TokenStore.RevokeAllForPrincipal`).
    - Emits critical audit event `whitetower.principal.deactivated.v1` attributed to SCIM service account (`00000000-0000-0000-0000-000000000002`).
  - Reactivation: supports `PATCH /scim/v2/Users/{id}` with `active: true` setting status back to `active`.
  - Server wiring: mounted on `/scim/v2/` via `ConsoleHandler` in `internal/server/handlers.go` and `cmd/whitetower/main.go`.
- SAML through a broker guide and verification (`docs/guides/saml-broker.md`, HUM-08):
  - Step-by-step enterprise guide configuring Keycloak as an identity broker to SAML 2.0 Identity Providers (Entra ID, Okta, Active Directory Federation Services).
  - Documents IdP SAML configuration, NameID and attribute statements, SAML group claim extraction, and role mapping to White Tower governance roles (`admin`, `operator`, `owner`, `auditor`, `user`).
  - Integration test `TestSAMLThroughBroker` in `internal/authn/saml_test.go` validating the brokered assertion ingestion, attribute/group mapping, principal provisioning, and session establishment.
- Tests:
  - ST-21 in `internal/authn/scim_test.go`: bearer token verification, user provisioning, filter query, deprovisioning via PATCH `active: false`, session and API token revocation, audit event verification, delete as deactivation, and reactivation via PATCH `active: true`.
  - `internal/authn/saml_test.go`: end-to-end SAML identity brokering and role mapping test.

### 2026-10-19: service accounts and token scopes (fix)

A review of P1-04's API found two ways around the permission matrix, which this fix closes (the maintainer's decision of 2026-10-19).

- **Service accounts.** Anyone could create a service account with any role, the advisory, operator and admin roles included, and then a token with that role's permissions. Now:
  - only a person is responsible for a service account, and gives it only roles they hold (`forbidden` otherwise), as HUM-02 and DC-4 require of role grants;
  - a service account acts with the roles bound to it that its responsible principal still holds, read when its token is used. It loses a role when that person loses it, and every role while that person is inactive (step 6: "a scoped token can do exactly what its scopes and its owner's roles allow").
- **Token scopes.** `createToken` checked the requested scopes against the roles of the token's principal only. A token holding `identity.me.read` could therefore create a token with every permission of its principal, and an administrator could create a token for anyone's service account with that account's permissions. Now each scope must also be a permission of the caller, and one of the scopes of the caller's own token when the caller uses one (ST-19).
- The notes of pull request 4 above say that deactivating a responsible human deactivates their service accounts and revokes their tokens: the code never did. Their tokens are now refused while the responsible principal is inactive. The service accounts and their tokens keep their state, so they work again if that principal is reactivated.
- Tests: a service account gets no role its responsible principal lacks, and a service account creates none (ST-18); it loses a role when its responsible principal does, and every role while that principal is inactive; a token creates no token beyond its own scopes, and an administrator gives no permission through someone else's service account (ST-19).
- Follow-ups:
  - Creating a service account with the steering, advisory or operator role is a grant that DC-4 asks to notify to the steering committee's inbox, which P1-04 builds (its pull request 7).
  - A person and their own service account are two principals: two-person rules of later plans (policy approvals in P1-06, halt releases in P1-08, enabling and unblocking in P1-16) must not count them as two people, as P1-04 refuses decisions on proposals to service accounts.
  - No operation hands a service account to another person, so one whose responsible principal left stays unusable until they come back.

### 2026-10-27: the erasure of a person (HUM-09)

Mapping the GDPR in the [framework mapping](../../security/framework-mapping.md) found that the domain model designs an erasure of a person's name and email (its section 7), and that no requirement or plan built it. On 2026-10-27 the maintainer decided that the MVP has it: HUM-09, a Should, and step 13, which pull request 7 builds ([AGENTS.md](../../../AGENTS.md), work queue).

The step erases the IdP subject as well as the name and the email, which the domain model's design left out: a subject kept would let the next login match the erased principal and write the person's name back. It erases only inactive people, and it is final.

The threat model gains T-85: an administrator erases a principal to make what that person did unattributable. The mitigations are an erasure only after a deactivation, which is itself audited, a reference to the request, and an audit event that names the actor. The security test catalog gains ST-88. Until pull request 7 lands, the plans index shows P1-03 in progress, and `test/security` asks for the markers of its security tests, ST-88's included, once it is done again.

### 2026-11-02: findings and decisions from the review of the sign-in fix

The review of P1-12's sign-in fix ([P1-12's progress notes](P1-12-packaging-and-deployment.md#progress-notes) of 2026-11-02) read P1-03's code on the way, and confirmed each of these on `main` by reproduction:

| Finding | Requirement | Work queue |
| --- | --- | --- |
| `DELETE /api/v1/tokens/{id}` needs only `identity.me.read` and checks no owner, so any signed-in principal revokes any principal's token | HUM-03, ST-19 | P1-03 fix: access control and sessions |
| A sign-in creates a session without revoking the one the browser holds. `SessionStore.Rotate` has no caller outside tests, and the test marked ST-14 calls it directly | ST-14 | The same |
| The authenticator falls back to the unprefixed `wt_session` whatever the cookie mode, which undoes the `__Host-` prefix | ADR-0009, ST-14 | The same |
| `dev.self_signed_tls` drops `Secure` and the prefix although the stacks' console serves HTTPS, so the session cookie also goes to Keycloak's HTTP port on 127.0.0.1 | ST-14 | The same |
| With OIDC off, `main` passes a typed nil as the REST API's exchanger, so the public `POST /api/v1/tokens/exchange` panics into a 500 | | The same |
| ST-03 never turns on OIDC, break-glass or SCIM, so the canaries in their secret files are never read | ST-03 | The same |
| A plain-HTTP `auth.oidc.issuer` is accepted outside development, though discovery, the token endpoint and the keys go through it | T-13 | The same |
| Discovery at start is fatal and comes before break-glass, so a core that starts while the identity provider is down serves nothing | KIL-08, HUM-06 | P1-03 fix: the identity provider's availability, and several replicas |
| The OIDC state is signed with a key that each process makes at random, so a sign-in that ends on another replica, or after a restart, fails | NFR-06 | The same |
| A sign-in creates a principal and rewrites its groups, from which its roles come, without an audit event | AUD-01 | P1-03 fix: audit events for people and their sessions |
| SCIM creates a principal under the issuer `scim` and the userName, and a sign-in another under the provider's issuer and `sub`. Nothing links them, so a SCIM deactivation leaves the person who signs in active | ST-21 | P1-03 fix: SCIM and sign-in share one principal |

The maintainer's decisions of 2026-11-02:

1. **The identity provider's availability.** The core starts while the identity provider is down, and discovers it in the background, with backoff and a timeout on each attempt. Meanwhile the sign-in routes and the token exchange answer 503, and break-glass and the machine listener work. Only configuration errors stop the start. The alternative, discovery kept fatal and documented, breaks KIL-08 and HUM-06 on a restart during an outage.
2. **Several replicas.** The OIDC state is signed with a shared key read from a file, `auth.oidc.state_key_file`, as the other secrets are. The alternative, the state kept in PostgreSQL, single use and expiring, needs no secret, but more code and a table to clean.
3. **SCIM and sign-in.** SCIM stores the `externalId` that the identity provider sends, and a sign-in matches the principal whose `externalId` equals a configurable claim of the ID token: `sub` by default, `oid` for Entra ID. The alternatives: adopting a principal by verified email, simpler to configure but tied to an address that changes and to a meaning of "verified" that varies between providers; or deferring, which leaves SCIM deprovisioning without effect on people who sign in.
4. **Audit.** The creation of a principal, a change of its groups (before and after), and each sign-in and sign-out of a person write audit events. The alternative, creations and group changes only, leaves the log silent on who signed in, and when.

### 2026-11-02: access control and sessions (fix)

The review of P1-12's sign-in fix confirmed seven problems in P1-03's code on `main` by reproduction. This fix closes them.

- **Token revocation (HUM-03, ST-19).** `DELETE /api/v1/tokens/{id}` needed only `identity.me.read`, which every role holds, and checked no owner: any signed-in principal revoked any principal's token. `TokenStore.Revoke` now applies the rule of `listTokens`: a caller revokes their own tokens, those of the service accounts they are responsible for, and any token as an administrator. Any other token is `not_found`, revoked or not, as a token that does not exist is, so that an ID never shows whether a token exists. The store decides, not the handler: the rule then holds for every caller of the store, and it reads the token in the transaction that revokes it. The OpenAPI description says who may revoke.
- **Rotation at sign-in (ST-14).** A sign-in created a session and left valid the one that the browser held. `SessionStore.Rotate` had no caller but its own test, which carried the ST-14 marker. The OIDC callback and break-glass now revoke the sessions that the request's session cookies name, under `__Host-wt_session` or the unprefixed `wt_session`, whoever they belong to, in the transaction that creates the new session (`SessionStore.Replace` and `ReplaceTx`). A sign-in that fails revokes nothing. `Rotate` is gone: a sign-in can change the principal and the roles, which `Rotate` kept. The notes of pull request 2 above say that `Rotate` runs when the authentication state changes: nothing called it.
- **The session cookie's name (ADR-0009, ST-14).** The authenticator fell back to `wt_session` whatever the cookie mode, so a cookie that another host of the domain or a plain HTTP page planted signed the browser in as whoever planted it. It now reads `__Host-wt_session` only.
- **The cookie mode.** `dev.self_signed_tls` turned off `Secure` and the `__Host-` prefix, although the console serves HTTPS in every configuration, self-signed certificate included. The session and state cookies are now always `Secure`, with the prefix, and the `SecureCookies` options are gone. The notes of pull request 2 above say that the core falls back to `wt_session` without TLS: it no longer does. Through the Vite development server on `http://localhost:5173`, Chromium keeps these cookies, since it treats `http://localhost` as secure. This was checked on 2026-11-02 with the core of this fix, the development Keycloak and Vite's proxy, in Chromium 153: two people signed in in turn, and the first session was refused afterwards.
- **The token exchange and SCIM without their services.** With OIDC off, `main` passed a nil `*authn.OIDCService` as the REST API's exchanger. The interface was then not nil, so the public `POST /api/v1/tokens/exchange` panicked into a 500, with a stack in the log. `main` now gives the API an exchanger only when OIDC is on. A server without OIDC sign-in has no token exchange, so the operation answers `not_found`, with the detail "token exchange is not configured", rather than `internal`, which would tell operators that the server failed. An identity provider that is configured but does not answer is another case, which the fix of its availability answers. The review found the same defect with SCIM off: `main` passed a nil `*authn.SCIMService` to `server.ConsoleHandler`, so a request under `/scim/v2/` panicked and the client saw its connection closed. `main` now mounts SCIM only when it is on, and its paths answer as any unknown path does. No other optional service of `main` is wired this way: OIDC and break-glass are mounted only when they exist.
- **ST-03.** The test wrote canaries into the files of the OIDC client secret, the break-glass hash and the SCIM token, but turned none of these services on, so nothing read them. It now turns on break-glass and SCIM and sends each a wrong credential, a canary too. It also signs in through a provider of its own, whose token endpoint refuses the authorization code, another canary. It fails if break-glass or SCIM do not answer as services that are on, or if the provider never received the client secret of the file. That provider serves plain HTTP, which only development allows (below), so the sign-in runs on a second server with the development certificate, while the first one serves the canary key.
- **A plain-HTTP issuer (T-13).** Browsers sign in at `auth.oidc.issuer`, and without `auth.oidc.discovery_url` the server takes the discovery document and the signing keys from it. An `http` issuer is now refused unless `dev.self_signed_tls` is set, which the stacks and `task run` set and a release build refuses (T-61).
- **ST-14 against the code.** Met: session fixation, since a sign-in makes its own token and revokes the one the browser held; the cookie flags (`__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, path `/`); idle and absolute expiry; rotation at sign-in, through OIDC and break-glass; revocation at logout through OIDC, and on deactivation. Not met, and follow-ups:
  - revocation on role changes: roles are copied into a session at sign-in. A change of groups at the identity provider takes effect at the next sign-in, which revokes only the session of that browser. The person's other sessions keep their roles until they expire, 12 hours at most. Step 4's local bindings change only when a service account is created, and service accounts have no sessions;
  - revocation at logout for break-glass alone: `/auth/logout` exists only with OIDC on, so without OIDC a break-glass session ends only when it expires, after one hour.
- Tests: refused revocations of another person's token, of another person's service account's token, and of another person's revoked token, with the answer of a token that does not exist, the token still working and no event; allowed revocations of one's own token, of one's service account's, and as an administrator, with the token refused afterwards and one event that names the caller as actor and the token's principal (ST-19). A sign-in through the callback revokes the previous person's session, the same person's, and one planted under `wt_session`, and a failed one revokes nothing; its cookies are `Secure`, with the prefix (ST-14). The same for break-glass, and for a refused credential (ST-14). `wt_session` alone signs nobody in (ST-14). Through the server's wiring, with OIDC off, the exchange answers `not_found` as not configured, and with SCIM off, `/scim/v2/Users` answers as an unknown path; nothing panics. An `http` issuer is refused outside development. ST-03 as above.
- Follow-ups:
  - The `Secure` cookie does not keep the session cookie off Keycloak's plain HTTP port in the stacks. Chromium treats `http://127.0.0.1` as secure too, so it sends `Secure` and `__Host-` cookies to every port of 127.0.0.1: checked on 2026-11-02, as the review found. Only another host name for Keycloak, such as `localhost`, would isolate them, which changes the stacks' issuer, realms and seed (P1-12).
  - The administrator's exception is a role, as in `listTokens`: a token of an administrator that holds only `identity.me.read` revokes any token.

### 2026-11-03: the identity provider's availability, and several replicas (fix)

The maintainer's decisions 1 and 2 of 2026-11-02, above. A core that started while the identity provider was down exited before it served break-glass, and a sign-in that ended on another replica, or after a restart, failed.

- **The core starts while the identity provider is down (KIL-08, HUM-06).** `authn.NewOIDCService` no longer reaches the provider. It checks the options and reads the CA file, and fails only on them, as `main` fails on a client secret or a state key file that it cannot read or parse: only the local configuration stops the start. `OIDCService.Run`, which `main` starts with the other background work, discovers the provider: at once, then a second after the first failure, and after twice the delay each time, up to a minute, on the injected clock. It retries whatever an attempt returned, an HTTP error, a closed connection, a malformed document and an issuer mismatch included, since a provider in the middle of an upgrade can answer wrongly for a while. A document that names another issuer is still refused, on every attempt (ST-16). Each failure is logged once, with its reason, sanitized, and the delay before the next attempt: once the delay has grown, one line a minute. Once discovered, the provider stays discovered until the core stops, as before.
- **Until discovery succeeds:**
  - `/auth/login` and `/auth/callback` answer 503, with `Retry-After: 10` and a fixed text;
  - `POST /api/v1/tokens/exchange` answers the new problem code `unavailable`, with HTTP 503 and `Retry-After: 10`, in the OpenAPI document and the errors reference. Without OIDC, the exchange stays `not_found`;
  - `/auth/logout` still revokes the session and clears its cookie, then sends the browser to the console's root, since the provider's end session endpoint is not known yet;
  - break-glass, the API with sessions and API tokens, and the machine listener are served from the start.

  The service keeps what discovery found behind an atomic pointer, which each request reads once, so that a discovery that ends meanwhile changes nothing halfway through a request.
- **Readiness and health.** `/readyz` checks the database and the schema, as before, so a replica stays ready while discovery retries: a load balancer that took it out would cut off break-glass and the machine listener too. `/healthz` answers `ok` while the operations listener serves. The log says `sign-in is unavailable: discovering the identity provider failed`, and the new gauge `whitetower_oidc_provider_discovered`, registered only when OIDC is on, is 0 until discovery succeeds, then 1.
- **One HTTP client for the identity provider.** Every call to the provider goes through one `http.Client` that the service makes, with a timeout of 10 seconds. Discovery takes it from `oidc.ClientContext`. The signing keys come through it too: go-oidc v3.21.0 fetches them with the client of the context that created the provider (`Provider.remoteKeySet`), and ignores that context's cancellation. The token exchange takes it from its context too, as oauth2 v0.36.0 does (`internal.ContextClient`). The core asks for no userinfo. A discovery attempt is one request, so the timeout bounds each attempt. `OIDCOptions.HTTPClient`, which only tests set, is gone.
- **`auth.oidc.ca_file`.** An optional PEM file with the certificate authorities of the provider's back channel: `auth.oidc.discovery_url`, or `auth.oidc.issuer` without it. As with `tracing.otlp.ca_file`, it is refused unless that URL is https, and its authorities replace the system's. A CA file that cannot be read, or holds no certificate, stops the start. Its TLS configuration comes from the new package `internal/platform/tlsclient`, which tracing's OTLP client now uses too: the code moved there from `internal/platform/tracing`, unchanged.
- **`auth.oidc.state_key_file` (NFR-06).** The state cookie of a sign-in is signed with the key of this file, rather than with 32 random bytes that each process made. It is required with `auth.oidc.issuer`, as `auth.oidc.client_secret_file` is, by `CheckServe`. Its format is base64, as `openssl rand -base64 32` writes it, with whitespace left out, and at least 32 bytes once decoded.
  - Base64 rather than raw bytes: the file is text, as the other secret files are, so a trailing newline that an editor adds changes nothing, and the decoded length can be checked, so that a password or a short value is refused rather than used.
  - At least 32 bytes: the output size of HMAC-SHA256, below which RFC 2104 (section 3) says that a key weakens the MAC.
  - A file that is not base64, or holds a shorter key, stops the start, and the error repeats nothing of the file.
  - The stacks and `task run` read the development key `deploy/compose/dev/secrets/oidc-state-key`, mounted as the client secret is. It is public, and reads as one: `whitetower/oidc/state/key/for/local/development/only` is base64 of 39 bytes.
- **The stacks** still start the core once Keycloak is healthy, which they no longer need: sign-in then works as soon as the core is up. Their comments, the development services' README, the evaluation stack's README, the development guide and the SAML broker guide say so, and how to make a state key.
- **Tests:**
  - through `serve`: a core whose provider answers 503 starts, is ready and healthy, serves break-glass, a session, an API token and the machine listener, answers 503 on `/auth/login`, `/auth/callback` and the exchange, logs that sign-in is unavailable and reports the gauge at 0; once the provider is up, a sign-in works without a restart, and the gauge is 1;
  - through `serve`: a sign-in that starts on one replica ends on another that reads the same state key file, with a session that both accept; a replica with another key refuses it;
  - the backoff on a fake clock: the delays are 1, 2, 4, 8, 16, 32, 60 and 60 seconds, no attempt comes before its delay, every kind of failure is retried and logged with its reason, and sign-in becomes available without a new service;
  - each attempt against a provider that accepts connections and never answers ends with the client's timeout, and the next attempt follows; `Run` returns when its context ends;
  - an `httptest` TLS provider is trusted with `auth.oidc.ca_file`, for discovery, the token exchange and the signing keys of a sign-in and of the CLI exchange, and refused without it;
  - two services with the same state key share a sign-in, and a service with another key refuses it; `ParseStateKey` takes a wrapped key and refuses a short one, a passphrase and URL-safe base64, without repeating them;
  - the refusals of the new settings: the CA file without an https back channel, in `TestLoadNamesTheBadSetting`, and the state key file missing with an issuer, in `TestEachCommandChecksWhatItNeeds`, since `CheckServe` checks it as it checks the client secret file; `NewOIDCService` refuses a missing or short state key and a CA file that it cannot use;
  - ST-03: the state key's file holds a canary, its base64, which never leaves the file; the test fails unless the state cookie is signed with that key, so the server read the file. `TestEverySecretFileIsCovered` classifies both new files;
  - the packaging tests check that both stacks and `task run` give the core a state key that it accepts.
- **Differences from the brief:**
  - `/auth/logout` does not answer 503 before discovery: it signs the browser out of the core, so that a person can always sign out.
  - `audit.export.otlp.ca_file` adds its authorities to the system's, unlike `tracing.otlp.ca_file` and what both settings' references say. `auth.oidc.ca_file` follows the references and tracing. The audit sink keeps its own code, since changing what it trusts is outside this fix: a follow-up.
- **Follow-ups:**
  - The Helm chart (the work queue's row 19), which no longer starts with `auth.oidc.issuer` set until it has: a Secret for the state key, from a value or an existing Secret, mounted as a file and named by `auth.oidc.state_key_file` in the ConfigMap; a value for `auth.oidc.ca_file`, with its volume; and the values and the egress rule that the row already lists.
  - Rotation of the state key: a new key refuses the sign-ins in flight, for at most the state cookie's 10 minutes. Accepting the previous key for that long would let operators rotate it without that.
  - The audit sink's CA file, above.

### 2026-11-03: audit events for people and their sessions (fix)

The maintainer's decision 4 of 2026-11-02, above. A sign-in created a principal and rewrote its groups, from which its roles come, outside any transaction and with no event, and neither a sign-in from a browser nor a sign-out left a trace in the audit log (AUD-01).

- **Four core event types**, each with its schema, example, catalog entry and indexing rule, named after `token.created` and `token.revoked`:

  | Type | Recorded when | Actor |
  | --- | --- | --- |
  | `whitetower.principal.created.v1` | A person's principal is created: at the first sign-in, through OIDC, the CLI's exchange or break-glass, or by SCIM. It holds the groups | The person; the break-glass custodian; SCIM's service account |
  | `whitetower.principal.groups_changed.v1` | A sign-in brings other groups, compared as sets: the groups before and after | The person whose sign-in carried them |
  | `whitetower.session.created.v1` | A person signs in from a browser through OIDC: the session's roles and its end | The person |
  | `whitetower.session.revoked.v1` | A request ends an active session: a sign-out (`signed_out`), or a sign-in in the browser that held it (`replaced`), which can be another person's | Who signed out, or who signed in |

  They name people by principal ID only, and hold no name, email address, IdP subject, token or hash of a token. As in the other events about people, their subject is the principal's ID.
- **Each sign-in recorded once.** A break-glass sign-in keeps `whitetower.breakglass.used.v1` as its record, and the CLI's sign-in `whitetower.token.created.v1`: neither writes `session.created`. Both write `principal.created` and `principal.groups_changed` when they apply. Break-glass's first use creates the custodian's principal, whose groups are always empty, so it records that creation and no change of groups; the schema of a change still allows `breakglass`, so that the emergency path never fails on it.
- **One transaction per sign-in.** `PrincipalStore.SignIn` replaces `UpsertHuman`. It locks the principal's row, creates or updates it, records its events, then runs the rest of the sign-in in the same transaction: the session of the callback, or the token of the exchange. A failure anywhere rolls back the principal's change with its events. `OIDCService` no longer reads the database itself, so `NewOIDCService` takes no database. The callback and the exchange read the ID token's claims through one function, `identityOf`, rather than with two copies of the same code.
- **Two sign-ins of one person at once.** `SignIn` locks the principal's row with `SELECT ... FOR UPDATE` before it reads the groups, so a second sign-in records its change from the groups that the first wrote. A first sign-in inserts with `ON CONFLICT DO NOTHING`. Under READ COMMITTED, an insert that meets a row that another transaction inserted waits for that transaction and, once it commits, inserts nothing; the next lock, a new statement, finds the row. Two first sign-ins, on one replica or two, thus create one principal and record one creation. `xmax = 0` in the former upsert tells which statement inserted, but not the groups before an update whose row another transaction inserted, since the statement's snapshot does not see them. A test holds the first sign-in at its event, with a lock on the audit log, until the second waits for it, with a first sign-in and with a known person.
- **Groups as sets.** Principals keep their groups sorted, each once, and events record them so: the same groups in another order record nothing. The first sign-in records its groups in `principal.created`, and no `groups_changed`: a change needs a before, and the creation already says what the groups are. The creation and the changes after it give a principal's groups at any time.
- **Sign-out.** `/auth/logout` revokes the session of its cookie only while the session is active, as `SessionStore.Get` judges it, and records that revocation with the session's principal and method, a break-glass session's included. A revoked, expired, unknown or empty cookie changes and writes nothing, so that a request that needs no authentication cannot add to the log. A revocation that fails is logged, and the cookie is still cleared. A sign-in that revokes the session the browser held records it as `replaced`, with whoever signs in as actor. The revocations of a deactivation stay recorded by `principal.deactivated`, and expiry records nothing.
- **Inactive principals.** The callback and the exchange refuse an inactive principal before anything is written: its name, email address, groups and last login stay as they were, no event is written, and the session that the browser held is not revoked, as for any sign-in that fails. Before, the upsert rewrote them, then refused.
- **SCIM.** A creation by SCIM records `principal.created` with SCIM's service account as actor, and never a sign-in. `PrincipalStore.ProvisionHuman` only inserts: a userName that exists is a 409, also when another creation of the same userName overtook the handler's own check, where the upsert overwrote the principal's name and email. SCIM no longer sets a last login, since it signs nobody in. Its matching is unchanged: the next fix changes it.
- **The size of the groups claim.** The claim has no bound of its own, but the ID token that carries it has: oauth2 v0.36.0 reads the token endpoint's answer up to 1 MiB, and the console refuses a request body over 1 MiB, the exchange's included. The identity provider signs the token, so nobody can enlarge their own groups, and an event of a change holds at most about twice the claim. No refusal was added.
- **Personal data.** A person's groups now reach the sealed log, tied to the pseudonymous principal ID, as the decision asks. Section 7 of the [domain model](../../architecture/domain-model.md#7-personal-data) says so: an erasure (step 13) clears them in `principals`, and the sealed events keep them until retention drops their month. The [framework mapping](../../security/framework-mapping.md) names the new types as evidence.
- **Tests:**
  - a first sign-in records the creation, with the groups as a set, and no change; the same groups in another order record nothing; other groups record one change through the exchange, with the groups before and after;
  - sign-ins of one person at once, on two replicas' stores: one creation, and each change from the groups before it, for a first sign-in and for a known person;
  - a sign-in whose session fails leaves no principal, no change of groups and no event; a writer that refuses the events leaves no principal and no change; a sign-out that cannot be recorded leaves the session valid;
  - through the callback: the creation and the sign-in, with the session's roles and its end, and the revocation of another person's session that the browser held, as replaced by the person who signs in;
  - through the exchange: the creation and a change of groups, a token per exchange, and no session;
  - an inactive principal at the callback and at the exchange writes nothing, and the session that the browser held stays valid;
  - a sign-out records the revocation of an active session, a break-glass session's included, and nothing for a revoked, expired, unknown or empty cookie, or for none;
  - break-glass records its use twice and the custodian's creation once, no session, and the revocation of the session that the browser held;
  - SCIM records the creation as its own and no sign-in; a userName that exists is a 409 through the handler, and `ErrPrincipalExists` through the store, with nothing recorded;
  - no event of these types holds the names, email addresses, IdP subjects or tokens of the tests, nor the SHA-256 of a session token in any encoding.
- **Differences from the brief:**
  - `session.created` holds the session's roles and its end as well: the groups do not give the roles alone, since the role mapping and the local bindings change too.
  - A race between two SCIM creations of one userName now answers 409 rather than overwriting the principal, and SCIM sets no last login: both follow from creating without an upsert, which the event of a creation needs.
- **Follow-ups:**
  - The creation of a service account, and its role bindings, record no event. Role bindings are outside this fix.
  - The events name no session, since sessions are known by the hash of their token. Pairing a sign-out with its sign-in needs an identifier of the session that is not secret, which takes a new migration.
  - `task verify:gen` does not compare `internal/authn/authndb`, so a stale generation of the authentication queries would pass CI.
  - From the brief, outside this fix: a logout route when only break-glass is on, and logout as a GET.

### 2026-11-03: SCIM and sign-in share one principal (fix)

The maintainer's decision 3 of 2026-11-02, above. SCIM created a principal under the issuer `scim` and the userName, and ignored `externalId`; a sign-in created another under the identity provider's issuer and `sub`. Nothing linked them, so a SCIM deactivation left the person who signed in active, with their sessions and tokens (ST-21).

- **The external ID.** Migration `00005` adds `external_id` to `principals`: the identity provider's ID of the person, which it sends as SCIM's `externalId` and in a claim of its ID tokens. It is 1 to 255 characters, unique among humans where set (a partial unique index), and only humans have one; the runtime role's grants on the table cover it. Service accounts and the break-glass custodian have none. Nothing is backfilled: the subject is the external ID only when the claim is `sub`.
- **The setting.** `auth.oidc.external_id_claim`, beside `auth.oidc.groups_claim`, names the claim: `sub` by default, `oid` for Entra ID. Its value must be a string, not blank, of at most 255 characters. Otherwise the callback answers 403 and the CLI's exchange `forbidden`, nothing is written, and the log names the claim, never its value. No other claim stands in for it: a principal found by `sub` when the claim is `oid` would be one that SCIM does not reach.
- **Matching at a sign-in.** The callback and the exchange both go through `PrincipalStore.SignIn`, which now requires an external ID. It locks the principal with the external ID; else the one with the issuer and subject, which it links when that principal has no external ID yet; else it creates one with the issuer, the subject and the external ID. The row lock and the insert-or-retry of the fix of audit events stay: the insert now does nothing on a conflict with either unique index, so that two first sign-ins of one person create one principal even when they carry two subjects, as Entra ID's `sub` differs between the console's client and the CLI's. A principal found by its external ID keeps its issuer and subject: SCIM's keeps `scim` and its userName, so that SCIM still finds it by its userName. A principal with the issuer and subject but another external ID, as after the claim changed, is neither changed nor joined by a second principal: the sign-in is refused, 403 at the callback and `forbidden` at the exchange, and the log names the principal. Break-glass signs its custodian in by issuer and subject, without an external ID.
- **SCIM.** A creation stores `externalId` and gives the principal the issuer `scim` and the userName as subject. A creation without `externalId`, or with a blank or overlong one, could never be the person who signs in: it is refused with 400 `invalidValue`. A userName that exists is a 409 `uniqueness`, as before, and so is an `externalId` that a user SCIM manages holds. The handler no longer looks for a collision by subject or email across every issuer: the store checks the userName under `scim`. A `PATCH` that gives the user the `externalId` it has changes nothing and is accepted, as from a client that sends every attribute. One that changes or removes it is refused with 400 `mutability`, before any of its operations applies: the external ID ties the principal to the person who signs in, so changing it would hand the principal, its roles and its agents to whoever the new value names, which the threat model's T-18 does not accept of a stolen SCIM token. SCIM's users now show their `externalId`.
- **A principal that signed in before SCIM provisioned it.** It has the person's external ID from that sign-in. SCIM's creation with that `externalId` adopts it rather than creating a second principal: SCIM's issuer and userName, the name and the email address are set on it, its ID, status, groups, last login and sessions stay, and the answer is 201 with its ID. The adoption records the new core event type `whitetower.principal.adopted.v1`, with SCIM's service account as actor and the principal's ID, and nothing that names the person; `principal.created` would have said that a principal was created twice. An adoption whose userName another creation took meanwhile is a 409, and records nothing. A principal that a sign-in created before this fix, and that has not signed in since, has no external ID yet: its next sign-in links it. Until then, a SCIM creation of that person makes a second principal, which the person's sign-ins find from then on, while the first keeps its API tokens until they expire. No release exists, so only the development and evaluation stacks have such principals: the evaluation seed's principals, written without an external ID, are linked at their first sign-in. The SAML broker guide says so for an upgrade. Principals that SCIM created before this fix have no external ID either; no sign-in reaches them, as before, and a `PATCH` cannot give them one.
- **SCIM's reach (a finding of this fix's review).** SCIM's read, list, filter, `PATCH` and `DELETE` found principals by ID, or by subject or email, whatever they were. Reproduced on `main` by `TestSCIMReachesOnlyPeople` before the change: the break-glass custodian was read (200), deactivated by `PATCH` (200) and by `DELETE` (204), listed, counted, and found by the filter `userName eq "custodian"`; a break-glass sign-in still answered 200, but its session was then refused, as its principal was inactive (KIL-08, HUM-06). A service account was read, and deactivated by `PATCH` and `DELETE`. SCIM's own principal is no row, so it was not reachable, but a row with its ID was. SCIM now reaches people only: human principals other than those that White Tower acts as, the custodian and SCIM's service account (`PrincipalStore.GetPerson` and `ListPeople`). Any other principal is "User not found", and the list and its count leave them out. The filter matched `subject = $1 OR email = $1` across every issuer with `LIMIT 1`, so its answer depended on the rows' order: it now matches SCIM's userName, the subject of a principal with the issuer `scim`. It accepts only `userName eq "value"`, with the value read as a JSON string; any other filter, `emails.value eq` included, is refused with 400 `invalidFilter`, where it was ignored and every user listed, an answer that a client looking a user up could take as a match. The SAML broker guide says which filter SCIM supports.
- **Events already in place.** A SCIM creation still records `principal.created` with method `scim`; `principal.groups_changed` and `session.created` are unchanged, and the tests of the fix of audit events pass as they were, with an external ID in their identities. No event holds an external ID, and the tests' check of what events must not hold covers it and the new type.
- **Personal data.** An external ID identifies the person at their identity provider, as the subject does: section 7 of the [domain model](../../architecture/domain-model.md#7-personal-data) lists it with the subject, and an erasure clears it. Step 13 above now says so, since a kept external ID would let the person's next sign-in find the erased principal.
- **Tests:**
  - ST-21 end to end: SCIM creates a person with an `externalId`; that person signs in through the callback, and exchanges an ID token from the CLI, and both land on SCIM's principal, with the claim `sub`, and with `oid` and two subjects; SCIM's deactivation then refuses their session and their token, and their next sign-in and exchange;
  - a person who signed in first: SCIM's creation adopts the principal, records the adoption and no creation, and keeps its groups, last login and session; the next sign-in finds it, the filter finds it by its userName, and SCIM's deactivation reaches the session;
  - a missing claim, a number, a list, an empty, a blank and an overlong claim refuse the callback and the exchange and create nothing, with `oid` configured and a `sub` present; the log names the claim and holds none of the values; the store refuses a sign-in and a provisioning without an external ID;
  - a principal with the issuer and subject and another external ID refuses the callback and the exchange, and stays as it was;
  - SCIM without `externalId`, with a blank or overlong one, with another user's, with the same user again, and with a userName that exists and another `externalId`; a `PATCH` that replaces, adds through the schema's URN, removes, or gives a value that is no string, refused whatever else it holds, and one with the value the user has, accepted;
  - SCIM's reach, as above, then a break-glass session that works; the filters that SCIM refuses, and `userName eq` in capitals and with a JSON escape;
  - sign-ins of one person at once, on two replicas: first sign-ins, with one subject and with two; a known person, with one subject and with two; and two sign-ins that link a principal without an external ID, where the second waits for the first and finds the principal linked. In each case one principal, one creation, each change from the groups before it, and the external ID stored;
  - an adoption whose userName a concurrent creation took is refused as a userName that exists, and records nothing;
  - through the REST API, the exchange's refusals are `forbidden`, with a fixed detail.
- **Differences from the brief:**
  - The filter refuses what it does not support, `emails.value eq` included, rather than only matching the userName deterministically: an ignored filter answered with every user. The review accepted it on 2026-11-04.
  - A sign-in that finds a principal by its issuer and subject with another external ID is refused, never relinked. The brief has the sign-in link only a principal without an external ID, and creating a second principal would break the uniqueness of the issuer and subject. The review accepted it on 2026-11-04.
  - SCIM's own principal is no row, so SCIM could not reach it; the restriction covers its ID should it become one.
  - The ST-21 entry of the [security test catalog](../../security/security-tests.md) now names the matching and SCIM's reach, which its tests check.
- **Follow-ups:**
  - The erasure (pull request 7) clears the external ID, as step 13 and ST-88's entry in the security test catalog now say.
  - Changing `auth.oidc.external_id_claim` after people have signed in is not supported yet, and the SAML broker guide says so. Their sign-ins are refused, and logged with the principal's ID and the claim's name, until their principals' external IDs are updated: no operation changes a principal's external ID, so that takes an operation for administrators or a migration.
  - A principal created by a sign-in before this fix, and provisioned by SCIM before its next sign-in, stays a second principal: no operation merges two principals.
  - SCIM compares userNames exactly, though RFC 7643 makes `userName` case-insensitive.
  - A `PATCH` still ignores every attribute other than `active` and `externalId`, such as `userName`, without saying so.
  - A creation with `active: false` deactivates the principal in a second transaction, and answers 201 with an active user if that fails.
  - `internal/inventory` and `adoptHuman` each read a unique violation from PostgreSQL's error: a helper in `internal/platform/db` would serve both.

### 2026-11-05: the reviews of the fixes, and the maintainer's decisions

The reviewer found the four fixes above complete: access control and sessions (#100), the identity provider's availability (#103), the audit events of people and their sessions (#104), and one principal for SCIM and sign-in (#105). The review of the last one found SCIM's reach, which the fix then closed. The follow-ups that the notes above list are unchanged. The reviews add three:

- **A stolen SCIM token.** Since #105, a SCIM token that knows a person's external ID can take over the principal that the person's sign-in created, and set its name and email address. It records `principal.adopted`, and gives neither a sign-in nor a role. The threat model's T-18 now says so (version 0.1.8).
- **Entra ID.** The SAML broker guide's details for Entra ID, `oid` with the `profile` scope and the default mapping of `mailNickname`, come from the provider's documentation, not from a tenant. The acceptance criteria already ask for one commercial identity provider, or for it as the first task of the pilot: that check covers them.
- **A refused sign-in leaves no trace**, neither in the log nor in a metric: decision 3 below.

The maintainer's decisions of 2026-11-05, on what the reviews left open:

1. **The administrator's exception for API tokens.** `listTokens`, `createToken` for another principal and `TokenStore.Revoke` let the platform administrator act on any principal's tokens because of the role, so a token of an administrator scoped to `identity.me.read` does so too. The exception becomes a permission, `identity.tokens.manage`, held by the platform administrator and checked by the authorizer, so that a token needs it in its scopes. The permission matrix gains its row (requirements, section 5.2.1). The alternatives: no exception for a token with scopes, which needs no new permission but leaves the exception outside the matrix; and `settings.manage`, which mixes settings with tokens.
2. **Roles after a change of groups (ST-14).** A session copies its roles at sign-in. A sign-in that changes a person's groups revokes the person's other sessions, in its transaction, so that no session keeps the roles of the groups before. API tokens already take their roles from the principal at each request. The alternatives: roles read at each request for sessions too, a larger change with one more query per request; and the 12 hours of a session accepted as a residual risk.
3. **Refused sign-ins.** A sign-in refused through the callback, the CLI's exchange or break-glass logs one line with its reason, and the principal's ID when there is one, and counts in a metric by method and result. It writes no audit event, since it changes nothing. The alternatives: an audit event, which would seal attempts that change no state; and nothing.
4. **SCIM's `PATCH`.** It keeps ignoring the attributes other than `active` and `externalId`, and the SAML broker guide says so: Entra ID sends `displayName`, `emails` and `name` at every synchronization, so refusing them would break its provisioning, and a sign-in already updates the name and the email. The alternatives: applying the name and the email, which a sign-in does anyway; and refusing them.

The work queue's rows "P1-03 fix: tokens and sessions" and "P1-03 fix: what identity records, and SCIM" take decisions 1 to 4, the two gaps of ST-14 and the follow-ups of #104 and #105 that they name. "Small fixes from the reviews of the identity and ingestion fixes" takes `task verify:gen` and the CA file of the audit sink.

### 2026-11-05: tokens and sessions (fix)

The maintainer's decisions 1 and 2 of 2026-11-05, above, and the two gaps of ST-14 that the fix of access control and sessions (#100) left.

- **The permission `identity.tokens.manage` (HUM-03, HUM-07, ST-19).** `listTokens`, `createToken` for another principal and `TokenStore.Revoke` let the admin role act on any principal's tokens, so an administrator's API token scoped to `identity.me.read` did too. The exception is now the permission `identity.tokens.manage`, which only the admin role holds, as the permission matrix's row says (requirements, section 5.2.1). `TokenStore.MayManageAnyToken` asks the authorizer, which `NewTokenStore` now takes and `main` wires, as the inventory does: an API token needs the permission in its scopes, and a break-glass session never has it. The two handlers and the revocation's rule use it, and nothing else checks the role. The operations themselves still need `identity.me.read`, since everyone manages their own tokens: an administrator's token that manages others' needs both scopes. `/me` lists the new permission for administrators. The OpenAPI descriptions of the three operations say who may act on another principal's tokens.
- **A change of groups ends the person's other sessions (ST-14).** A session copies its roles at sign-in. A sign-in whose groups, compared as sets, differ from the principal's revokes every session of the principal, in the transaction that records `whitetower.principal.groups_changed.v1`, before the rest of the sign-in runs. The session of that sign-in is created after, so it is the one left. This holds for the callback and the CLI's exchange, which creates a token and no session; API tokens already take their roles from the principal at each request. Break-glass signs in a custodian whose groups are always none, so it never changes groups and never revokes another break-glass session: two custodians can work at once. A sign-in with the same groups revokes nothing, and one that fails after the change rolls the revocation back with the change. Two sign-ins of one person at once on two replicas keep the row lock of the fix of audit events: the second reads the first's groups, and if they differ, revokes the first's session too, so the session left has the latest groups. The lock's own test covers the reading; no test runs this case.
- **What records the revocations.** `principal.groups_changed` does, as `principal.deactivated` records the revocations of a deactivation: no `session.revoked` per session, whose reasons are a sign-out and a sign-in in the browser that held the session. A session that the browser held and that the change already revoked is then no longer active, so the callback records no `replaced` for it. No schema accepts anything other than before; the descriptions of both say so (the review, below).
- **Sign-out with a POST and the CSRF token (ST-14).** `/auth/logout` moved from `OIDCService` to `LogoutService`, which `main` mounts whenever OIDC or break-glass is on, so that a break-glass session can end before its hour. A POST whose cookie names an active session needs the session's CSRF token in `X-CSRF-Token`, checked by `SessionStore.ValidateRequestCSRF`, as the API checks it; without it the answer is 403, and nothing is revoked or cleared. With it, the session is revoked and recorded as before, and the cookie cleared.
  - A request without the session cookie clears none. A cross-site request never carries the cookie, which is `SameSite=Lax`: clearing it would sign the browser out, which is what the check prevents.
  - A cookie of no active session, revoked, expired or unknown, is cleared without a token: it names nothing that a forged request could end. A sign-out that cannot read the session, as when the database does not answer, answers 500 and changes nothing, since the token cannot be checked without the session.
  - The answer is JSON, `{"redirect_url": ...}`: the identity provider's end session endpoint, from `OIDCService.EndSessionURL`, or the console's root before discovery, without OIDC and after a break-glass session, which never signed in at the provider, possibly down. Only `fetch` sends the CSRF header, and `fetch` cannot follow a redirect to the provider's origin, so the console navigates there itself. A form would need the token in its body, which ADR-0009 puts in a header, and the console's `form-action 'self'` would stop its redirect to the provider.
  - **A GET answers 405, with `Allow: POST`, and signs nobody out.** A link, an image or a prefetch makes a GET, which another site can make too. A redirect to the console was the alternative: it would leave a person who opened an old link to `/auth/logout` believing that they had signed out, on a shared computer for instance, while the 405 says that nothing happened.
- **The console signs out.** When `/me` gives it a session's CSRF token, the console shows **Sign out**, which posts to `/auth/logout` with the token, then goes where the answer says; a failure says so, and the console stays. Its two new strings are in English and Spanish, after the browser's languages, in a small table of their own (`web/src/messages.ts`): plan P1-10.1 moves every string to react-i18next, a new dependency that this fix does not add. The browser test signs out with the button, and checks that a GET signs nobody out.
- **ST-14 against the code.** Both gaps that #100 listed are closed: sessions are revoked on a change of the groups from which roles come, and at logout for break-glass alone.
- **Documents.** The development guide, the READMEs of the development and evaluation stacks and the fifteen-minute demo sign out with the console's **Sign out**, since opening `/auth/logout` no longer signs out. The placeholder page of `task run` has none: the guide says to clear the site's cookies there. The SAML broker guide's `/me` example of an administrator lists the new permission, and the domain model's `sessions` row the revocation after a change of groups.
- **Tests:**
  - the matrix gives `identity.tokens.manage` to the admin role only (ST-17, now 26 permissions); the authorizer allows it to an administrator, and to an administrator's token only when its scopes hold it, never to a token of another role or to a break-glass session;
  - through the REST API: an administrator's token without the permission is refused another person's token, as one that does not exist, and listing and creating the tokens of another person's service account (`forbidden`); with the permission, all three succeed; another person and a break-glass session are refused listing and creating; the person responsible for the service account and an administrator's session are allowed (ST-19);
  - a sign-in that changes the groups revokes the person's other sessions, through the callback and the exchange, and keeps its own session and another person's; the same groups, a sign-in that fails after the change, and two break-glass sign-ins revoke nothing; the change records no `session.revoked` (ST-14);
  - a GET, a HEAD and a DELETE answer 405 with `Allow: POST`; a POST without the CSRF token, with another session's or with a wrong one answers 403; none revokes the session or sets a cookie; a POST without the cookie sets none; the console's POST revokes, records one sign-out, clears the cookie and answers the console's root; a revoked session's cookie is cleared without a token and records nothing (ST-14);
  - a break-glass session's sign-out goes to the console's root while an OIDC session's goes to the end session endpoint; a sign-out that cannot read the session answers 500 and sets no cookie;
  - through `serve` with break-glass alone: `/auth/logout` exists, a GET and a POST without the token sign nobody out, and the POST with the token from `/me` ends the session (ST-14);
  - the earlier tests of the end session endpoint, before and after discovery, check `EndSessionURL` or go through `LogoutService`, and those of the recorded sign-outs send the session's CSRF token;
  - the console: the button posts with the session's CSRF token and goes where the answer says; none without a session; a failure says so and stays; Spanish for a browser that prefers it; the choice of language.
- **Differences from the brief:**
  - No event schema accepts anything other than before: the change of groups records the revocations, as a deactivation does.
  - The sign-out answers JSON rather than a redirect, and a break-glass session's goes to the console's root, for the reasons above.
  - The console's strings are in a small table rather than in react-i18next, which plan P1-10.1 brings.
- **Follow-ups:**
  - `listServiceAccounts` lists every service account for the admin role, whatever the scopes of the caller's token: an exception of the same kind, which the matrix's row on tokens does not cover.
  - A change of the role mapping, a setting, revokes no session: the sessions keep the roles of the mapping before until they end, 12 hours at most.
  - The descriptions of `whitetower.principal.groups_changed.v1` and `whitetower.session.revoked.v1` did not say that a change of groups ends the person's other sessions, which the first records. Done in the review's corrections, below.
  - The placeholder page of `task run` has no **Sign out**.
  - The SAML broker guide still says that the audit log records nothing of a sign-in, which is no longer so since #104.
- **The review's corrections (2026-11-05).** The review found the fix complete, and asked for two corrections, in a commit of their own:
  - **The end session endpoint's scheme.** Before this fix the core answered a redirect to `end_session_endpoint`; the console now navigates there itself, from its own origin, and discovery took the endpoint unchecked, so a broken or hostile discovery document could hand the console a `javascript:` or `data:` URL. Only the console's `script-src 'self'` stopped it. Discovery now keeps the endpoint only when it is an absolute URL with a host and the scheme `https`, or `http` when the issuer's is too, which only `dev.self_signed_tls` allows (T-13, the fix of access control and sessions). Any other endpoint is treated as absent: the sign-out is the core's only, as before discovery. Discovery logs that once, with the endpoint sanitized, and never refuses the provider for it. The console checks the answer too: `signOut` returns the URL only when it is a path of the console's origin, starting with one `/` and no backslash after it, or an absolute `https:` or `http:` URL; anything else fails, as a missing `redirect_url` does.
  - **The event descriptions.** The schema of `whitetower.principal.groups_changed.v1`, and its catalog entry's summary, say that a change of groups also revokes every session of the person, which this event records; the schema of `whitetower.session.revoked.v1` says that those revocations, like a deactivation's, are recorded by `groups_changed` rather than by `session.revoked`. Descriptions only: they follow the maintainer's decision 2, and no schema accepts anything other than before. `TestEveryExampleIsIndexed` and `test/contracts` pass without `-update`.
  - Tests: discovery keeps an https endpoint, and an http one for an http issuer, and drops plain HTTP for an https issuer, `javascript:`, `data:`, a relative URL, one without a scheme and one with a line break, logging each once, sanitized; the console goes to `/` and to an http URL, and refuses `javascript:alert(1)`, a `data:` URL, `//` and `/\` URLs and a relative one, saying that the sign-out failed.

### 2026-11-05: the review of the tokens fix, and the maintainer's decisions 5 and 6

The review found the tokens fix complete (#111), and CI passed. Apart from the agent's thirteen break experiments, the reviewer's own, a sign-out without the CSRF check, failed four tests. The review's two corrections are in the note above. It also covered the small fixes of the same day, which came from these reviews ([P1-01's](P1-01-core-platform-skeleton.md#progress-notes) and [P1-02's](P1-02-audit-log.md#progress-notes) progress notes of 2026-11-05): the reviewer's break experiment, a CA file added to the system's authorities, failed the audit sink's new test.

Where the follow-ups of both go:

| Follow-up | Where it goes |
| --- | --- |
| `listServiceAccounts` lists every service account for the admin role, whatever the token's scopes, and drops the error of reading an account's roles | Decision 5 below; the work queue's row "P1-03 fix: what identity records, and SCIM" |
| A change of the role mapping revokes no session | Decision 6 below; the row "P1-03 fix: sessions after a change of the role mapping" |
| The SAML broker guide says that the audit log records nothing of a sign-in | The row "P1-03 fix: what identity records, and SCIM", which edits the guide |
| The placeholder page of `task run` has no **Sign out** | Not changed. It serves development only, the development guide says how to sign out there, and the console through Vite has the button |
| `task verify:gen` ignores untracked files | The row "Small fixes from the reviews of 2026-11-05" |
| `tlsclient`'s own test does not check the "only" of its name | The same row |

The maintainer's decisions of 2026-11-05, on what the review left open:

5. **Listing service accounts.** `listServiceAccounts` lists every service account to the admin role and, to anyone else, those they are responsible for. It checks the role, as the tokens' exception did before decision 1, so an administrator's token scoped to `identity.me.read` lists every service account, with its name, email address, responsible person and roles. `identity.tokens.manage` covers it too, since an administrator lists the service accounts to manage their tokens, and the permission matrix's row says so (requirements, section 5.2.1). The alternatives: a permission of its own, one more that only the administrator would hold; and the exception left as it is, outside the matrix.
6. **Sessions after a change of the role mapping (ST-14).** `auth.oidc.role_mapping` is read at start-up, and a session copies its roles at sign-in, so after a change and a restart the open sessions keep the roles of the mapping before, for up to 12 hours. API tokens take their roles at each request and are not affected. A session records the SHA-256 of the mapping that resolved its roles, and the authenticator refuses a session whose hash is not the current mapping's, so everyone signs in again after a change; break-glass sessions, whose roles do not come from the mapping, are exempt. The alternatives: the delay documented, with the deactivation of a person to remove a privilege at once; and roles read at each request, which decision 2 set aside for the changes of groups.

### 2026-11-06: small fixes from the reviews of 2026-11-05

A fix outside the seven pull requests, from the work queue's row of small fixes from the reviews of 2026-11-05. Its other item, `task verify:gen`, is in [P1-01's progress notes](P1-01-core-platform-skeleton.md#progress-notes) of the same day.

- **`TestAClientTrustsTheAuthoritiesOfItsCAFileOnly` checks the "only" of its name**, as the audit sink's test does ([P1-02's progress notes](P1-02-audit-log.md#progress-notes) of 2026-11-05). A request with the CA file passes whether or not the system's authorities are in the pool too, since the test server's certificate chains to none of them, so the test now compares the pool of `Config` with a pool of the file's authorities alone. `tlsclient` itself does not change.
- **Break experiment:** with the system's pool and the file's authorities appended to it, the test fails on Windows; the former test passed.

### 2026-11-06: what identity records, and SCIM (fix)

The maintainer's decisions 3 to 5 of 2026-11-05, above, and the follow-ups of #104 and #105 that the work queue's row names.

- **The creation of a service account is recorded (AUD-01).** The new core event type `whitetower.service_account.created.v1`, with its schema, example, catalog entry and indexing rule, holds the service account's principal ID, the person who created it as actor, the person responsible for it and the roles bound to it, sorted. Today the actor and the responsible person are one: the member says who answers for the account if an operation ever creates one for someone else. It holds no name or email address of the account, which a person chose and which can name someone (NFR-20). `CreateServiceAccount` records it in the transaction that creates the account and binds its roles, so a writer that refuses it leaves neither. The [framework mapping](../../security/framework-mapping.md) names it as evidence of roles and responsibilities.
- **A refused sign-in leaves a trace (decision 3).** The callback, the CLI's exchange and break-glass log one line, `refusing a sign-in`, at the warning level, with the method (`oidc`, `token_exchange` or `breakglass`), the reason and the principal's ID when the refusal found one: an inactive principal, or one that holds another external ID. The store refuses those two with an error that names the principal and wraps `ErrPrincipalInactive` or `ErrExternalIDConflict`, as before. The line adds what helps, never a value of an ID token or a credential: the claim's name, the verifier's error, the provider's `error` and `error_description`, sanitized. The new counter `whitetower_auth_sign_ins_total`, registered on main's registry whichever way of signing in is on, counts every sign-in by method and result:

  | Result | When |
  | --- | --- |
  | `success` | The person is signed in |
  | `invalid_request` | No state cookie, a state of no sign-in, no authorization code, no ID token, or no credential |
  | `provider_error` | The identity provider sent the browser back with an error, such as `access_denied` |
  | `invalid_token` | The ID token does not verify, is not the sign-in's, or its claims cannot be read |
  | `no_external_id`, `external_id_conflict` | The two refusals of the fix of 2026-11-03 |
  | `inactive` | The principal is deactivated |
  | `invalid_credential`, `rate_limited` | Break-glass's credential does not verify, or the client is over its rate |
  | `error` | The server or the provider failed: the provider not discovered, the code not exchanged, no ID token in the provider's answer, the database. The log already says so, in its own line, and does now for the missing ID token too |

  The labels are the server's own words. A refusal writes no audit event, since it changes nothing. The callback's former lines of a provider's error, a token that does not verify and a nonce that does not match, which logged the expected nonce, the exchange's two, and the line that `identityOf` logged for a missing external ID, are now that one line, so each refusal logs once. A break-glass refusal names no principal: the request names none, and its method implies the custodian.
- **SCIM compares userNames without regard to case (RFC 7643, section 4.1.1).** Migration `00006` adds a unique index on `lower(subject)` for SCIM's principals, the issuer `scim`. The filter and the check before a creation compare `lower(subject)` with the lowered userName, through `GetPrincipalBySCIMUserName`, as the index does, so both follow the database's locale: `en_US.utf8` in the official image folds letters beyond ASCII, and the C locale only ASCII ones. A creation that another one overtook with the userName in another case inserts nothing, and an adoption meets the index: both are a userName that exists, 409. A user keeps the userName as SCIM gave it. No deployment stack turns SCIM on and no release came before, so no database should hold two userNames of SCIM's that differ only in case; one that does fails the migration, with the duplicated value.
- **A creation with `active: false` in one transaction.** `ProvisionHuman` takes whether the user is active. When not, the transaction that creates or adopts the principal deactivates it, as `Deactivate` does, through `deactivateTx`, which `Deactivate` now runs in its own transaction: it records `principal.deactivated` with SCIM as actor, and ends the sessions and API tokens of a principal that a person signed in as. A failure rolls the creation back, and SCIM answers 500, where it answered 201 with an active user.
- **Listing service accounts (decision 5; HUM-07, ST-19).** `listServiceAccounts` lists every service account to a principal that `TokenStore.MayManageAnyToken` allows, so an API token needs `identity.tokens.manage` in its scopes and a break-glass session never has it, and to anyone else those they are responsible for. It returns the error of reading an account's roles, which it dropped, leaving the roles out. The OpenAPI description says who sees what.
- **The SAML broker guide** says that a `PATCH` applies only `active` and checks `externalId`, and ignores every other attribute, which Entra ID sends at every synchronization (decision 4); that SCIM compares userNames without regard to case; that a creation with `active: false` is inactive; and what the audit log, the server's log and the metric record of a sign-in, where it said that the audit log recorded nothing of one, stale since #104. The domain model's row on `principals` says that SCIM's userNames are unique without regard to case.
- **Tests:**
  - the creation of a service account records its account, actor, responsible person and roles, sorted, and no name or email address; a role the person lacks, and a writer that refuses the event, leave no account and no event;
  - each kind of refusal through the callback, the exchange and break-glass logs one line, with its method, its reason and the principal's ID when there is one, counts once with its reason, and writes no audit event; a success of each method counts as `success` and logs no refusal; a provider that cannot exchange the code counts as `error`; break-glass over its rate is `rate_limited`; the log holds none of the tokens' claims, nor the credentials;
  - the filter finds a user with its userName in another case and answers the userName as given; a creation, an adoption, the store and an insert in the database are each refused with the userName in another case; two provisionings at once, the second an adoption or a creation with the userName in another case, create one user;
  - a creation with `active: false` creates the user inactive, and an adoption deactivates the principal and ends its session, each recording the deactivation by SCIM; a writer that refuses the deactivation leaves no user (ST-21);
  - through the REST API, every service account with its roles is listed to an administrator and to an administrator's token with `identity.tokens.manage`, and only their own to an administrator's token without it, to a person responsible for one and to a break-glass session; a failure to read the roles answers `internal` and is logged (ST-19);
  - the tests of the fix of 2026-11-03 that read the refusals' log lines read the one line now.
- **Differences from the brief:**
  - The metric counts successes and failures too, so that a refusal can be read against every sign-in; a refusal is the reason as result.
  - Requests that end no sign-in, without a state or a credential, count and log as `invalid_request` refusals, as a forged callback is one.
- **Follow-ups:**
  - A verification error at the callback or the exchange cannot tell a token that does not verify from signing keys that could not be fetched: both count as `invalid_token`, and the error in the line says which.
  - A SCIM creation with `active: true` of a person whose principal an administrator deactivated, and that SCIM adopts, leaves it inactive, as before.
  - The erasure of a person (pull request 7) replaces the subject with a placeholder: for SCIM's principals, the placeholders must differ without regard to case.

### 2026-11-09: sessions after a change of the role mapping (fix)

The maintainer's decision 6 of 2026-11-05, above (ST-14).

- **A session records the role mapping that resolved its roles.** Migration `00007` adds `role_mapping_sha256` to `sessions`: 32 bytes, or none. `SessionOptions.RoleMapping` gives the session store `auth.oidc.role_mapping`, which `main` passes to it as to the OIDC service, and the store records the mapping's hash in every session that it creates, except break-glass's, whose roles do not come from the mapping. The callback is the only way of signing in that creates a session whose roles come from the mapping: the CLI's exchange creates an API token, which takes its roles at each request, and no code creates a session of the method `cli`, which the column allows. Such a session would record the hash too, as every method but `breakglass` does. The store hashes the mapping once, at start: the check compares bytes of the row that `Get` already reads, with no new query on the request path.
- **The canonical form.** The hash covers the form's name, `whitetower-role-mapping-v1`, then each group in the order of its bytes, followed by its role, every string preceded by its length in eight bytes.
  - The order in which the file or the environment variable lists the groups carries no meaning, and the map that the configuration holds has already lost it.
  - The lengths keep `{"wt-owners": "owner"}` and `{"wt-owner": "sowner"}` apart, where a separator could appear in a name. Two mappings therefore hash the same exactly when they map the same groups to the same roles; a nil mapping and an empty one hash as one.
  - JSON with sorted keys was the alternative: Go's encoder replaces invalid UTF-8 with U+FFFD, so two mappings that differ could write the same text.
  - `ResolveEffectiveRoles` also looks a group up without its leading slash, so a few mappings that differ only in groups that start with slashes, such as `{"x": "owner", "/x": "user", "//x": "user"}` and `{"x": "owner", "//x": "user"}`, resolve the same roles for every group. They hash apart: reducing a mapping to a minimal form would add code for groups that no provider sends, and the cost is a sign-in, never a role.
  - The configuration refuses an invalid role whenever OIDC is on, so no mapping that resolves a session's roles holds one.
- **The refusal is an expired session's.** `SessionStore.Get` refuses a session whose hash is not its own mapping's, after the checks of revocation and expiry, with `ErrSessionExpired`, so that every reader handles it as an expired session: the API answers 401 with the detail of any credential that it does not accept, and writes no log line or audit event of its own; the cookie stays, until the next sign-in replaces it, and the console offers no **Sign out**; `/auth/logout` clears the cookie without the CSRF token and revokes nothing. No answer, log line or event names a hash. A session without a hash, created before the migration, is refused; a break-glass session is accepted whatever it holds.
- **Neither revoked nor touched.** The refusal neither revokes the session nor slides its idle expiry. During a rolling restart, a replica that still runs the mapping before accepts the sessions of that mapping and refuses those of the new one, and the other way round; revoking at the refusal would let each replica end the sessions that the others create. A return to the mapping before accepts its sessions again, until they expire.
- **A sign-in revokes a held session of another mapping.** `RevokeActiveSession`, which `ReplaceTx` runs on the sessions that the browser held, revokes a session that is neither revoked nor expired whatever its mapping, and records it as `replaced`, so the sign-in that follows a refusal leaves no session that a replica of the other mapping, or a return to it, would accept. The query's comment said "active, as `SessionStore.Get` judges it", and now says so.
- **Documents.** The configuration reference's `auth.oidc.role_mapping` says that after a change everyone signs in again, that the order of the groups does not matter, that break-glass sessions and API tokens are not affected, and what a rolling restart does. The domain model's `sessions` row says what a session records.
- **Tests:**
  - with a session store of another mapping, as after a restart or on another replica, a session of the methods `oidc` and `cli` is refused as expired, and the other way round: a role changed, a group added or removed, a group and its role cut elsewhere, and a group with a leading slash; the same mapping built in another order, and a nil mapping then an empty one, accept it; after each refusal, the store of the session's mapping still accepts it (ST-14);
  - the authenticator of another mapping refuses the session's cookie with `ErrSessionExpired`; the refusal does not slide the idle expiry; a sign-out with another mapping clears the cookie without the CSRF token, and records and revokes nothing (ST-14);
  - a break-glass session is accepted with another mapping; a session of the methods `oidc` and `cli` without a hash, as before the migration, is refused (ST-14);
  - a sign-in through the callback revokes the held session of another mapping, which that mapping's store then finds revoked, and records it as `replaced` (ST-14);
  - through `serve`, three replicas on one database (ST-14): a sign-in on the replica of the mapping before gives the role `owner`, which the replica that lists the same mapping in another order accepts; the replica of the mapping after, which makes the members of `wt-owners` users, refuses that session, and its own sign-in gives the role `user`, which both replicas of the mapping before refuse. Each refusal answers as for a session that does not exist. A break-glass session of the replica of the mapping before is accepted by the replica of the mapping after.
- **Break experiments:** each made the tests above fail, and was undone by an edit:
  - without the check in `Get`, five cases of the table, the session without a hash and the test through `serve` fail; the last answers `/me` with the role `owner` on the replica of the mapping after, which is the fault this fix closes;
  - with break-glass sessions checked too, the break-glass tests of the package and through `serve` fail;
  - with a session without a hash accepted, its test fails;
  - with the check after the idle expiry slides, the test of the idle expiry fails;
  - without the lengths in the canonical form, the case of a group and its role cut elsewhere fails;
  - without the mapping in `main`'s session store, the test through `serve` fails;
  - with a held session revoked only when `Get` accepts it, the sign-in's test of a session of another mapping fails.
- **Follow-ups:**
  - The setting reaches four places that `main` wires with the same value: the session store, the OIDC service, the authenticator, for the roles of API tokens, and the inventory. Should the mapping ever become a setting that changes at runtime (plan P1-17 leaves role mappings to P1-03), the session store must take the hash of the mapping in force from the same source.
  - A sign-out with the cookie of a session of another mapping clears the cookie and revokes nothing, as for an expired session: a replica of that mapping, or a return to it, would accept the session until it expires. The console cannot send that sign-out: `/me` refuses the session, so it shows no **Sign out**.

### 2026-11-10: the maintainer's decision 7, on what the session's hash covers

The fix of 2026-11-09 (#119) records in each session the SHA-256 of the role mapping that resolved its roles. Its review found that the mapping is not the only setting that shapes a session: `auth.oidc.groups_claim` names the claim of the ID token that the groups are read from, so a change of it changes the roles of the next sign-in, while the open sessions keep theirs for up to 12 hours, as they did after a change of the mapping before #119. Other settings decide which ID tokens the server accepts and which person a sign-in is, with the same effect on the sessions they created.

The maintainer's decision of 2026-11-10:

7. **What the session's hash covers (ST-14).** White Tower assumes that the environment it is deployed in may be compromised, and that its users may be rogue. So the hash covers every setting that decides which ID tokens the server accepts, which person a sign-in is and what roles it gives: `issuer`, `client_id`, `allowed_algorithms`, `external_id_claim`, `groups_claim` and `role_mapping`. After a change of any of them and a restart, the server refuses every session but break-glass's, as it does now after a change of the mapping: a move away from an identity provider that is compromised, a registration that admitted people it should not have, a claim of identity that a person could change, or an algorithm that is no longer trusted leaves no session that the configuration before created. The settings of transport and routine stay out, since rotating them must sign no one out: `discovery_url`, `ca_file`, `client_secret_file`, `state_key_file`, `redirect_url`, `scopes` and `cli_client_id`, whose exchange creates API tokens, not sessions. The alternatives:
   - identity and roles without `allowed_algorithms`, where the sessions created from tokens signed with an algorithm that is removed expire on their own, within 12 hours;
   - `groups_claim` and `role_mapping` alone, where a change of identity provider or of the claim of identity leaves the sessions open for up to 12 hours, with no operation today that ends every session.

The work queue's row "P1-03 fix: the session's hash covers the sign-in configuration" takes it.

### 2026-11-10: the session's hash covers the sign-in configuration (fix)

The maintainer's decision 7, above (ST-14), on the fix of 2026-11-09.

- **What a session records.** The SHA-256 of the sign-in configuration that created it: the settings of `auth.oidc` that decide which ID tokens the server accepts (`issuer`, `client_id`, `allowed_algorithms`), which person a sign-in is (`external_id_claim`) and what roles it gives (`groups_claim`, `role_mapping`). `SessionOptions.SignInConfiguration`, of the new type `authn.SignInConfiguration`, replaces `SessionOptions.RoleMapping`, and `main` builds it from `auth.oidc` with `signInConfiguration`, from the same settings that it gives the OIDC service. The settings of transport and routine stay out, so rotating them signs no one out: `discovery_url`, `ca_file`, `cli_client_id`, `client_secret_file`, `state_key_file`, `redirect_url` and `scopes`.
- **The canonical form**, `whitetower-sign-in-configuration-v1`: the form's name, the issuer, the client ID, the number of algorithms then each of them, the external ID claim, the groups claim, then the number of groups and each group followed by its role. Every string is preceded by its length and each list by its number of items, in eight bytes.
  - The counts are new. With the lengths alone, strings moved from one setting to the next, such as algorithms that become the claims, could write the same bytes; a test has such a case.
  - The algorithms are sorted in the order of their bytes, and each is written once. The verifier, go-oidc through go-jose, accepts a token whose algorithm is in the list, so it reads the list as a set: two lists that differ only in their order or in an algorithm listed twice accept the same tokens, and hash alike. Hashing the repetitions would add no protection, since a repetition never adds or removes an algorithm, and would only sign everyone in again after an edit that changes nothing.
  - The groups are sorted as before. A nil list or mapping hashes as an empty one.
  - An empty setting hashes apart from one that is set, even where the OIDC service gives a default, such as `sub` for `external_id_claim` or its list of algorithms. The configuration already writes those defaults, so an empty value is one that an operator emptied, and the cost is one sign-in, never a role; applying the defaults in the hash would make a second copy of them, to keep in step with the OIDC service's.
  - The issuer is compared byte for byte, as go-oidc compares it, so a trailing slash makes another issuer.
- **Names.** Migration `00008` renames `sessions.role_mapping_sha256` to `sign_in_configuration_sha256`, and its constraint. The new form changes every hash: after the upgrade, every session but break-glass's is refused once, and its person signs in again. No release came before, so this concerns development and evaluation stacks only.
- **Unchanged.** The check in `Get`, its refusal as an expired session, which names neither a hash nor a setting, the exemption of break-glass sessions, the refusal of a session without a hash, and the sign-in that revokes a held session of another configuration work as the fix of 2026-11-09 says. The store hashes once, at start, and the request path does not change. With OIDC off, the issuer is empty, so the sessions that OIDC created before are refused, and only break-glass sessions remain.
- **Documents.** The configuration reference's section `auth.oidc` names the six settings that a session records, says that after a change of any of them everyone signs in again, what is not affected, and what a rolling restart does, which moved there from `role_mapping`. Each of the six says that a change of it signs everyone in again, and `allowed_algorithms` that their order and an algorithm listed twice do not matter. The domain model's `sessions` row says what a session records.
- **Tests (ST-14):**
  - with a session store of another configuration, a session of the methods `oidc` and `cli` is refused as expired, and the other way round, after a change of the issuer (another one, a trailing slash, OIDC turned off), of the client ID, of the algorithms (one added, one removed, none for the defaults), of the external ID claim (another one, none for the default), of the groups claim, and of the mapping, as before; so are strings cut elsewhere, between a group and its role and between the issuer and the client ID, and strings moved from one setting to the next. The same configuration, the algorithms in another order or one of them listed twice, and lists and a mapping that are nil, then empty, accept it. After each refusal, the store of the session's configuration still accepts it;
  - the authenticator, the idle expiry and the sign-out of the fix of 2026-11-09, now with another external ID claim;
  - a break-glass session is accepted with another issuer, another mapping and OIDC off; a session without a hash is refused;
  - through `main`'s `signInConfiguration`, a change of each covered setting refuses a session, and a change of each setting left out keeps it. The test names every field of `config.OIDC`, and fails on one it does not name, so that a setting added later is put on one side or the other;
  - through `serve`, five replicas on one database. Besides the replicas of the mappings before and after, a replica that lists the mapping and the algorithms in another order, one algorithm twice, and runs another discovery URL, CLI client ID, client secret file, state key file, redirect URL and scopes accepts the session of the replica before; replicas of another issuer and of another external ID claim refuse it, as a session that does not exist. Each accepts a break-glass session.
- **Break experiments:** each made the tests above fail, and was undone by an edit:
  - without the check in `Get`, the 17 refusals of the table, the session without a hash, the six covered settings through `signInConfiguration` and the test through `serve` fail;
  - without the counts of the lists, the case of strings moved from one setting to the next fails;
  - without the lengths of the strings, both cases of strings cut elsewhere fail;
  - with the algorithms unsorted, the cases of another order and of an algorithm listed twice, and the test through `serve`, fail; with them sorted but not written once, the case of an algorithm listed twice and the test through `serve` fail;
  - without the issuer in the form, its three cases, its case through `signInConfiguration` and the test through `serve` fail;
  - with `signInConfiguration` leaving out `external_id_claim`, or adding `cli_client_id` to it, the setting's case and the test through `serve` fail;
  - with `main`'s session store given an empty configuration, the test through `serve` fails;
  - with break-glass sessions checked too, the three break-glass cases and the test through `serve` fail;
  - with a session without a hash accepted, its test fails.
- **Follow-ups:**
  - The CLI's exchange creates API tokens that last 12 hours and take their roles at each request, from the groups that the person's last sign-in recorded: after a change of the issuer, or of another covered setting, an exchanged token keeps working until it expires. Decision 7 left the exchange out, since it creates no session.
  - The six settings reach the session store and the OIDC service through two structures that `main` fills from `auth.oidc`. The follow-up of 2026-11-09 on a mapping that changes at runtime now holds for all six.

### 2026-11-10: the review of the sign-in configuration's fix, and the maintainer's decisions 8 and 9

The reviewer found the fix that makes the session's hash cover the sign-in configuration complete. Its agent named one gap, and the review a second, both about what outlives a sign-in that should no longer count:

- **The CLI's tokens.** The CLI's exchange turns an ID token into an API token of 12 hours, which is no session and records no hash: after a change of the issuer, or of another setting that decision 7 covers, it keeps working until it expires.
- **A provider fixed without a change of configuration.** A compromised identity provider that is fixed with the same issuer and claims changes no setting, so no hash refuses anything: the sessions created meanwhile last up to 12 hours, and the API tokens created with them up to 90 days. Today people can only be deactivated one by one.

The maintainer's decisions of 2026-11-10:

8. **The CLI's tokens record the sign-in configuration (ST-14).** A token that the exchange creates records the hash of the configuration that accepted its ID token, with `cli_client_id`, the client that the exchange accepts, in place of `client_id`, and the authenticator refuses it when the hash is not the current one, as it refuses a session. A change of `cli_client_id` ends the CLI's tokens and no browser session; a change of `client_id` ends the sessions and no CLI token. The tokens that people create themselves, and those of service accounts, record none: decision 9 covers them. The alternative: leaving them to expire within 12 hours.
9. **Emergency revocation (HUM-10, ST-89).** The platform administrator, or the break-glass custodian, ends at once every session and every API token, of people and of service accounts, the caller's session included unless it is a break-glass session, and the audit log records it: step 14. The cost: everyone signs in again, and the integrations' tokens are created again. The alternatives: ending the sessions and the CLI's tokens only, which leaves a token of 90 days that an intruder created; and the procedure of deactivating the people concerned, who can be anyone after a compromise of the provider.

The requirements gain HUM-10, with its row in the permission matrix, and HUM-06 and ST-20 say that break-glass can run it; the security test catalog gains ST-89. The work queue's rows "P1-03 fix: the CLI's tokens record the sign-in configuration" and "P1-03 pull request 8: emergency revocation" take them.

### 2026-11-10: the CLI's tokens record the sign-in configuration (fix)

The maintainer's decision 8, above (ST-14, ST-19), on the fix that makes the session's hash cover the sign-in configuration.

- **What a token of the exchange records.** Migration `00009` adds `sign_in_configuration_sha256` to `api_tokens`: 32 bytes, or none. A token that the CLI's exchange creates records the SHA-256 of the sign-in configuration that accepted its ID token. `authn.SignInConfiguration` gains `CLIClientID`, which `main`'s `signInConfiguration` fills from `auth.oidc.cli_client_id`, and `NewTokenStore` takes the configuration, the same that `main` gives the session store. The token store hashes it once, at start; the exchange gives the store's hash to `createWithLifetimeTx`, and `Create`, for people and service accounts, gives none.
- **The canonical form**, `whitetower-cli-sign-in-configuration-v1`: the sessions' form, with the CLI's client ID in place of the console's. `signInConfigurationSHA256` now takes the name of the form and the client ID, so both hashes come from one encoder. The form has a name of its own so that the two hashes never meet: with one name, a configuration whose two clients are one would write the same hash for its sessions and for its CLI's tokens.
- **The refusal is an unknown token's.** `GetByToken` refuses a token whose hash is not the store's own, after the checks of revocation and expiry and before it reads the principal, with `ErrInvalidToken`, the error of a token that it does not know: the API answers 401 with the detail of any credential that it does not accept, and nothing logs or records the refusal. No answer names a hash or a setting. The check compares bytes of the row that `GetAPITokenByHash` already reads, with no new query on the request path.
- **Neither revoked nor touched.** The refusal neither revokes the token nor writes its `last_used_at`. During a rolling restart, a replica that still runs the configuration before accepts the CLI's tokens of that configuration and refuses those of the new one, and the other way round; a return to the configuration before accepts its tokens again, until they expire.
- **What each change ends.** A change of `client_id` ends the sessions and no CLI token; a change of `cli_client_id` ends the CLI's tokens and no session; a change of `issuer`, `allowed_algorithms`, `external_id_claim`, `groups_claim` or `role_mapping` ends both. With OIDC off, the issuer is empty, so the CLI's tokens created before are refused, as the sessions are.
- **Tokens without a hash.** The tokens that people create, and those of service accounts, record none and are accepted whatever the configuration: decision 9 covers them. The exchange's tokens created before the migration would have none either, and would be accepted until they expire, 12 hours at most after the upgrade. They are refused, as sessions without a hash are: the migration gives them 32 zero bytes, the hash of no configuration. They are the only tokens named `wtctl` that last exactly 12 hours: people and service accounts create tokens through `Create`, whose lifetimes are whole days, and nothing else calls `CreateWithLifetime`. A token that a person named `wtctl` keeps none. The alternatives:
  - a column that says which tokens the exchange created, as `sessions.method` does, set by the migration with the same marker: explicit, but a second column whose only use after the transition repeats that a token has a hash;
  - the name and the lifetime checked at each request, for good, for a transition of 12 hours;
  - the migration revoking those tokens: a revocation that the audit log would not record;
  - nothing: they expire within 12 hours, and no release came before, so only development and evaluation stacks hold any.
- **Documents.** The configuration reference's section `auth.oidc` names the seven settings, and says which of them sessions record, which the CLI's tokens record, what a change of each ends, what is not affected and what a rolling restart does. `cli_client_id` says that after a change everyone logs in again with the CLI and no session ends, `client_id` that no CLI token ends, and the five others that everyone signs in again in the console and with the CLI. The domain model's `api_tokens` row says what a token of the exchange records.
- **Tests:**
  - with a token store of another configuration, a token of the exchange is refused as an invalid token after a change of the CLI client ID, of the issuer (another one, a trailing slash, OIDC turned off), of the algorithms (one added, one removed), of the external ID claim, of the groups claim and of the mapping, and with the issuer and the CLI client ID cut elsewhere; the same configuration in another order, an algorithm listed twice and another client ID accept it. After each refusal, the store of the token's configuration still accepts it (ST-14);
  - the authenticator of another configuration refuses the token as it refuses a token that does not exist; the refusal neither revokes it nor writes `last_used_at`, which the store of its configuration then writes; the session of a configuration whose console's client is the CLI's records another hash than the token (ST-14);
  - a person's token, named `wtctl`, and a service account's record none, and are accepted with another CLI client ID, another issuer and OIDC off, which refuse the exchange's token; a token of the exchange that holds 32 zero bytes is refused by its own configuration (ST-19);
  - the sessions' table gains another CLI client ID, which keeps the session;
  - migration `00009`, on a database at `00008`, gives 32 zero bytes to a token named `wtctl` of 12 hours, and none to a token named `wtctl` of a day, to one of 12 hours named otherwise and to one of 30 days;
  - through `main`'s `signInConfiguration`, one test now says for each setting whether a change of it ends the sessions and the CLI's tokens: the five shared settings end both, `client_id` the sessions alone, `cli_client_id` the CLI's tokens alone, and the six others neither. A person's token and a service account's are kept after each change. The CLI's tokens come from the exchange of an OIDC service of the settings before;
  - through `serve`, seven replicas on one database. The replica of the settings of transport no longer changes the CLI client ID, and two replicas join, of another client ID and of another CLI client ID. A token of the exchange on the replica before is accepted by the replicas of transport and of another client ID, and refused by those of the mapping after, of another issuer, of another external ID claim and of another CLI client ID, as a token that does not exist. The session is refused by the replica of another client ID and accepted by that of another CLI client ID. A token that the person created with the CLI's token is accepted by all seven (ST-14, ST-19).
- **Break experiments:** each made the tests above fail, and was undone by an edit:
  - without the check in `GetByToken`, the ten refusals of the table, the test of the tokens without a hash, the six settings that end the CLI's tokens through `signInConfiguration` and the test through `serve` fail;
  - with tokens without a hash refused too, five cases of `TestAPITokenSecurity`, the test of the tokens without a hash, the 13 settings through `signInConfiguration` and the test through `serve` fail;
  - with the check after `last_used_at` is written, the test of the refusal fails;
  - with the CLI's tokens hashed in the sessions' form, the case of the two forms fails;
  - with the console's client ID in the CLI's hash, the cases of another client ID and of another CLI client ID, the test of the tokens without a hash, both client IDs through `signInConfiguration` and the test through `serve` fail; with the CLI's client ID in the sessions' hash, the two client IDs of the sessions' table, both through `signInConfiguration` and the test through `serve` fail;
  - with the exchange recording no hash, the ten refusals, the test of the tokens without a hash, the six settings through `signInConfiguration` and the test through `serve` fail;
  - with `main`'s `signInConfiguration` leaving out `cli_client_id`, its case and the test through `serve` fail; with `main`'s token store given an empty configuration, the test through `serve` fails;
  - with the migration's marker without the name, or without the lifetime, the migration's test fails.
- **Follow-ups:**
  - The exchange also accepts an ID token whose audience is `client_id`, the console's, when the CLI's verifier refuses it. Its token records the CLI's form all the same, so a change of `client_id`, the client that accepted that ID token, does not end it. Decision 8 names `cli_client_id` as the client that the exchange accepts; whether the exchange should keep accepting the console's ID tokens is the maintainer's question.
  - The six settings and `cli_client_id` reach the session store, the token store and the OIDC service through structures that `main` fills from `auth.oidc`. The follow-up of 2026-11-09 on a mapping that changes at runtime holds for the token store too.
