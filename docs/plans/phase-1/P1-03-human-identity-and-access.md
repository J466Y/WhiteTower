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
  - the principal is marked erased, with the reference as the reason of its status, and the time of the change from `clock.Clock`.

  Its ID, its issuer, its last login and every record that refers to it stay. Every check that a principal is inactive treats an erased one the same way, so that an erased owner still suspends their agents (INV-05), and a service account whose responsible principal is erased stays unusable for good (the fix of 2026-10-19).
- **Final.** An erased principal is never reactivated. If the person logs in again, the login finds no principal with their subject and creates a new one, with a new ID.
- **Audited.** The erasure records `whitetower.principal.erased.v1`, with its actor, the principal's ID and the reference, and nothing that names the person: a new core event type, with every step of AGENTS.md's checklist.
- **Nothing else to erase.** No other table holds the name, the email or the subject. Text that people wrote into sealed events, such as halt reasons and agents' names, stays until retention drops it; the domain model's section 7 asks them to keep personal data out of it.

**Done when:** after an erasure, a canary name, email and subject appear in no table and in no API response; an active principal and a service account are refused; an erased principal cannot be reactivated, and the same person logging in again gets a new principal (ST-88).

## Acceptance criteria

- Login and logout work against Keycloak and against at least one commercial IdP (Entra ID or Okta), or the latter is scheduled as the first pilot task if no tenant is available.
- The permission tests cover every role and permission pair, including separation of duties.
- The security tests of step 12 pass.
- Deactivating a principal revokes their sessions immediately.
- An erasure leaves the person's name, email and IdP subject nowhere in White Tower, and keeps the history consistent (HUM-09).
- The security tests assigned to this plan in the [security test catalog](../../security/security-tests.md#p1-03-human-identity-and-access) pass: ST-13 to ST-22, and ST-88.

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
  - The events about people take the principal's ID as subject, as `principal.deactivated`, `token.created` and `breakglass.used` did before them, while the contracts' section 8.2 reserves the subject for an agent's ID.
  - `task verify:gen` does not compare `internal/authn/authndb`, so a stale generation of the authentication queries would pass CI.
  - From the brief, outside this fix: a logout route when only break-glass is on, and logout as a GET.
