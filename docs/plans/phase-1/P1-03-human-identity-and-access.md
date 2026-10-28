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
