# P1-03: Human identity and access

| | |
| --- | --- |
| **Phase** | 1 Core MVP |
| **Status** | Draft |
| **Size** | M |
| **Depends on** | P1-01, P1-02 (writer) |
| **Unblocks** | P1-04, P1-10, P1-11 |
| **Requirements** | HUM-01 to HUM-08, KIL-08 (break-glass), NFR-12 |
| **Decisions** | ADR-0009 |

## Goal

People log in through the organization's IdP. Their roles come from IdP groups. Every operation is authorized in one place, against the permission matrix, with separation of duties enforced. Tokens never reach the browser, sessions can be revoked, and a break-glass path keeps the kill switch usable when the IdP is down.

## Scope

**In:** OIDC login through the backend-for-frontend, sessions, CSRF protection, principals and their status, role mapping and bindings, the authorization engine, API tokens, the CLI token exchange, SCIM, break-glass, SAML through a broker.

**Out:** the console screens (P1-10.1 and P1-10.6); the CLI side of login (P1-11); machine identities (P1-05).

## Deliverables

- `internal/authn` and `internal/authz`.
- OpenAPI operations: `/me`, principals, role bindings, API tokens, the CLI exchange; `/auth/*` routes; `/scim/v2/Users`.
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
- **Local bindings:** administrators can add role bindings inside White Tower; every binding change is audited.
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

Tests from the P0-04 catalog for this plan:

- CSRF, session fixation, cookie flags, open redirects;
- ID token replay (nonce), algorithm confusion in ID token validation;
- the full separation-of-duties matrix;
- rate limits on login and break-glass.

**Done when:** all pass in CI.

## Acceptance criteria

- Login and logout work against Keycloak and against at least one commercial IdP (Entra ID or Okta), or the latter is scheduled as the first pilot task if no tenant is available.
- The permission tests cover every role and permission pair, including separation of duties.
- The security tests of step 12 pass.
- Deactivating a principal revokes their sessions immediately.

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
