# ADR-0009: Human authentication through a backend-for-frontend with server-side sessions

- **Status:** Proposed
- **Date:** 2026-09-28
- **Related:** HUM-01 to HUM-07, NFR-12; ADR-0002; plan P1-03

## Context

Humans log in through the organization's IdP with OIDC (HUM-01). The console is a single-page app (ADR-0002). A browser app can either hold OIDC tokens in JavaScript, where any XSS flaw can steal them, or leave token handling to the server. White Tower is a security product whose console can halt the whole fleet, so a stolen session has a high impact.

## Decision

- The core acts as a **backend-for-frontend (BFF)**: it runs the OIDC authorization code flow with PKCE as a confidential client, validates the ID token and creates a **server-side session** stored in PostgreSQL.
- The browser only receives an opaque session cookie named with the `__Host-` prefix, `HttpOnly`, `Secure` and `SameSite=Lax`. OIDC tokens never reach JavaScript.
- Sessions have an idle timeout (30 minutes by default) and an absolute lifetime (12 hours by default), are rotated at login and are revoked at logout or when the principal is deactivated.
- State-changing requests require a CSRF token sent in a header, on top of the SameSite protection.
- **The CLI** logs in with the authorization code flow with PKCE and a loopback redirect, as `kubectl` OIDC plugins do. The core exchanges the resulting ID token for a short-lived White Tower API token bound to the same principal. Personal access tokens (HUM-07) cover automation. The device authorization grant is a later option for headless machines.
- Roles come from the IdP group claim through a configurable mapping (HUM-02). The permission matrix is evaluated in the core on every request (HUM-03).

## Consequences

**Easier**
- XSS cannot steal tokens, and sessions can be revoked centrally, which matters for deprovisioning owners.
- One implementation of OIDC in the core serves the console and the CLI.

**Harder**
- The core keeps session state in PostgreSQL. This is cheap and already a dependency (ADR-0003).
- Cross-site request forgery has to be handled explicitly (the CSRF token above).

## Alternatives considered

- **Tokens in the browser (public client with PKCE).** Common in SPAs, but it exposes tokens to XSS and makes revocation depend on the IdP. Rejected.
- **A separate authentication proxy (for example oauth2-proxy).** Keeps OIDC out of the core, but adds a component and still needs role mapping in the core. Rejected for the MVP; operators can still put one in front.
