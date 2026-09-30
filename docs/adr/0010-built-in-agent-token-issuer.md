# ADR-0010: Built-in token issuer for agent and module credentials

- **Status:** Proposed
- **Date:** 2026-09-28
- **Related:** AID-01 to AID-09, KIL-06; ADR-0004, ADR-0005; plan P1-05

## Context

Agent identity is one of the five functions of the core. The charter lists SPIFFE/SPIRE, Keycloak and the identities of Microsoft AGT as candidate components, and asks for short-lived, per-task credentials federated with the existing IdP.

Standards work points the same way. The IETF WIMSE working group adopted "AI Identity Management System" (`draft-ietf-wimse-aims-00`, September 2026). It treats agents as workloads with WIMSE or SPIFFE identifiers and short-lived credentials, and calls static API keys an antipattern. The MCP specification (version 2026-07-28) requires tokens bound to their audience through RFC 8707 resource indicators, and forbids token passthrough.

The central governance rule is that an agent that is halted, suspended, retired or not approved for production must not get credentials. That rule depends on core state that changes at any moment, for example when someone presses the kill switch. The component that issues credentials has to see that state at issuance time.

## Decision

- **The core includes a minimal OAuth 2.0 authorization server for machine identities.** It supports only the client credentials grant with `private_key_jwt` client authentication (RFC 7523). Agents and module instances register public keys; White Tower never holds their private keys.
- **Access tokens** are JWTs following RFC 9068, signed with ES256 (the most widely supported algorithm for verifiers), valid for 5 minutes by default and 15 at most. They carry the SPIFFE-format subject (`spiffe://<trust-domain>/agent/<agent-id>`), the audience requested through a resource indicator (RFC 8707) and White Tower claims: agent ID, owner, environment and risk tier.
- **Issuance checks governance state in the same database transaction** (AID-04): no token for halted, suspended or retired agents; production tokens only for active agents. The one exception is the module API: the enforcement point of a halted or suspended agent still gets tokens for it, and only for it, so it can acknowledge the halt, deliver its evidence and learn of the release ([threat model](../security/threat-model.md), DC-1). That channel cannot free the agent: the state it carries keeps the gate closed.
- **Discovery.** JWKS at `/.well-known/jwks.json` and RFC 8414 metadata at `/.well-known/oauth-authorization-server`. Signing keys rotate with overlap.
- **Extension points**, designed now and built later:
  - Kubernetes workload identity federation, accepting projected service account tokens as client assertions (AID-07, Should in the MVP).
  - Token exchange (RFC 8693) for per-task tokens carrying the on-behalf-of user (AID-08, Phase 2).
  - SPIFFE SVIDs from SPIRE as client credentials (AID-09).
  - External issuers (Keycloak, Entra Agent ID and others) through an identity module, where the core keeps the registry and the governance gate.

## Consequences

**Easier**
- The governance gate is atomic: once the kill switch commits, no new token is issued for any audience but the module API.
- No extra component for pilots and air-gapped installs.
- Standard OAuth: gateways, MCP servers and tools can verify tokens with any JWT library and the published JWKS. Audience-bound tokens fit the MCP authorization rules the Phase 2 gateway will follow.

**Harder**
- White Tower owns a security-critical piece of code. Mitigations: a deliberately narrow feature set (one grant, one client authentication method), well-reviewed libraries (`go-jose`), negative tests (algorithm confusion, replay, audience, expiry) and fuzzing.
- Outstanding tokens stay valid until they expire (5 minutes by default). This is acceptable because halts do not rely on tokens: they are pushed to enforcement points (ADR-0005).

## Alternatives considered

- **Keycloak, one client per agent.** A mature authorization server, but it cannot see halts or lifecycle state at issuance time without synchronization, which reopens the window the governance gate is meant to close. Kept as an external issuer option.
- **SPIRE as the only identity source.** Excellent workload attestation, but it requires deploying SPIRE everywhere, which is too much for pilots. Supported as a credential source later.
- **AGT or vendor-specific identities** (decentralized identifiers, Entra Agent ID). Tied to one ecosystem; they can be mapped to White Tower identities by adapters.
- **A full OAuth framework (for example `ory/fosite`).** Much larger surface than the single grant needed.
