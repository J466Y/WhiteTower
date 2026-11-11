# Runbook: the identity provider is compromised

| | |
| --- | --- |
| **When** | Someone could sign in as anyone through the organization's identity provider, or change who is in which group: its administrators' accounts, its signing keys or its group membership were compromised |
| **Who** | The break-glass custodians, the platform administrator and the identity provider's administrators |
| **Requirements** | HUM-06, HUM-10; security tests ST-14, ST-89 |

White Tower trusts the identity provider for who people are and for their groups, from which their roles come (threat model, T-14 and R-07). While the provider is compromised, everything that it signed in may be an intruder's: the console's sessions, which last up to 12 hours, the CLI's tokens, up to 12 hours, and the API tokens that those sessions created, up to 90 days.

Fixing the provider changes no setting of White Tower, so on its own it ends none of them. Follow these steps in order.

## Before an incident

Break-glass must be on (`auth.breakglass.enabled`, with `auth.breakglass.credential_hash_file`), with its credential split between two custodians: once OIDC is off, a break-glass session is the only way in. `whitetower breakglass init` makes the credential, and shows it once. Turning break-glass on during the incident takes a restart of every replica.

## 1. Turn OIDC off

On every replica, empty `auth.oidc.issuer` (`WT_AUTH_OIDC_ISSUER`) and restart, every replica at once if you can.

- The server then refuses every session that the provider created, and every token of the CLI's exchange: they record the hash of the sign-in configuration, which the issuer is part of. Sign-in and the CLI's exchange are gone, so nobody signs in through the provider again.
- During a rolling restart, a replica that still runs OIDC accepts them. Finish the restart before you go on.
- The API tokens that people and service accounts created are not affected: the next step ends them.

## 2. Revoke every session and API token

Sign in with break-glass (`POST /auth/breakglass`), then run the emergency revocation, with a reason such as a reference to the incident:

```sh
# The break-glass session's cookie, and the CSRF token that /api/v1/me returns.
curl -X POST https://whitetower.example.com/api/v1/emergency-revocation \
  -H 'Content-Type: application/json' \
  -H "Cookie: __Host-wt_session=$SESSION" -H "X-CSRF-Token: $CSRF" \
  -d '{"reason":"INC-2041: the identity provider was compromised"}'
```

- It ends every session and every API token, of people and of service accounts, the CLI's included, on every replica. The other break-glass sessions end too. Only your break-glass session stays, so that you can go on halting agents while the provider is fixed.
- The answer says how many sessions and tokens it revoked, of those not revoked before, expired ones included. The audit log records `whitetower.access.revoked_all.v1`, and the server logs a security alert.
- Principals and their roles stay. Running it again ends what was created since, and is recorded again.
- No API token can run it, whatever its scopes. The platform administrator can, from a session, but only break-glass sessions exist while OIDC is off.

Then read the audit log for what the provider's sign-ins did while it was compromised: the sessions and tokens created (`whitetower.session.created.v1`, `whitetower.token.created.v1`), the changes of groups (`whitetower.principal.groups_changed.v1`), the service accounts created, and what their principals did.

## 3. Fix the provider

Follow the provider's own procedure: remove the intruder's access, rotate its signing keys, and check the membership of every group that `auth.oidc.role_mapping` maps to a role, since White Tower's roles come from those groups. Rotate the client secret of White Tower's client too (`auth.oidc.client_secret_file`): rotating it signs nobody out.

## 4. Turn OIDC on again

Restore `auth.oidc.issuer` on every replica, and restart. People sign in again, and the CLI logs in again.

- The sessions and CLI tokens of before step 1 record the same configuration as now, so the server would accept them again: step 2 revoked them.
- The integrations' tokens were revoked too: their owners create them again.
- End your break-glass session: sign out in the console, or `POST /auth/logout` with its CSRF token.

## 5. Rotate the SCIM token

If SCIM is on (`auth.scim.enabled`), the provider held the token that SCIM requests carry, and it may have leaked: write a new token to `auth.scim.token_file`, give it to the provider's SCIM client, and restart every replica, which reads the file at start.

The modules' credentials are neither sessions nor API tokens, so the revocation does not end them. Rotating them, if they could have leaked, comes with plan P1-05, which adds it to this runbook.
