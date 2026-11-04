# SAML 2.0 Identity Providers via Keycloak Broker

How to connect SAML-only identity providers (such as Active Directory Federation Services, Shibboleth, PingFederate, or Okta SAML) to White Tower using Keycloak as an OpenID Connect (OIDC) identity broker (requirement HUM-08, plan P1-03 step 10).

## Overview

White Tower uses OpenID Connect (OIDC) with PKCE and a Backend-for-Frontend (BFF) architecture for human authentication. Organizations that standardize on SAML 2.0 can authenticate against White Tower without native SAML support by using Keycloak as an identity broker:

```
+-------------+         OIDC          +---------------+         SAML 2.0        +-------------+
| White Tower | <-------------------> | Keycloak      | <---------------------> | Enterprise  |
| Console     |  Authorization Code   | (OIDC Broker) |   AuthnRequest / POST   | SAML IdP    |
| (BFF)       |  with S256 PKCE       +---------------+   SAMLResponse          +-------------+
+-------------+
```

1. The user initiates login at White Tower (`/auth/login`).
2. White Tower redirects to Keycloak's authorization endpoint with PKCE (`S256`).
3. Keycloak redirects the user to the enterprise SAML IdP with a signed SAML `AuthnRequest`.
4. The user authenticates at the SAML IdP (e.g. through Kerberos, smart card, or enterprise MFA).
5. The SAML IdP returns a signed SAML assertion via HTTP POST to Keycloak's Assertion Consumer Service (ACS).
6. Keycloak maps SAML attributes (email, name, group memberships) into user attributes and realm groups.
7. Keycloak issues standard OpenID Connect tokens (`id_token`) containing the user's identity and group claims.
8. White Tower validates the ID token, synchronizes the principal record, derives effective roles, and issues a session cookie.

---

## Prerequisites

- A running Keycloak instance (v24 or later) with administrative access.
- A realm configured for White Tower (e.g., the `whitetower` realm from `deploy/compose/dev/keycloak/whitetower-realm.json`).
- Administrative access to the enterprise SAML Identity Provider to register White Tower / Keycloak as a Service Provider (SP).
- Metadata or endpoints from the SAML IdP:
  - IdP Entity ID / Issuer URI.
  - Single Sign-On (SSO) Service URL (HTTP-POST or HTTP-Redirect binding).
  - IdP X.509 signing certificate (PEM format).

---

## Step 1: Configure Keycloak as a SAML Service Provider

1. Open the Keycloak Administration Console and select the **whitetower** realm.
2. In the left navigation menu, click **Identity Providers**.
3. In the **Add provider** dropdown, select **SAML v2.0**.
4. Configure the general settings:
   - **Alias**: `saml-idp` (used in callback URLs).
   - **Display name**: `Enterprise SAML SSO` (shown on the Keycloak login screen).
5. Import IdP Metadata:
   - **Use entity descriptor**: If the SAML IdP provides an XML metadata URL or file, paste it or upload it directly. Keycloak will automatically populate the endpoints and signing certificates.
   - **Manual configuration** (if metadata is not available):
     - **Service Provider Entity ID**: `https://<keycloak-host>/realms/whitetower`
     - **Single Sign-On Service URL**: Enter the SAML IdP's SSO URL.
     - **Single Logout Service URL**: Enter the SAML IdP's Single Logout URL (optional).
     - **NameID Policy Format**: `Email` or `Persistent` or `Unspecified`.
     - **Principal Type**: `Attribute [Name]` (e.g., `email`) or `Subject NameID`.
     - **Signature Algorithm**: `RSA_SHA256` (refuse legacy `RSA_SHA1`).
     - **Validate Signature**: `ON`.
     - **Validating X509 Certificates**: Paste the IdP signing certificate.
6. Click **Save**.

---

## Step 2: Register Keycloak in the Enterprise SAML IdP

Register Keycloak as a trusted SAML Service Provider (SP) in your enterprise IdP using the following endpoints:

| Parameter | Value |
| --- | --- |
| **SP Entity ID / Audience** | `https://<keycloak-host>/realms/whitetower` |
| **Assertion Consumer Service (ACS) URL** | `https://<keycloak-host>/realms/whitetower/broker/saml-idp/endpoint` |
| **Single Logout URL** | `https://<keycloak-host>/realms/whitetower/broker/saml-idp/endpoint` |
| **Binding** | HTTP-POST |
| **NameID Format** | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |

Ensure the SAML IdP releases the following SAML attributes in its assertion:
- `email` (or `urn:oid:0.9.2342.19200300.100.1.3` / `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`): User's corporate email.
- `displayName` (or `givenName` and `surname`): User's full name.
- `memberOf` (or `groups` / `http://schemas.xmlsoap.org/claims/Group`): Security group memberships.

---

## Step 3: Configure SAML Attribute Mappers in Keycloak

To map incoming SAML assertions to Keycloak user attributes and White Tower governance groups:

1. In Keycloak, navigate to **Identity Providers** > **saml-idp** > **Mappers**.
2. Click **Add mapper** for each attribute:

### Email Mapper
- **Name**: `email-mapper`
- **Mapper Type**: `Attribute Importer`
- **Attribute Name**: `email` (or the exact SAML claim URI sent by the IdP)
- **User Attribute Name**: `email`

### Display Name Mapper
- **Name**: `name-mapper`
- **Mapper Type**: `Attribute Importer`
- **Attribute Name**: `displayName`
- **User Attribute Name**: `displayName`

### Group Mappers (Role Synchronization)
Map corporate directory groups to White Tower governance groups (`/wt-steering`, `/wt-advisory`, `/wt-owners`, `/wt-users`, `/wt-operators`, `/wt-auditors`, `/wt-admins`):

For each role:
- **Name**: `map-owners`
- **Mapper Type**: `Advanced Claim to Group`
- **Claims**:
  - **Key**: `memberOf` (or `groups`)
  - **Value**: `CN=WhiteTower-Owners,OU=Groups,DC=corp,DC=example,DC=com` (or regex matching your IdP group pattern)
- **Group**: `/wt-owners`

Repeat for each required governance group.

---

## Step 4: Verify the White Tower OIDC Client

Keycloak must send the browser back to White Tower, and expose the mapped groups in the OIDC ID token claim that White Tower consumes.

1. In Keycloak, navigate to **Clients** > **whitetower-console** > **Settings**, and check the client's exact URIs, without wildcards:
   - **Valid redirect URIs**: `https://<whitetower-host>/auth/callback`, the server's `auth.oidc.redirect_url`.
   - **Valid post logout redirect URIs**: `https://<whitetower-host>/`, the console's root on the origin of `auth.oidc.redirect_url`. After a logout, White Tower sends the browser to Keycloak with this URI and the client's ID, and Keycloak refuses a URI that it does not list.
2. Navigate to **Clients** > **whitetower-console** > **Client scopes**.
3. Verify that the dedicated client scope contains a `groups` mapper:
   - **Mapper Type**: `Group Membership`
   - **Token Claim Name**: `groups`
   - **Full group path**: `false` (outputs `["wt-owners"]` instead of `["/wt-owners"]`, or keep `true` since White Tower normalizes leading slashes)
   - **Add to ID token**: `ON`
   - **Add to userinfo**: `ON`

---

## Step 5: White Tower Server Configuration

In `whitetower.yaml`, configure the OIDC provider pointing to Keycloak:

```yaml
auth:
  oidc:
    issuer: "https://<keycloak-host>/realms/whitetower"
    client_id: "whitetower-console"
    client_secret_file: "/etc/whitetower/secrets/oidc-client-secret"
    state_key_file: "/etc/whitetower/secrets/oidc-state-key"
    redirect_url: "https://<whitetower-host>/auth/callback"
    scopes:
      - "openid"
      - "profile"
      - "email"
    groups_claim: "groups"
    external_id_claim: "sub"
    role_mapping:
      wt-steering: steering
      wt-advisory: advisory
      wt-owners: owner
      wt-users: user
      wt-operators: operator
      wt-auditors: auditor
      wt-admins: admin
    allowed_algorithms:
      - "RS256"
      - "ES256"
```

The state key signs the state of each sign-in, which the browser keeps in a cookie until Keycloak sends it back. Make it once, with `openssl rand -base64 32 > oidc-state-key`, and give every replica of the server the same file, so that a sign-in can end on another replica than the one it started on.

`external_id_claim` names the claim of the ID token that identifies the person to SCIM as well: the section on SCIM below says which to choose.

The scopes leave out `groups`, which the server asks for by default. Keycloak defines no `groups` client scope and answers `invalid_scope` to a request for one, while the mapper of step 4 already puts the groups in the ID token. To ask for `groups`, first create a client scope named `groups` in Keycloak and add it to the client's default client scopes.

---

## Step 6: End-to-End Verification

1. Navigate to White Tower in a browser: `https://<whitetower-host>/auth/login`.
2. White Tower initiates OIDC authorization with Keycloak.
3. Keycloak redirects to the enterprise SAML IdP.
4. Complete authentication at the SAML IdP.
5. Upon return, verify that:
   - The user is redirected to the White Tower console.
   - `GET /api/v1/me`, opened in the same browser, returns the authenticated principal, with the roles that its groups map to, the permissions of those roles and the session's CSRF token. For a member of `wt-admins`:
     ```json
     {
       "csrfToken": "SPewXN0PyWqBMhFQ3FPoJwuEntUsZ4bRp7p_-02k-y8",
       "displayName": "Alice Admin",
       "id": "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59",
       "kind": "human",
       "permissions": ["identity.me.read", "inventory.view", "settings.manage"],
       "roles": ["admin"]
     }
     ```
   - The audit log records nothing of the sign-in yet: the first sign-in creates the principal, and each sign-in updates its groups and its last sign-in time, without an audit event. The events of people and sessions are planned (requirement AUD-01). A sign-in that fails leaves its cause in the server's log.

---

## SCIM and sign-in: one principal per person

When the identity provider also provisions people through SCIM (`auth.scim.enabled`), the user that SCIM creates and the person who signs in must be the same principal, or SCIM's deactivation does not reach the person (requirement HUM-05, security test ST-21). White Tower links them by one value, the person's **external ID**:

- SCIM sends it as the user's `externalId`. White Tower refuses a user without one (`400`, `invalidValue`), and a change of it in a `PATCH` (`400`, `mutability`): the external ID is what ties the user to the person who signs in.
- The ID token carries it in the claim that `auth.oidc.external_id_claim` names: `sub` by default. A sign-in finds the principal with that external ID. An ID token without the claim, or whose claim is not a string, is refused (`403`), and the server's log names the claim, never its value. No other claim stands in for it.

Map both to the same value, one that never changes and that the person cannot edit: not an email address or a username.

| Who issues the ID token | `auth.oidc.external_id_claim` | SCIM's `externalId` |
| --- | --- | --- |
| Keycloak, for its own users | `sub`, the default: the user's ID in Keycloak | The user's ID, if a SCIM client provisions from Keycloak |
| Microsoft Entra ID, signing in to White Tower directly | `oid`: the user's object ID, which Entra ID puts in the ID token with the `profile` scope. Entra ID's `sub` differs from one client to another, the console's and the CLI's included | The object ID. Entra ID's default SCIM mapping sends `mailNickname` as `externalId`: in the enterprise application, under **Provisioning** > **Mappings** > **Provision Microsoft Entra ID Users**, edit the mapping of `externalId` and choose the source attribute `objectId` |
| Keycloak, brokering Entra ID through SAML as this guide does | `oid`, which Keycloak must add: its own `sub` is a user ID that Entra ID does not know. Import the SAML attribute `http://schemas.microsoft.com/identity/claims/objectidentifier` into a user attribute with an **Attribute Importer** mapper (step 3), and add a **User Attribute** mapper to the `whitetower-console` client that writes it into the ID token as `oid` | The object ID, mapped from `objectId` as above |

If the two values differ, SCIM's user and the person who signs in are two principals: SCIM's deactivation deactivates its own, and the person's sessions and API tokens stay valid.

A person who signed in before SCIM provisioned them already has a principal with their external ID. SCIM's creation of that user takes the principal over rather than creating a second one: the answer is `201` with the principal's ID, SCIM's `userName`, name and email address are set on it, and the audit log records `whitetower.principal.adopted.v1`. A user whose `externalId` SCIM already gave another user is refused (`409`, `uniqueness`).

SCIM supports one filter, `userName eq "value"`, which finds the user that SCIM created, or took over, with that `userName`. Any other filter, such as `emails.value eq` or `externalId eq`, is refused (`400`, `invalidFilter`). SCIM reaches people only: never a service account or the break-glass custodian.

Choose the claim before people sign in: changing `auth.oidc.external_id_claim` afterwards is not supported yet. The principal of a person who signed in before holds the old value, so their sign-in finds no principal by the new one, finds theirs by its issuer and subject, and is refused (`403`); the server logs `refusing a sign-in` with the principal's ID and the claim's name, and no value of the token.

When upgrading from a version without external IDs, the principals that people signed in as have none until their next sign-in, which gives them theirs. If SCIM provisions such a person before they sign in again, it creates a second principal, which their sign-ins find from then on. No release of White Tower came before external IDs, so this concerns development and evaluation data only.

---

## Troubleshooting

- **Invalid signature / algorithm mismatch:** Ensure the SAML IdP uses SHA-256 for signing assertions. Keycloak refuses SHA-1 by default.
- **Missing groups:** Inspect Keycloak's user profile after first login to ensure the SAML `memberOf` claim was populated and matched the group mapper rules.
- **Time drift:** Ensure NTP is active on both the SAML IdP and Keycloak servers. SAML assertion `NotBefore` and `NotOnOrAfter` tolerances are typically under 60 seconds.
