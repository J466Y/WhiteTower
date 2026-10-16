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

## Step 4: Verify White Tower OIDC Client Mappers

Keycloak must expose the mapped groups in the OIDC ID token claim that White Tower consumes.

1. In Keycloak, navigate to **Clients** > **whitetower-console** > **Client scopes**.
2. Verify that the dedicated client scope contains a `groups` mapper:
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
    redirect_url: "https://<whitetower-host>/auth/callback"
    scopes:
      - "openid"
      - "profile"
      - "email"
      - "groups"
    groups_claim: "groups"
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

---

## Step 6: End-to-End Verification

1. Navigate to White Tower in a browser: `https://<whitetower-host>/auth/login`.
2. White Tower initiates OIDC authorization with Keycloak.
3. Keycloak redirects to the enterprise SAML IdP.
4. Complete authentication at the SAML IdP.
5. Upon return, verify that:
   - The user is redirected to the White Tower console.
   - `GET /api/v1/me` returns the authenticated principal:
     ```json
     {
       "id": "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59",
       "displayName": "Alice Admin",
       "roles": ["admin"],
       "permissions": ["*"]
     }
     ```
   - An audit event `whitetower.principal.provisioned.v1` or login audit trail is recorded.

---

## Troubleshooting

- **Invalid signature / algorithm mismatch:** Ensure the SAML IdP uses SHA-256 for signing assertions. Keycloak refuses SHA-1 by default.
- **Missing groups:** Inspect Keycloak's user profile after first login to ensure the SAML `memberOf` claim was populated and matched the group mapper rules.
- **Time drift:** Ensure NTP is active on both the SAML IdP and Keycloak servers. SAML assertion `NotBefore` and `NotOnOrAfter` tolerances are typically under 60 seconds.
