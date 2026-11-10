package authn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Security test ST-19: API tokens: scopes enforced, expiry, storage only as a hash, revocation with the principal
func TestAPITokenSecurity(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)

	az := authz.NewAuthorizer()
	authenticator := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, map[string]string{
		"admins":    "admin",
		"operators": "operator",
		"auditors":  "auditor",
	})

	email := "alice@example.com"
	principal, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-alice", ExternalID: "sub-alice", DisplayName: "Alice Admin", Email: &email, Groups: []string{"admins"}}, nil)
	if err != nil {
		t.Fatalf("upserting principal: %v", err)
	}

	adminActor := auth.Principal{
		ID:    principal.ID.String(),
		Kind:  auth.Human,
		Name:  "Alice Admin",
		Roles: []string{"admin"},
	}

	t.Run("storage only as a hash", func(t *testing.T) {
		scopes := []string{string(authz.PermissionAuditEventsRead)}
		created, err := tokenStore.Create(ctx, principal.ID, "ci-token", scopes, 30, adminActor)
		if err != nil {
			t.Fatalf("creating token: %v", err)
		}

		if len(created.Token) < 40 || created.Token[:7] != authn.TokenPrefix {
			t.Errorf("token %q does not match expected prefix", created.Token)
		}

		// Verify database storage
		var dbPrefix string
		var dbHash []byte
		var dbName string
		err = database.QueryRow(ctx, "SELECT token_prefix, token_hash, name FROM whitetower.api_tokens WHERE id = $1", created.ID).
			Scan(&dbPrefix, &dbHash, &dbName)
		if err != nil {
			t.Fatalf("querying token row: %v", err)
		}

		if len(dbHash) != 32 {
			t.Fatalf("expected 32-byte SHA-256 hash, got %d bytes", len(dbHash))
		}

		expectedHash := sha256.Sum256([]byte(created.Token))
		if string(dbHash) != string(expectedHash[:]) {
			t.Fatalf("db token_hash does not match sha256 of plaintext token")
		}

		if dbPrefix != created.Token[:15] {
			t.Errorf("db prefix %q, want %q", dbPrefix, created.Token[:15])
		}

		// Ensure raw secret is not stored anywhere
		var rawCount int
		err = database.QueryRow(ctx, "SELECT COUNT(*) FROM whitetower.api_tokens WHERE name = $1 OR token_prefix = $1", created.Token).
			Scan(&rawCount)
		if err != nil {
			t.Fatalf("checking raw token presence: %v", err)
		}
		if rawCount != 0 {
			t.Errorf("raw token secret leaked into database columns")
		}
	})

	t.Run("scopes enforced", func(t *testing.T) {
		// Create an operator who has PermissionAuditEventsRead and PermissionHaltFleetIssue.
		opEmail := "operator@example.com"
		op, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-operator", ExternalID: "sub-operator", DisplayName: "Op Operator", Email: &opEmail, Groups: []string{"operators"}}, nil)
		if err != nil {
			t.Fatalf("upserting operator: %v", err)
		}
		opActor := auth.Principal{ID: op.ID.String(), Kind: auth.Human, Name: "Op Operator", Roles: []string{"operator"}}

		// We create a token scoped ONLY to audit events read.
		scopes := []string{string(authz.PermissionAuditEventsRead)}
		created, err := tokenStore.Create(ctx, op.ID, "read-only-audit", scopes, 15, opActor)
		if err != nil {
			t.Fatalf("creating scoped token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
		req.Header.Set("Authorization", "Bearer "+created.Token)

		p, err := authenticator.Authenticate(req)
		if err != nil {
			t.Fatalf("authenticating with token: %v", err)
		}

		if len(p.Scopes) != 1 || p.Scopes[0] != string(authz.PermissionAuditEventsRead) {
			t.Fatalf("expected scopes [%s], got %v", authz.PermissionAuditEventsRead, p.Scopes)
		}

		// Permitted by role and permitted by token scope:
		if err := az.Authorize(ctx, p, "getAuditEvents"); err != nil {
			t.Errorf("expected getAuditEvents permitted, got %v", err)
		}

		// Permitted by role (operator has haltFleet), but NOT in token scopes: MUST be denied (ST-19).
		if err := az.Authorize(ctx, p, "haltFleet"); !errors.Is(err, auth.ErrDenied) {
			t.Errorf("expected haltFleet denied by token scope, got %v", err)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		scopes := []string{string(authz.PermissionAuditEventsRead)}
		created, err := tokenStore.Create(ctx, principal.ID, "expiring-token", scopes, 10, adminActor)
		if err != nil {
			t.Fatalf("creating token: %v", err)
		}

		// Valid on creation
		tok, _, err := tokenStore.GetByToken(ctx, created.Token)
		if err != nil {
			t.Fatalf("get token before expiry: %v", err)
		}
		if tok.LastUsedAt == nil {
			t.Errorf("expected LastUsedAt to be updated on touch")
		}

		// Advance clock past expiration (11 days)
		clk.Advance(11 * 24 * time.Hour)

		_, _, err = tokenStore.GetByToken(ctx, created.Token)
		if !errors.Is(err, authn.ErrTokenExpired) {
			t.Fatalf("expected ErrTokenExpired, got %v", err)
		}

		// Authenticator also refuses expired token
		req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		req.Header.Set("Authorization", "Bearer "+created.Token)
		if _, err := authenticator.Authenticate(req); !errors.Is(err, authn.ErrTokenExpired) {
			t.Errorf("authenticator expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("revocation with the principal", func(t *testing.T) {
		// Create a separate user with tokens
		bobEmail := "bob@example.com"
		bob, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-bob", ExternalID: "sub-bob", DisplayName: "Bob Operator", Email: &bobEmail, Groups: []string{"operators"}}, nil)
		if err != nil {
			t.Fatalf("upserting bob: %v", err)
		}

		bobActor := auth.Principal{ID: bob.ID.String(), Kind: auth.Human, Name: "Bob Operator"}
		t1, err := tokenStore.Create(ctx, bob.ID, "bob-pat-1", []string{string(authz.PermissionInventoryView)}, 30, bobActor)
		if err != nil {
			t.Fatalf("creating token 1: %v", err)
		}
		t2, err := tokenStore.Create(ctx, bob.ID, "bob-pat-2", []string{string(authz.PermissionAuditEventsRead)}, 30, bobActor)
		if err != nil {
			t.Fatalf("creating token 2: %v", err)
		}

		// Verify tokens work before deactivation
		if _, _, err := tokenStore.GetByToken(ctx, t1.Token); err != nil {
			t.Fatalf("token 1 should be valid: %v", err)
		}
		if _, _, err := tokenStore.GetByToken(ctx, t2.Token); err != nil {
			t.Fatalf("token 2 should be valid: %v", err)
		}

		// Deactivate Bob
		if err := principalStore.Deactivate(ctx, bob.ID, adminActor, "left organization"); err != nil {
			t.Fatalf("deactivating principal: %v", err)
		}

		// Both tokens must now be revoked
		if _, _, err := tokenStore.GetByToken(ctx, t1.Token); !errors.Is(err, authn.ErrTokenRevoked) && !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Errorf("token 1 should be revoked after deactivation, got %v", err)
		}
		if _, _, err := tokenStore.GetByToken(ctx, t2.Token); !errors.Is(err, authn.ErrTokenRevoked) && !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Errorf("token 2 should be revoked after deactivation, got %v", err)
		}

		// Verify revoked_at in DB
		list, err := tokenStore.ListByPrincipal(ctx, bob.ID)
		if err != nil {
			t.Fatalf("listing bob tokens: %v", err)
		}
		for _, tok := range list {
			if tok.RevokedAt == nil {
				t.Errorf("token %s was not marked revoked in database", tok.ID)
			}
		}
	})

	t.Run("manual revocation", func(t *testing.T) {
		scopes := []string{string(authz.PermissionAuditEventsRead)}
		tok, err := tokenStore.Create(ctx, principal.ID, "token-to-revoke", scopes, 30, adminActor)
		if err != nil {
			t.Fatalf("creating token: %v", err)
		}

		if err := tokenStore.Revoke(ctx, tok.ID, adminActor, "lost credential"); err != nil {
			t.Fatalf("revoking token: %v", err)
		}

		if _, _, err := tokenStore.GetByToken(ctx, tok.Token); !errors.Is(err, authn.ErrTokenRevoked) {
			t.Fatalf("expected ErrTokenRevoked, got %v", err)
		}
	})

	t.Run("service account lifecycle and tokens", func(t *testing.T) {
		// 1. Create service account tied to Audrey, an auditor
		audreyEmail := "audrey@example.com"
		audrey, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-audrey", ExternalID: "sub-audrey", DisplayName: "Audrey Auditor", Email: &audreyEmail, Groups: []string{"auditors"}}, nil)
		if err != nil {
			t.Fatalf("upserting audrey: %v", err)
		}
		audreyActor := auth.Principal{ID: audrey.ID.String(), Kind: auth.Human, Name: "Audrey Auditor", Roles: []string{"auditor"}}
		saEmail := "pipeline@example.com"
		sa, err := principalStore.CreateServiceAccount(ctx, "CI Pipeline", &saEmail, []string{"auditor"}, audreyActor)
		if err != nil {
			t.Fatalf("creating service account: %v", err)
		}

		if sa.Kind != "service_account" {
			t.Errorf("expected service_account kind, got %s", sa.Kind)
		}
		if sa.ResponsiblePrincipalID == nil || *sa.ResponsiblePrincipalID != audrey.ID {
			t.Errorf("expected responsible principal %s, got %v", audrey.ID, sa.ResponsiblePrincipalID)
		}

		// 2. Issue token for service account
		saActor := auth.Principal{ID: sa.ID.String(), Kind: auth.ServiceAccount, Name: "CI Pipeline"}
		saToken, err := tokenStore.Create(ctx, sa.ID, "pipeline-key", []string{string(authz.PermissionAuditEventsRead)}, 60, saActor)
		if err != nil {
			t.Fatalf("creating service account token: %v", err)
		}

		// 3. Authenticate with service account token
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
		req.Header.Set("Authorization", "Bearer "+saToken.Token)
		authP, err := authenticator.Authenticate(req)
		if err != nil {
			t.Fatalf("authenticating service account: %v", err)
		}

		if authP.Kind != auth.ServiceAccount {
			t.Errorf("expected principal kind service_account, got %s", authP.Kind)
		}
		if len(authP.Roles) != 1 || authP.Roles[0] != "auditor" {
			t.Errorf("expected role [auditor], got %v", authP.Roles)
		}

		// 4. List service accounts
		sas, err := principalStore.ListServiceAccounts(ctx, &audrey.ID)
		if err != nil {
			t.Fatalf("listing service accounts: %v", err)
		}
		if len(sas) == 0 {
			t.Fatalf("expected at least 1 service account")
		}

		// 5. Service account cannot be created with nonexistent responsible principal
		nobody := auth.Principal{ID: uuid.New().String(), Kind: auth.Human, Roles: []string{"auditor"}}
		_, err = principalStore.CreateServiceAccount(ctx, "Bad SA 1", nil, []string{"auditor"}, nobody)
		if !errors.Is(err, authn.ErrPrincipalNotFound) {
			t.Errorf("expected ErrPrincipalNotFound for nonexistent responsible principal, got %v", err)
		}

		// 6. Service account cannot be created with inactive responsible principal
		deactivatedEmail := "inactive-user@example.com"
		inactiveUser, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-inactive", ExternalID: "sub-inactive", DisplayName: "Inactive User", Email: &deactivatedEmail, Groups: []string{"operators"}}, nil)
		if err != nil {
			t.Fatalf("upserting inactive user: %v", err)
		}
		if err := principalStore.Deactivate(ctx, inactiveUser.ID, adminActor, "test deactivation"); err != nil {
			t.Fatalf("deactivating user: %v", err)
		}
		inactiveActor := auth.Principal{ID: inactiveUser.ID.String(), Kind: auth.Human, Roles: []string{"operator"}}
		_, err = principalStore.CreateServiceAccount(ctx, "Bad SA 2", nil, []string{"operator"}, inactiveActor)
		if !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Errorf("expected ErrPrincipalInactive for inactive responsible principal, got %v", err)
		}
	})

	t.Run("a service account acts with no more than its responsible principal holds", func(t *testing.T) {
		// Owen holds the operator and auditor roles through his IdP groups.
		owenEmail := "owen@example.com"
		owen, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-owen", ExternalID: "sub-owen", DisplayName: "Owen Operator", Email: &owenEmail, Groups: []string{"operators", "auditors"}}, nil)
		if err != nil {
			t.Fatalf("upserting owen: %v", err)
		}
		owenActor := auth.Principal{ID: owen.ID.String(), Kind: auth.Human, Name: "Owen Operator", Roles: []string{"auditor", "operator"}}
		sa, err := principalStore.CreateServiceAccount(ctx, "Halt Bot", nil, []string{"operator", "auditor"}, owenActor)
		if err != nil {
			t.Fatalf("creating service account: %v", err)
		}
		saActor := auth.Principal{ID: sa.ID.String(), Kind: auth.ServiceAccount, Name: "Halt Bot"}
		saToken, err := tokenStore.Create(ctx, sa.ID, "halt-bot", []string{string(authz.PermissionAuditEventsRead)}, 30, saActor)
		if err != nil {
			t.Fatalf("creating service account token: %v", err)
		}
		rolesOf := func() ([]string, error) {
			t.Helper()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/events", nil)
			req.Header.Set("Authorization", "Bearer "+saToken.Token)
			p, err := authenticator.Authenticate(req)
			if err != nil {
				return nil, err
			}
			return p.Roles, nil
		}

		if roles, err := rolesOf(); err != nil || strings.Join(roles, ",") != "auditor,operator" {
			t.Fatalf("roles %v, %v; want auditor and operator", roles, err)
		}

		// Owen leaves the operators' group: his service account loses the role
		// too, although it is still bound to it.
		if _, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-owen", ExternalID: "sub-owen", DisplayName: "Owen Operator", Email: &owenEmail, Groups: []string{"auditors"}}, nil); err != nil {
			t.Fatalf("updating owen's groups: %v", err)
		}
		if roles, err := rolesOf(); err != nil || strings.Join(roles, ",") != "auditor" {
			t.Fatalf("roles %v, %v; want auditor only", roles, err)
		}

		// Once Owen is inactive, his service account's tokens are refused.
		if err := principalStore.Deactivate(ctx, owen.ID, adminActor, "left the organization"); err != nil {
			t.Fatalf("deactivating owen: %v", err)
		}
		if _, err := rolesOf(); !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Fatalf("got %v, want ErrPrincipalInactive", err)
		}
	})

	// Security test ST-18: Nobody gets a role through a service account that they do not hold
	t.Run("a service account gets only roles that its responsible principal holds", func(t *testing.T) {
		uliEmail := "uli@example.com"
		uli, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-uli", ExternalID: "sub-uli", DisplayName: "Uli User", Email: &uliEmail}, nil)
		if err != nil {
			t.Fatalf("upserting uli: %v", err)
		}
		uliActor := auth.Principal{ID: uli.ID.String(), Kind: auth.Human, Name: "Uli User", Roles: []string{"user"}}
		for _, role := range []string{"advisory", "operator", "steering", "admin"} {
			if _, err := principalStore.CreateServiceAccount(ctx, "Escalator", nil, []string{role}, uliActor); !errors.Is(err, authn.ErrRoleNotHeld) {
				t.Errorf("%s: got %v, want ErrRoleNotHeld", role, err)
			}
		}
		if _, err := principalStore.CreateServiceAccount(ctx, "Helper", nil, []string{"user"}, uliActor); err != nil {
			t.Errorf("a role the user holds: %v", err)
		}

		// A service account is responsible for none.
		botActor := auth.Principal{ID: uuid.New().String(), Kind: auth.ServiceAccount, Roles: []string{"user"}}
		if _, err := principalStore.CreateServiceAccount(ctx, "Grandchild", nil, []string{"user"}, botActor); !errors.Is(err, authn.ErrResponsibleNotHuman) {
			t.Errorf("got %v, want ErrResponsibleNotHuman", err)
		}
	})

	t.Run("input validations", func(t *testing.T) {
		scopes := []string{string(authz.PermissionAuditEventsRead)}

		// Empty name
		if _, err := tokenStore.Create(ctx, principal.ID, "   ", scopes, 30, adminActor); err == nil {
			t.Errorf("expected error for empty name")
		}

		// Name too long
		longName := strings.Repeat("a", 101)
		if _, err := tokenStore.Create(ctx, principal.ID, longName, scopes, 30, adminActor); err == nil {
			t.Errorf("expected error for name > 100 characters")
		}

		// Invalid scope
		if _, err := tokenStore.Create(ctx, principal.ID, "bad-scope", []string{"invalid:scope:xyz"}, 30, adminActor); err == nil {
			t.Errorf("expected error for invalid scope")
		}

		// Expiry out of bounds
		if _, err := tokenStore.Create(ctx, principal.ID, "bad-expiry-0", scopes, -1, adminActor); err == nil {
			t.Errorf("expected error for negative expiry")
		}
		if _, err := tokenStore.Create(ctx, principal.ID, "bad-expiry-100", scopes, 91, adminActor); err == nil {
			t.Errorf("expected error for expiry > 90 days")
		}
	})
}

// tokensWithSignInConfiguration returns a token store of database whose CLI
// tokens the sign-in configuration c accepts: a replica, or a server after a
// restart, that runs those settings of auth.oidc.
func tokensWithSignInConfiguration(t *testing.T, database *db.DB, clk *clocktest.Fake, c authn.SignInConfiguration) *authn.TokenStore {
	t.Helper()
	return authn.NewTokenStore(database, clk, audit.NewWriter(mustCatalog(t), clk), authz.NewAuthorizer(), c)
}

// exchangeWith returns the CLI's exchange of a server that runs the sign-in
// configuration c, whose issuer is idp: a function that exchanges an ID token
// of idp for Cleo, in the group wt-owners, and returns the API token that
// tokens creates.
func exchangeWith(t *testing.T, idp *mockIDP, clk *clocktest.Fake, principals *authn.PrincipalStore, sessions *authn.SessionStore,
	tokens *authn.TokenStore, c authn.SignInConfiguration,
) func(t *testing.T) *authn.CreatedToken {
	t.Helper()
	svc := newService(t, authn.OIDCOptions{
		Issuer:            c.Issuer,
		ClientID:          c.ClientID,
		CLIClientID:       c.CLIClientID,
		AllowedAlgorithms: c.AllowedAlgorithms,
		ExternalIDClaim:   c.ExternalIDClaim,
		GroupsClaim:       c.GroupsClaim,
		RoleMapping:       c.RoleMapping,
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		Tokens:            tokens,
	}, principals, sessions)
	return func(t *testing.T) *authn.CreatedToken {
		t.Helper()
		created, err := svc.ExchangeIDToken(context.Background(), idp.signIDToken(map[string]any{}, map[string]any{
			"iss":    c.Issuer,
			"aud":    c.CLIClientID,
			"sub":    "usr-cleo",
			"name":   "Cleo Canary",
			"groups": []string{"wt-owners"},
			"exp":    clk.Now().Add(time.Hour).Unix(),
		}))
		if err != nil {
			t.Fatalf("exchanging an ID token: %v", err)
		}
		return created
	}
}

// Security test ST-14: a token of the CLI's exchange records the sign-in
// configuration that accepted its ID token, with the CLI's client ID, so a
// server whose configuration is another, after a change of one of those
// settings and a restart or on another replica, refuses the token as one that
// does not exist: a change of which ID tokens the exchange accepts, of which
// person a sign-in is, or of what roles it gives. A change of the console's
// client ID, which sessions record and these tokens do not, keeps them, as
// changes that carry no meaning do. The refusal changes nothing of the token,
// which the server of its configuration still accepts, and the hash of a
// token never passes for a session's
func TestACLITokenOfAnotherSignInConfigurationIsRefusedAsAnUnknownOne(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)
	// configuredWith is the configuration of the server whose exchange
	// creates the tokens, with a change.
	configuredWith := func(change func(c *authn.SignInConfiguration)) authn.SignInConfiguration {
		return signInConfiguration(func(c *authn.SignInConfiguration) {
			c.Issuer = idp.server.URL
			change(c)
		})
	}
	configured := configuredWith(func(*authn.SignInConfiguration) {})
	before := tokensWithSignInConfiguration(t, database, clk, configured)
	exchange := exchangeWith(t, idp, clk, principalStore, sessionStore, before, configured)

	for _, tt := range []struct {
		name  string
		after authn.SignInConfiguration
		want  error // nil: the token is accepted
	}{
		// What carries no meaning, and the console's client.
		{"the same configuration", configuredWith(func(c *authn.SignInConfiguration) {
			c.RoleMapping = map[string]string{"wt-admins": "admin", "wt-owners": "owner"}
		}), nil},
		{"the algorithms in another order, one of them listed twice", configuredWith(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = []string{"ES256", "RS256", "ES256"}
		}), nil},
		{"another client ID", configuredWith(func(c *authn.SignInConfiguration) {
			c.ClientID = "whitetower-console-2"
		}), nil},

		// Which ID tokens the exchange accepts.
		{"another CLI client ID", configuredWith(func(c *authn.SignInConfiguration) {
			c.CLIClientID = "wtctl-2"
		}), authn.ErrInvalidToken},
		{"another issuer", configuredWith(func(c *authn.SignInConfiguration) {
			c.Issuer = "https://idp.example.net/realms/whitetower"
		}), authn.ErrInvalidToken},
		{"the issuer with a trailing slash", configuredWith(func(c *authn.SignInConfiguration) {
			c.Issuer += "/"
		}), authn.ErrInvalidToken},
		{"OIDC turned off", configuredWith(func(c *authn.SignInConfiguration) {
			c.Issuer = ""
		}), authn.ErrInvalidToken},
		{"an algorithm added", configuredWith(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = append(c.AllowedAlgorithms, "PS256")
		}), authn.ErrInvalidToken},
		{"an algorithm removed", configuredWith(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = []string{"RS256"}
		}), authn.ErrInvalidToken},

		// Which person a sign-in is, and what roles it gives.
		{"another external ID claim", configuredWith(func(c *authn.SignInConfiguration) {
			c.ExternalIDClaim = "oid"
		}), authn.ErrInvalidToken},
		{"another groups claim", configuredWith(func(c *authn.SignInConfiguration) {
			c.GroupsClaim = "roles"
		}), authn.ErrInvalidToken},
		{"a role changed", configuredWith(func(c *authn.SignInConfiguration) {
			c.RoleMapping["wt-owners"] = "user"
		}), authn.ErrInvalidToken},

		// Strings that a separator would join alike.
		{"the issuer and the CLI client ID cut elsewhere", configuredWith(func(c *authn.SignInConfiguration) {
			c.Issuer, c.CLIClientID = c.Issuer+"w", "tctl"
		}), authn.ErrInvalidToken},
	} {
		t.Run(tt.name, func(t *testing.T) {
			created := exchange(t)
			if _, _, err := tokensWithSignInConfiguration(t, database, clk, tt.after).GetByToken(ctx, created.Token); !errors.Is(err, tt.want) {
				t.Errorf("a token of the CLI's exchange, with the configuration after: got %v, want %v", err, tt.want)
			}
			if _, _, err := before.GetByToken(ctx, created.Token); err != nil {
				t.Errorf("a token of the CLI's exchange, with its own configuration: got %v, want it accepted", err)
			}
		})
	}

	// The authenticator refuses it as a token that does not exist, which the
	// API answers as any credential that it does not accept.
	after := tokensWithSignInConfiguration(t, database, clk, configuredWith(func(c *authn.SignInConfiguration) {
		c.CLIClientID = "wtctl-2"
	}))
	authenticator := authn.NewAuthenticator(sessionStore, principalStore, after, configured.RoleMapping)
	created := exchange(t)
	clk.Advance(time.Minute)
	for name, token := range map[string]string{
		"a token of another configuration": created.Token,
		"a token that does not exist":      authn.TokenPrefix + "does-not-exist",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if p, err := authenticator.Authenticate(req); p != nil || !errors.Is(err, authn.ErrInvalidToken) {
			t.Errorf("authenticating with %s: got %v, %v; want it refused as an invalid token", name, p, err)
		}
	}

	// The refusal neither revokes nor touches the token.
	var lastUsed, revoked *time.Time
	if err := database.QueryRow(ctx, "SELECT last_used_at, revoked_at FROM whitetower.api_tokens WHERE id = $1", created.ID).Scan(&lastUsed, &revoked); err != nil {
		t.Fatal(err)
	}
	if lastUsed != nil || revoked != nil {
		t.Errorf("a token refused by another configuration: last used at %v, revoked at %v; want neither", lastUsed, revoked)
	}
	if token, _, err := before.GetByToken(ctx, created.Token); err != nil || token.LastUsedAt == nil || !token.LastUsedAt.Equal(clk.Now()) {
		t.Errorf("the token with its own configuration, after the refusal: got %v, %v; want it accepted and touched", token, err)
	}

	// A session of a configuration whose console's client is the CLI's
	// records another hash than the CLI's token: each form has its own name.
	session, err := storeWithSignInConfiguration(t, database, clk, configuredWith(func(c *authn.SignInConfiguration) {
		c.ClientID = c.CLIClientID
	})).Create(ctx, created.PrincipalID, "oidc", []string{"owner"})
	if err != nil {
		t.Fatal(err)
	}
	var sessionHash, tokenHash []byte
	if err := database.QueryRow(ctx, "SELECT sign_in_configuration_sha256 FROM whitetower.sessions WHERE id_hash = $1", session.IDHash).Scan(&sessionHash); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(ctx, "SELECT sign_in_configuration_sha256 FROM whitetower.api_tokens WHERE id = $1", created.ID).Scan(&tokenHash); err != nil {
		t.Fatal(err)
	}
	if len(tokenHash) != sha256.Size || bytes.Equal(sessionHash, tokenHash) {
		t.Errorf("the CLI's token records %x, and the session of the same settings %x; want two hashes apart", tokenHash, sessionHash)
	}
}

// Security test ST-19: the tokens that people create, and those of service
// accounts, record no sign-in configuration, whatever their name, so a server
// of any configuration accepts them, OIDC turned off included, while it
// refuses the CLI's tokens of another configuration. A token of the CLI's
// exchange created before tokens recorded a configuration holds the hash of
// none, as migration 00009 writes it, and is refused
func TestOnlyTheCLIsTokensRecordTheSignInConfiguration(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)
	configured := signInConfiguration(func(c *authn.SignInConfiguration) { c.Issuer = idp.server.URL })
	before := tokensWithSignInConfiguration(t, database, clk, configured)
	exchange := exchangeWith(t, idp, clk, principalStore, sessionStore, before, configured)

	cli := exchange(t)
	cleo := auth.Principal{ID: cli.PrincipalID.String(), Kind: auth.Human, Roles: []string{"owner"}}
	scopes := []string{string(authz.PermissionIdentityMeRead)}
	// Named as the exchange names its tokens.
	own, err := before.Create(ctx, cli.PrincipalID, "wtctl", scopes, 1, cleo)
	if err != nil {
		t.Fatal(err)
	}
	bot, err := principalStore.CreateServiceAccount(ctx, "Cleo's deployer", nil, []string{"owner"}, cleo)
	if err != nil {
		t.Fatal(err)
	}
	botToken, err := before.Create(ctx, bot.ID, "deploys", scopes, 30, auth.Principal{ID: bot.ID.String(), Kind: auth.ServiceAccount})
	if err != nil {
		t.Fatal(err)
	}
	var recorded int
	if err := database.QueryRow(ctx, "SELECT count(*) FROM whitetower.api_tokens WHERE id = ANY($1) AND sign_in_configuration_sha256 IS NOT NULL",
		[]uuid.UUID{own.ID, botToken.ID}).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 0 {
		t.Errorf("%d of a person's token and a service account's record a sign-in configuration, want none", recorded)
	}

	for name, c := range map[string]authn.SignInConfiguration{
		"another CLI client ID": signInConfiguration(func(c *authn.SignInConfiguration) { c.Issuer, c.CLIClientID = idp.server.URL, "wtctl-2" }),
		"another issuer":        signInConfiguration(func(*authn.SignInConfiguration) {}),
		"OIDC turned off":       {},
	} {
		store := tokensWithSignInConfiguration(t, database, clk, c)
		for what, token := range map[string]string{"a person's token": own.Token, "a service account's token": botToken.Token} {
			if _, _, err := store.GetByToken(ctx, token); err != nil {
				t.Errorf("%s, with %s: got %v, want it accepted", what, name, err)
			}
		}
		if _, _, err := store.GetByToken(ctx, cli.Token); !errors.Is(err, authn.ErrInvalidToken) {
			t.Errorf("a token of the CLI's exchange, with %s: got %v, want it refused as an invalid token", name, err)
		}
	}

	old := exchange(t)
	if _, err := database.Exec(ctx, `UPDATE whitetower.api_tokens SET sign_in_configuration_sha256 = decode(repeat('00', 32), 'hex') WHERE id = $1`, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := before.GetByToken(ctx, old.Token); !errors.Is(err, authn.ErrInvalidToken) {
		t.Errorf("a token of the CLI's exchange created before tokens recorded a configuration: got %v, want it refused as an invalid token", err)
	}
}
