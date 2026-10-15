package authn_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
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
	principal, err := principalStore.UpsertHuman(ctx, "https://idp.example.com", "sub-alice", "Alice Admin", &email, []string{"admins"})
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
		op, err := principalStore.UpsertHuman(ctx, "https://idp.example.com", "sub-operator", "Op Operator", &opEmail, []string{"operators"})
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
		bob, err := principalStore.UpsertHuman(ctx, "https://idp.example.com", "sub-bob", "Bob Operator", &bobEmail, []string{"operators"})
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
		// 1. Create service account tied to Alice
		saEmail := "pipeline@example.com"
		sa, err := principalStore.CreateServiceAccount(ctx, "CI Pipeline", &saEmail, principal.ID, []string{"auditor"}, principal.ID)
		if err != nil {
			t.Fatalf("creating service account: %v", err)
		}

		if sa.Kind != "service_account" {
			t.Errorf("expected service_account kind, got %s", sa.Kind)
		}
		if sa.ResponsiblePrincipalID == nil || *sa.ResponsiblePrincipalID != principal.ID {
			t.Errorf("expected responsible principal %s, got %v", principal.ID, sa.ResponsiblePrincipalID)
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
		sas, err := principalStore.ListServiceAccounts(ctx, &principal.ID)
		if err != nil {
			t.Fatalf("listing service accounts: %v", err)
		}
		if len(sas) == 0 {
			t.Fatalf("expected at least 1 service account")
		}

		// 5. Service account cannot be created with nonexistent responsible principal
		nonexistentID := uuid.New()
		_, err = principalStore.CreateServiceAccount(ctx, "Bad SA 1", nil, nonexistentID, []string{"auditor"}, principal.ID)
		if !errors.Is(err, authn.ErrPrincipalNotFound) {
			t.Errorf("expected ErrPrincipalNotFound for nonexistent responsible principal, got %v", err)
		}

		// 6. Service account cannot be created with inactive responsible principal
		deactivatedEmail := "inactive-user@example.com"
		inactiveUser, err := principalStore.UpsertHuman(ctx, "https://idp.example.com", "sub-inactive", "Inactive User", &deactivatedEmail, []string{"operators"})
		if err != nil {
			t.Fatalf("upserting inactive user: %v", err)
		}
		if err := principalStore.Deactivate(ctx, inactiveUser.ID, adminActor, "test deactivation"); err != nil {
			t.Fatalf("deactivating user: %v", err)
		}
		_, err = principalStore.CreateServiceAccount(ctx, "Bad SA 2", nil, inactiveUser.ID, []string{"auditor"}, principal.ID)
		if !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Errorf("expected ErrPrincipalInactive for inactive responsible principal, got %v", err)
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
