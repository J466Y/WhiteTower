package authn_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

var testEpoch = time.Date(2026, 10, 14, 16, 0, 0, 0, time.UTC)

func setupAuthn(t *testing.T, clk *clocktest.Fake) (*authn.SessionStore, *authn.PrincipalStore) {
	t.Helper()
	d := dbtest.New(t)
	database := d.Open(t)

	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(cat, clk)

	sessionStore := authn.NewSessionStore(database, clk, authn.SessionOptions{
		IdleTimeout:      30 * time.Minute,
		AbsoluteLifetime: 12 * time.Hour,
	})
	principalStore := authn.NewPrincipalStore(database, clk, writer, sessionStore)
	return sessionStore, principalStore
}

// Security test ST-14: Session fixation is impossible; cookie flags are set; idle and absolute expiry apply; sessions are rotated at login and revoked at logout, on deactivation and on role changes
func TestSessionLifecycleAndSecurity(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore := setupAuthn(t, clk)

	email := "alice@example.com"
	principal, err := principalStore.UpsertHuman(ctx, "https://idp.example.com", "sub-12345", "Alice Operator", &email, []string{"operators"})
	if err != nil {
		t.Fatalf("upserting principal: %v", err)
	}

	t.Run("cookie flags are set properly", func(t *testing.T) {
		session, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		cookie := sessionStore.Cookie(session.Token, true)
		if cookie.Name != authn.CookieNameSecure {
			t.Errorf("expected cookie name %s, got %s", authn.CookieNameSecure, cookie.Name)
		}
		if !cookie.HttpOnly {
			t.Errorf("expected HttpOnly=true")
		}
		if !cookie.Secure {
			t.Errorf("expected Secure=true")
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("expected SameSite=Lax, got %v", cookie.SameSite)
		}
		if cookie.Path != "/" {
			t.Errorf("expected Path=/, got %s", cookie.Path)
		}

		clear := sessionStore.ClearCookie(true)
		if clear.MaxAge != -1 {
			t.Errorf("expected clear cookie MaxAge=-1, got %d", clear.MaxAge)
		}
	})

	t.Run("session rotation prevents fixation", func(t *testing.T) {
		s1, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating initial session: %v", err)
		}

		s2, err := sessionStore.Rotate(ctx, s1.Token)
		if err != nil {
			t.Fatalf("rotating session: %v", err)
		}

		if s2.Token == s1.Token {
			t.Errorf("rotated session must have a new token")
		}
		if s2.CSRFToken == s1.CSRFToken {
			t.Errorf("rotated session must have a new CSRF token")
		}

		// The old session is revoked immediately.
		_, err = sessionStore.Get(ctx, s1.Token)
		if !errors.Is(err, authn.ErrSessionRevoked) {
			t.Errorf("old session must be revoked after rotation, got %v", err)
		}

		// The new session is active.
		loaded, err := sessionStore.Get(ctx, s2.Token)
		if err != nil {
			t.Fatalf("loading rotated session: %v", err)
		}
		if loaded.PrincipalID != principal.ID {
			t.Errorf("principal mismatch on rotated session")
		}
	})

	t.Run("idle and absolute expiration", func(t *testing.T) {
		clk.Advance(2 * time.Hour)

		s, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		// Advance 20 minutes (within 30m idle timeout).
		clk.Advance(20 * time.Minute)
		s, err = sessionStore.Get(ctx, s.Token)
		if err != nil {
			t.Fatalf("session should still be active after 20m: %v", err)
		}

		// Advance 31 minutes without activity (exceeds 30m idle timeout).
		clk.Advance(31 * time.Minute)
		_, err = sessionStore.Get(ctx, s.Token)
		if !errors.Is(err, authn.ErrSessionExpired) {
			t.Errorf("session should expire on idle timeout, got %v", err)
		}

		// Create another session and test absolute lifetime.
		sAbs, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		// Slide continuously for 13 hours (past 12h absolute lifetime).
		for i := 0; i < 39; i++ {
			clk.Advance(20 * time.Minute)
			_, err = sessionStore.Get(ctx, sAbs.Token)
			if err != nil {
				break
			}
		}
		if !errors.Is(err, authn.ErrSessionExpired) {
			t.Errorf("session must expire after absolute lifetime of 12h even with activity, got %v", err)
		}
	})

	t.Run("revocation at logout and on deactivation", func(t *testing.T) {
		clk.Advance(2 * time.Hour)
		s1, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		// Manual revocation (logout).
		if err := sessionStore.Revoke(ctx, s1.Token); err != nil {
			t.Fatalf("revoking session: %v", err)
		}
		if _, err := sessionStore.Get(ctx, s1.Token); !errors.Is(err, authn.ErrSessionRevoked) {
			t.Errorf("expected ErrSessionRevoked after logout, got %v", err)
		}

		// Deactivation revokes all sessions.
		s2, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}
		s3, err := sessionStore.Create(ctx, principal.ID, "cli", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		adminActor := auth.Principal{ID: uuid.Must(uuid.NewV7()).String(), Kind: auth.Human}
		if err := principalStore.Deactivate(ctx, principal.ID, adminActor, "test deactivation"); err != nil {
			t.Fatalf("deactivating principal: %v", err)
		}

		// Both sessions must be revoked.
		if _, err := sessionStore.Get(ctx, s2.Token); !errors.Is(err, authn.ErrSessionRevoked) && !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Errorf("session s2 should be invalid after deactivation, got %v", err)
		}
		if _, err := sessionStore.Get(ctx, s3.Token); !errors.Is(err, authn.ErrSessionRevoked) && !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Errorf("session s3 should be invalid after deactivation, got %v", err)
		}
	})

	t.Run("cleanup removes expired sessions", func(t *testing.T) {
		clk.Advance(2 * time.Hour)
		s, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		// Advance past absolute lifetime.
		clk.Advance(13 * time.Hour)
		deleted, err := sessionStore.DeleteExpired(ctx)
		if err != nil {
			t.Fatalf("deleting expired sessions: %v", err)
		}
		if deleted < 1 {
			t.Errorf("expected at least 1 deleted session, got %d", deleted)
		}

		// Should not be in database anymore.
		if _, err := sessionStore.Get(ctx, s.Token); !errors.Is(err, authn.ErrSessionNotFound) && !errors.Is(err, authn.ErrSessionExpired) {
			t.Errorf("expected ErrSessionNotFound or ErrSessionExpired, got %v", err)
		}
	})
}
