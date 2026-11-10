package authn_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

var testEpoch = time.Date(2026, 10, 14, 16, 0, 0, 0, time.UTC)

func setupAuthn(t *testing.T, clk *clocktest.Fake) (*authn.SessionStore, *authn.PrincipalStore, *authn.TokenStore, *db.DB) {
	t.Helper()
	d := dbtest.New(t)
	database := d.Open(t)

	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(cat, clk)

	sessionStore := authn.NewSessionStore(database, clk, writer, authn.SessionOptions{
		IdleTimeout:      30 * time.Minute,
		AbsoluteLifetime: 12 * time.Hour,
	})
	tokenStore := authn.NewTokenStore(database, clk, writer, authz.NewAuthorizer())
	principalStore := authn.NewPrincipalStore(database, clk, writer, sessionStore, tokenStore)
	return sessionStore, principalStore, tokenStore, database
}

// Security test ST-14: only the session cookie with the __Host- prefix signs a
// request in, so that a session cookie that another host of the domain or a
// plain HTTP page planted signs nobody in as whoever planted it (ADR-0009)
func TestOnlyThePrefixedSessionCookieSignsIn(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, _ := setupAuthn(t, clk)
	authenticator := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, nil)

	victim, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-victim", ExternalID: "sub-victim", DisplayName: "Vera Victim"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-attacker", ExternalID: "sub-attacker", DisplayName: "Mallory Planter"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	planted, err := sessionStore.Create(ctx, attacker.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	own, err := sessionStore.Create(ctx, victim.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name, cookies string
		want          string // the principal signed in; empty: nobody
	}{
		{"the unprefixed cookie alone", "wt_session=" + planted.Token, ""},
		{"the unprefixed cookie before the prefixed one", "wt_session=" + planted.Token + "; __Host-wt_session=" + own.Token, victim.ID.String()},
		{"the prefixed cookie", "__Host-wt_session=" + own.Token, victim.ID.String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			req.Header.Set("Cookie", tt.cookies)
			p, err := authenticator.Authenticate(req)
			if err != nil {
				t.Fatalf("authenticating: %v", err)
			}
			got := ""
			if p != nil {
				got = p.ID
			}
			if got != tt.want {
				t.Errorf("signed in as %q, want %q", got, tt.want)
			}
		})
	}
}

// Security test ST-14: cookie flags are set; idle and absolute expiry apply; sessions are revoked at logout and on deactivation
func TestSessionLifecycleAndSecurity(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, _ := setupAuthn(t, clk)

	email := "alice@example.com"
	principal, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-12345", ExternalID: "sub-12345", DisplayName: "Alice Operator", Email: &email, Groups: []string{"operators"}}, nil)
	if err != nil {
		t.Fatalf("upserting principal: %v", err)
	}

	t.Run("cookie flags are set properly", func(t *testing.T) {
		session, err := sessionStore.Create(ctx, principal.ID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		cookie := sessionStore.Cookie(session.Token)
		if cookie.Name != "__Host-wt_session" {
			t.Errorf("expected cookie name __Host-wt_session, got %s", cookie.Name)
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

		clear := sessionStore.ClearCookie()
		if clear.Name != "__Host-wt_session" || !clear.Secure || clear.MaxAge != -1 {
			t.Errorf("expected a Secure __Host-wt_session clear cookie with MaxAge=-1, got %+v", clear)
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

// storeWithSignInConfiguration returns a session store of database whose
// sessions the sign-in configuration c creates: a replica, or a server after
// a restart, that runs those settings of auth.oidc.
func storeWithSignInConfiguration(t *testing.T, database *db.DB, clk *clocktest.Fake, c authn.SignInConfiguration) *authn.SessionStore {
	t.Helper()
	return authn.NewSessionStore(database, clk, audit.NewWriter(mustCatalog(t), clk), authn.SessionOptions{
		IdleTimeout:         30 * time.Minute,
		AbsoluteLifetime:    12 * time.Hour,
		SignInConfiguration: c,
	})
}

// signInConfiguration is a sign-in configuration as an operator writes it,
// with a change: the configuration of a server after a change of its
// settings and a restart, or of another replica. Its lists and its mapping
// are the configuration's own, so that change may edit them.
func signInConfiguration(change func(c *authn.SignInConfiguration)) authn.SignInConfiguration {
	c := authn.SignInConfiguration{
		Issuer:            "https://idp.example.com/realms/whitetower",
		ClientID:          "whitetower-console",
		AllowedAlgorithms: []string{"RS256", "ES256"},
		ExternalIDClaim:   "sub",
		GroupsClaim:       "groups",
		RoleMapping:       map[string]string{"wt-owners": "owner", "wt-admins": "admin"},
	}
	change(&c)
	return c
}

// Security test ST-14: a session keeps the roles of its sign-in, so a server
// whose sign-in configuration is not the one that created the session, after
// a change of one of its settings and a restart or on another replica,
// refuses the session as an expired one, and the other way round: a change of
// which ID tokens the server accepts, of which person a sign-in is, or of
// what roles it gives. Two configurations that differ only in what carries no
// meaning are one. The refusal changes nothing of the session: the server of
// its configuration still accepts it, and a sign-out of the other one clears
// its cookie and revokes nothing, as for an expired session
func TestASessionOfAnotherSignInConfigurationIsRefusedAsAnExpiredOne(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	_, principalStore, _, database := setupAuthn(t, clk)
	nia, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-nia", ExternalID: "usr-nia", DisplayName: "Nia Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	configured := signInConfiguration(func(*authn.SignInConfiguration) {})
	for _, tt := range []struct {
		name          string
		before, after authn.SignInConfiguration
		want          error // nil: the session is accepted
	}{
		// What carries no meaning.
		{"the same configuration", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.RoleMapping = map[string]string{"wt-admins": "admin", "wt-owners": "owner"}
		}), nil},
		{"the algorithms in another order", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = []string{"ES256", "RS256"}
		}), nil},
		{"an algorithm listed twice", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = []string{"RS256", "ES256", "RS256"}
		}), nil},
		{"no algorithms and no mapping, then empty ones", signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms, c.RoleMapping = nil, nil
		}), signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms, c.RoleMapping = []string{}, map[string]string{}
		}), nil},

		// Which ID tokens the server accepts.
		{"another issuer", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.Issuer = "https://idp.example.net/realms/whitetower"
		}), authn.ErrSessionExpired},
		{"the issuer with a trailing slash", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.Issuer += "/"
		}), authn.ErrSessionExpired},
		{"OIDC turned off", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.Issuer = ""
		}), authn.ErrSessionExpired},
		{"another client ID", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.ClientID = "whitetower-console-2"
		}), authn.ErrSessionExpired},
		{"an algorithm added", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = append(c.AllowedAlgorithms, "PS256")
		}), authn.ErrSessionExpired},
		{"an algorithm removed", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = []string{"ES256"}
		}), authn.ErrSessionExpired},
		{"no algorithms, for the OIDC service's defaults", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = nil
		}), authn.ErrSessionExpired},

		// Which person a sign-in is.
		{"another external ID claim", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.ExternalIDClaim = "oid"
		}), authn.ErrSessionExpired},
		{"no external ID claim, for the OIDC service's default", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.ExternalIDClaim = ""
		}), authn.ErrSessionExpired},

		// What roles it gives.
		{"another groups claim", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.GroupsClaim = "roles"
		}), authn.ErrSessionExpired},
		{"a role changed", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.RoleMapping["wt-owners"] = "user"
		}), authn.ErrSessionExpired},
		{"a group added", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.RoleMapping["wt-users"] = "user"
		}), authn.ErrSessionExpired},
		{"a group removed", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			delete(c.RoleMapping, "wt-admins")
		}), authn.ErrSessionExpired},
		{"a group with a leading slash", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.RoleMapping = map[string]string{"wt-owners": "owner", "/wt-admins": "admin"}
		}), authn.ErrSessionExpired},

		// Strings that a separator would join alike.
		{"a group and its role cut elsewhere", signInConfiguration(func(c *authn.SignInConfiguration) {
			c.RoleMapping = map[string]string{"wt-owners": "owner"}
		}), signInConfiguration(func(c *authn.SignInConfiguration) {
			c.RoleMapping = map[string]string{"wt-owner": "sowner"}
		}), authn.ErrSessionExpired},
		{"the issuer and the client ID cut elsewhere", configured, signInConfiguration(func(c *authn.SignInConfiguration) {
			c.Issuer, c.ClientID = c.Issuer+"w", "hitetower-console"
		}), authn.ErrSessionExpired},
		{"strings moved from one setting to the next", signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = []string{"ES256", "PS256", "RS256"}
			c.ExternalIDClaim, c.GroupsClaim = "oid", "roles"
			c.RoleMapping = map[string]string{"wt-owners": "owner"}
		}), signInConfiguration(func(c *authn.SignInConfiguration) {
			c.AllowedAlgorithms = []string{"ES256"}
			c.ExternalIDClaim, c.GroupsClaim = "PS256", "RS256"
			c.RoleMapping = map[string]string{"oid": "roles", "wt-owners": "owner"}
		}), authn.ErrSessionExpired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := storeWithSignInConfiguration(t, database, clk, tt.before)
			after := storeWithSignInConfiguration(t, database, clk, tt.after)
			// Every session that the configuration creates, whatever its
			// method, break-glass aside.
			for _, method := range []string{"oidc", "cli"} {
				for _, stores := range []struct {
					name     string
					from, to *authn.SessionStore
				}{{"after", before, after}, {"before", after, before}} {
					session, err := stores.from.Create(ctx, nia.ID, method, []string{"owner"})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := stores.to.Get(ctx, session.Token); !errors.Is(err, tt.want) {
						t.Errorf("a session of method %s, with the configuration %s: got %v, want %v", method, stores.name, err, tt.want)
					}
					if _, err := stores.from.Get(ctx, session.Token); err != nil {
						t.Errorf("a session of method %s, with its own configuration: got %v, want it accepted", method, err)
					}
				}
			}
		})
	}

	before := storeWithSignInConfiguration(t, database, clk, configured)
	after := storeWithSignInConfiguration(t, database, clk, signInConfiguration(func(c *authn.SignInConfiguration) {
		c.ExternalIDClaim = "oid"
	}))
	session, err := before.Create(ctx, nia.ID, "oidc", []string{"owner"})
	if err != nil {
		t.Fatal(err)
	}

	// The authenticator refuses it as an expired session, which the API
	// answers as any credential that it does not accept.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: authn.CookieName, Value: session.Token})
	if p, err := authn.NewAuthenticator(after, principalStore, nil, nil).Authenticate(req); p != nil || !errors.Is(err, authn.ErrSessionExpired) {
		t.Errorf("authenticating with a session of another configuration: got %v, %v; want it refused as expired", p, err)
	}

	// A refusal does not slide the idle expiry.
	clk.Advance(20 * time.Minute)
	if _, err := after.Get(ctx, session.Token); !errors.Is(err, authn.ErrSessionExpired) {
		t.Fatalf("a session of another configuration: got %v, want it refused", err)
	}
	clk.Advance(15 * time.Minute)
	if _, err := before.Get(ctx, session.Token); !errors.Is(err, authn.ErrSessionExpired) {
		t.Errorf("a session idle for 35 minutes, refused by another configuration after 20: got %v, want it expired", err)
	}

	// A sign-out of the other configuration clears the cookie without the
	// CSRF token, as that of a session it does not accept, and revokes
	// nothing.
	session, err = before.Create(ctx, nia.ID, "oidc", []string{"owner"})
	if err != nil {
		t.Fatal(err)
	}
	recorded := len(eventsOf(t, database, sessionRevoked))
	rec := postLogout(t, authn.NewLogoutService(after, authn.LogoutOptions{Logger: slog.New(slog.DiscardHandler)}), http.MethodPost, session.Token, "")
	if next := redirectOf(t, rec); next != "/" || !clearsTheCookie(rec) {
		t.Errorf("a sign-out with a session of another configuration: to %q, cookies %v; want the console's root, and the cookie cleared", next, rec.Result().Cookies())
	}
	if n := len(eventsOf(t, database, sessionRevoked)) - recorded; n != 0 {
		t.Errorf("%d sign-outs recorded, want none", n)
	}
	if _, err := before.Get(ctx, session.Token); err != nil {
		t.Errorf("the session after a sign-out of another configuration: got %v, want it accepted by its own", err)
	}
}

// Security test ST-14: a break-glass session, which no sign-in configuration
// creates, is accepted whatever the configuration, OIDC turned off included,
// where it is the only kind of session; a session that recorded no
// configuration, created before sessions recorded one, is refused as one of
// another configuration
func TestBreakglassSessionsAreExemptAndSessionsWithoutAConfigurationAreRefused(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	_, principalStore, _, database := setupAuthn(t, clk)
	omar, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-omar", ExternalID: "usr-omar", DisplayName: "Omar Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := storeWithSignInConfiguration(t, database, clk, signInConfiguration(func(*authn.SignInConfiguration) {}))

	breakglass, err := before.Create(ctx, omar.ID, "breakglass", []string{"operator"})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]authn.SignInConfiguration{
		"another issuer": signInConfiguration(func(c *authn.SignInConfiguration) { c.Issuer = "https://idp.example.net/realms/whitetower" }),
		"another role mapping": signInConfiguration(func(c *authn.SignInConfiguration) {
			c.RoleMapping = map[string]string{"wt-owners": "user"}
		}),
		"OIDC turned off": {},
	} {
		if _, err := storeWithSignInConfiguration(t, database, clk, c).Get(ctx, breakglass.Token); err != nil {
			t.Errorf("a break-glass session, with %s: got %v, want it accepted", name, err)
		}
	}

	for _, method := range []string{"oidc", "cli"} {
		session, err := before.Create(ctx, omar.ID, method, []string{"operator"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(ctx, `UPDATE whitetower.sessions SET sign_in_configuration_sha256 = NULL WHERE id_hash = $1`, session.IDHash); err != nil {
			t.Fatal(err)
		}
		if _, err := before.Get(ctx, session.Token); !errors.Is(err, authn.ErrSessionExpired) {
			t.Errorf("a session of method %s without a configuration: got %v, want it refused as expired", method, err)
		}
	}
}
