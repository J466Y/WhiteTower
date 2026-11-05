package authn_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
)

// postLogout sends logout a request with the method given, with the session
// cookie of token when token is not empty, and the CSRF token csrf in its
// header, as the console sends it, when csrf is not empty.
func postLogout(t *testing.T, logout http.Handler, method, token, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/auth/logout", nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: authn.CookieName, Value: token})
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	logout.ServeHTTP(rec, req)
	return rec
}

// redirectOf returns where the answer to a sign-out sends the browser.
func redirectOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var answer struct {
		RedirectURL string `json:"redirect_url"`
	}
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" ||
		json.Unmarshal(rec.Body.Bytes(), &answer) != nil || answer.RedirectURL == "" {
		t.Fatalf("sign-out: got %d %q %q, want 200 with where the browser goes", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	return answer.RedirectURL
}

// clearsTheCookie reports whether an answer deletes the session cookie.
func clearsTheCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == authn.CookieName && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// Security test ST-14: only a POST that carries the CSRF token of the
// session signs a browser out, so that another site cannot: a GET, a POST
// without the token, with another session's token or with a wrong one revoke
// nothing and clear no cookie, and a POST without the session cookie, as a
// cross-site request that SameSite=Lax withholds it from, clears none
func TestOnlyAPostWithTheSessionsCSRFTokenSignsOut(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)
	logout := authn.NewLogoutService(sessionStore, authn.LogoutOptions{Logger: slog.New(slog.DiscardHandler)})
	kim, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-kim", ExternalID: "usr-kim", DisplayName: "Kim Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessionStore.Create(ctx, kim.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	another, err := sessionStore.Create(ctx, kim.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name, method, csrf string
		want               int
	}{
		{"a GET", http.MethodGet, session.CSRFToken, http.StatusMethodNotAllowed},
		{"a HEAD", http.MethodHead, session.CSRFToken, http.StatusMethodNotAllowed},
		{"a DELETE", http.MethodDelete, session.CSRFToken, http.StatusMethodNotAllowed},
		{"a POST without the CSRF token, as another site's form sends it", http.MethodPost, "", http.StatusForbidden},
		{"a POST with another session's CSRF token", http.MethodPost, another.CSRFToken, http.StatusForbidden},
		{"a POST with a wrong CSRF token", http.MethodPost, "not-the-csrf-token", http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := postLogout(t, logout, tt.method, session.Token, tt.csrf)
			if rec.Code != tt.want {
				t.Errorf("got %d %q, want %d", rec.Code, rec.Body.String(), tt.want)
			}
			if tt.want == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
				t.Errorf("Allow %q, want POST", rec.Header().Get("Allow"))
			}
			if cookies := rec.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("the answer sets cookies %v, want none", cookies)
			}
			if _, err := sessionStore.Get(ctx, session.Token); err != nil {
				t.Errorf("the session: %v, want it valid", err)
			}
		})
	}

	rec := postLogout(t, logout, http.MethodPost, "", "")
	if next := redirectOf(t, rec); next != "/" || len(rec.Result().Cookies()) != 0 {
		t.Errorf("a POST without the session cookie: to %q, cookies %v; want the console's root, and no cookie", next, rec.Result().Cookies())
	}
	if _, err := sessionStore.Get(ctx, session.Token); err != nil {
		t.Errorf("the session after a POST without its cookie: %v, want it valid", err)
	}
	if n := len(eventsOf(t, database, sessionRevoked)); n != 0 {
		t.Fatalf("%d sign-outs recorded, want none", n)
	}

	// The console's sign-out.
	rec = postLogout(t, logout, http.MethodPost, session.Token, session.CSRFToken)
	if next := redirectOf(t, rec); next != "/" || !clearsTheCookie(rec) {
		t.Errorf("the sign-out: to %q, cookies %v; want the console's root, and the cookie cleared", next, rec.Result().Cookies())
	}
	if _, err := sessionStore.Get(ctx, session.Token); !errors.Is(err, authn.ErrSessionRevoked) {
		t.Errorf("the session after the sign-out: %v, want it revoked", err)
	}
	if _, err := sessionStore.Get(ctx, another.Token); err != nil {
		t.Errorf("another session of the person: %v, want it valid", err)
	}
	if revoked := eventsOf(t, database, sessionRevoked); len(revoked) != 1 || revoked[0].reason != "signed_out" {
		t.Errorf("sign-outs recorded: %v, want one", revoked)
	}

	// A cookie of no active session names nothing that a forged request
	// could end: it is cleared, and nothing is recorded.
	rec = postLogout(t, logout, http.MethodPost, session.Token, "")
	if next := redirectOf(t, rec); next != "/" || !clearsTheCookie(rec) {
		t.Errorf("a sign-out with a revoked session's cookie: to %q, cookies %v; want the console's root, and the cookie cleared", next, rec.Result().Cookies())
	}
	if n := len(eventsOf(t, database, sessionRevoked)); n != 1 {
		t.Errorf("%d sign-outs recorded, want 1", n)
	}
}

// A sign-out sends the browser on to the identity provider's end session
// page, which ends the person's session there too, but a break-glass
// session's to the console's root: it was never signed in at the provider,
// which may well be down.
func TestABreakglassSignOutStaysAtTheCore(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, _ := setupAuthn(t, clk)
	logout := authn.NewLogoutService(sessionStore, authn.LogoutOptions{
		EndSession: func() string { return "https://idp.example/logout" },
		Logger:     slog.New(slog.DiscardHandler),
	})
	mia, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-mia", ExternalID: "usr-mia", DisplayName: "Mia Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for method, want := range map[string]string{"oidc": "https://idp.example/logout", "breakglass": "/"} {
		session, err := sessionStore.Create(ctx, mia.ID, method, []string{"operator"})
		if err != nil {
			t.Fatal(err)
		}
		if next := redirectOf(t, postLogout(t, logout, http.MethodPost, session.Token, session.CSRFToken)); next != want {
			t.Errorf("the sign-out of a %s session: to %q, want %q", method, next, want)
		}
	}
}

// A sign-out that cannot read the session, as when the database does not
// answer, changes nothing and clears no cookie: without the session, the CSRF
// token cannot be checked.
func TestASignOutThatCannotReadTheSessionChangesNothing(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)
	lee, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-lee", ExternalID: "usr-lee", DisplayName: "Lee Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessionStore.Create(ctx, lee.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	database.Close()

	rec := postLogout(t, authn.NewLogoutService(sessionStore, authn.LogoutOptions{Logger: slog.New(slog.DiscardHandler)}),
		http.MethodPost, session.Token, session.CSRFToken)
	if rec.Code != http.StatusInternalServerError || len(rec.Result().Cookies()) != 0 {
		t.Errorf("got %d, cookies %v; want 500 and no cookie", rec.Code, rec.Result().Cookies())
	}
}
