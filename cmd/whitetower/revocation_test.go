package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

// Security test ST-89: through the server's wiring, an emergency revocation
// on one replica ends, on every replica, every session and API token: an
// administrator's session, another break-glass session, the CLI's token, a
// service account's token and the administrator's own token; the break-glass
// session that runs it stays, also on a replica without OIDC. No token holds
// its permission, neither the CLI's nor one that the administrator creates,
// and a token is refused it whatever its scopes, as is a request without the
// session's CSRF token or without a reason. An administrator who runs it ends
// their own session, and the answer clears its cookie. Each run logs the alert
func TestAnEmergencyRevocationEndsEverySessionAndTokenOnEveryReplica(t *testing.T) {
	credential, hash, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatal(err)
	}
	hashFile := filepath.Join(t.TempDir(), "breakglass-hash")
	writeSecret(t, hashFile, hash+"\n")
	breakglass := []string{"WT_AUTH_BREAKGLASS_ENABLED=true", "WT_AUTH_BREAKGLASS_CREDENTIAL_HASH_FILE=" + hashFile}
	d := dbtest.New(t)
	idp := newSigningProvider(t)
	idp.up.Store(true)
	// The person who signs in is in wt-owners, whom this mapping makes
	// administrators.
	withOIDC := startServeOn(t, d, append(append(oidcEnv(t, idp.URL, writeStateKey(t)), breakglass...), "WT_AUTH_OIDC_ROLE_MAPPING=wt-owners=admin")...)
	withoutOIDC := startServeOn(t, d, breakglass...)
	withOIDC.waitForDiscovery(t)

	jsonBody := http.Header{"Content-Type": {"application/json"}}
	// session holds the headers of a session's reads, and of its changes,
	// which carry its CSRF token.
	type session struct{ read, change http.Header }
	sessionOf := func(s *serving, cookie string) session {
		t.Helper()
		_, me := get(t, s.console+"/api/v1/me", http.Header{"Cookie": {cookie}})
		var p struct {
			CSRFToken string `json:"csrfToken"`
		}
		if err := json.Unmarshal([]byte(me), &p); err != nil || p.CSRFToken == "" {
			t.Fatalf("/me: %s, want the session's CSRF token", me)
		}
		return session{
			read:   http.Header{"Cookie": {cookie}},
			change: http.Header{"Cookie": {cookie}, "X-Csrf-Token": {p.CSRFToken}, "Content-Type": {"application/json"}},
		}
	}
	administrator := func() session {
		t.Helper()
		status, cookie := finishSignIn(t, withOIDC.console, startSignIn(t, withOIDC.console))
		if status != http.StatusFound || cookie == "" {
			t.Fatalf("a sign-in: %d, session cookie %q", status, cookie)
		}
		return sessionOf(withOIDC, cookie)
	}
	custodian := func(s *serving) session {
		t.Helper()
		header, _ := call(t, http.StatusOK, http.MethodPost, s.console+"/auth/breakglass", `{"credential":"`+credential+`"}`, jsonBody)
		for _, c := range (&http.Response{Header: header}).Cookies() {
			if c.Name == authn.CookieName {
				return sessionOf(s, c.Name+"="+c.Value)
			}
		}
		t.Fatal("break-glass set no session cookie")
		return session{}
	}
	bearer := func(body string) http.Header {
		t.Helper()
		var created struct{ Token string }
		if err := json.Unmarshal([]byte(body), &created); err != nil || created.Token == "" {
			t.Fatalf("a created token: %v: %s", err, body)
		}
		return http.Header{"Authorization": {"Bearer " + created.Token}, "Content-Type": {"application/json"}}
	}
	revoke := func(want int, s *serving, header http.Header, body string) (http.Header, string) {
		t.Helper()
		return call(t, want, http.MethodPost, s.console+"/api/v1/emergency-revocation", body, header)
	}
	ended := func(body string, sessions, tokens int64) {
		t.Helper()
		var r struct{ Sessions, Tokens int64 }
		if err := json.Unmarshal([]byte(body), &r); err != nil || r.Sessions != sessions || r.Tokens != tokens {
			t.Errorf("the revocation answered %s, want %d sessions and %d tokens ended", body, sessions, tokens)
		}
	}

	admin := administrator()
	_, exchanged := call(t, http.StatusOK, http.MethodPost, withOIDC.console+"/api/v1/tokens/exchange", `{"idToken":"`+idp.sign(t, map[string]any{
		"iss": idp.URL, "aud": "wtctl", "sub": "usr-signs-in", "name": "Sam Signs-In", "groups": []string{"wt-owners"},
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})+`"}`, jsonBody)
	cliToken := bearer(exchanged)
	if strings.Contains(exchanged, "identity.emergency.revoke") {
		t.Errorf("the CLI's token of an administrator holds the emergency revocation: %s", exchanged)
	}
	_, account := call(t, http.StatusCreated, http.MethodPost, withOIDC.console+"/api/v1/service-accounts", `{"displayName":"Sync bot","roles":["admin"]}`, admin.change)
	var bot struct{ ID string }
	if err := json.Unmarshal([]byte(account), &bot); err != nil {
		t.Fatal(err)
	}
	_, created := call(t, http.StatusCreated, http.MethodPost, withOIDC.console+"/api/v1/tokens",
		`{"name":"bot key","scopes":["identity.me.read"],"principalId":"`+bot.ID+`"}`, admin.change)
	botsToken := bearer(created)
	// No token holds the emergency revocation's permission; the
	// administrator's own token holds every other permission they hold.
	if _, refused := call(t, http.StatusBadRequest, http.MethodPost, withOIDC.console+"/api/v1/tokens",
		`{"name":"revoker","scopes":["identity.emergency.revoke"]}`, admin.change); !strings.Contains(refused, `invalid scope \"identity.emergency.revoke\"`) {
		t.Errorf("a token with the emergency revocation's permission: %s", refused)
	}
	_, created = call(t, http.StatusCreated, http.MethodPost, withOIDC.console+"/api/v1/tokens",
		`{"name":"everything","scopes":["identity.me.read","identity.tokens.manage","inventory.view","settings.manage"]}`, admin.change)
	adminsToken := bearer(created)
	running, other := custodian(withoutOIDC), custodian(withOIDC)

	reason := `{"reason":"INC-2041: the identity provider was compromised"}`
	for _, token := range []http.Header{adminsToken, cliToken} {
		revoke(http.StatusForbidden, withOIDC, token, reason)
	}
	revoke(http.StatusForbidden, withoutOIDC, http.Header{"Cookie": running.read["Cookie"], "Content-Type": {"application/json"}}, reason)
	for _, body := range []string{`{}`, `{"reason":" "}`, `{"reason":"` + strings.Repeat("a", authn.MaxRevocationReason+1) + `"}`} {
		revoke(http.StatusBadRequest, withoutOIDC, running.change, body)
	}
	get(t, withOIDC.console+"/api/v1/me", admin.read)

	header, body := revoke(http.StatusOK, withoutOIDC, running.change, reason)
	ended(body, 2, 3)
	if c := header.Get("Set-Cookie"); c != "" {
		t.Errorf("the custodian's revocation sets the cookie %q, want none", c)
	}
	for _, s := range []*serving{withOIDC, withoutOIDC} {
		for name, credential := range map[string]http.Header{
			"the administrator's session": admin.read, "another break-glass session": other.read,
			"the CLI's token": cliToken, "a service account's token": botsToken, "the administrator's own token": adminsToken,
		} {
			if _, refused := call(t, http.StatusUnauthorized, http.MethodGet, s.console+"/api/v1/me", "", credential); !strings.Contains(refused, `"code":"unauthenticated"`) {
				t.Errorf("%s after the revocation: %s", name, refused)
			}
		}
		get(t, s.console+"/api/v1/me", running.read)
	}
	_, body = revoke(http.StatusOK, withOIDC, running.change, reason)
	ended(body, 0, 0)

	again := administrator()
	header, body = revoke(http.StatusOK, withOIDC, again.change, `{"reason":"INC-2042"}`)
	ended(body, 2, 0)
	if c := header.Get("Set-Cookie"); !strings.HasPrefix(c, authn.CookieName+"=;") || !strings.Contains(c, "Max-Age=0") {
		t.Errorf("the administrator's revocation sets the cookie %q, want it cleared", c)
	}
	for _, s := range []session{again, running} {
		call(t, http.StatusUnauthorized, http.MethodGet, withOIDC.console+"/api/v1/me", "", s.read)
	}
	const alert = "SECURITY ALERT: emergency revocation ended every session and API token"
	if n, m := len(withoutOIDC.logs.records(t, alert)), len(withOIDC.logs.records(t, alert)); n != 1 || m != 2 {
		t.Errorf("%d and %d alerts logged, want 1 and 2", n, m)
	}
}
