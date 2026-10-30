package authn_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

type mockIDP struct {
	server       *httptest.Server
	privKey      *rsa.PrivateKey
	keyID        string
	customToken  string
	tokenHandler func(w http.ResponseWriter, r *http.Request)
	// discovery replaces the discovery document, which otherwise names the
	// mock itself; set it before the first request.
	discovery map[string]any
	// hangUp is a path at which the mock closes the connection without an
	// answer, as a provider that went away does; set it before the first
	// request.
	hangUp string
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key for mock IdP: %v", err)
	}
	keyID := "mock-idp-key-1"

	m := &mockIDP{
		privKey: privKey,
		keyID:   keyID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		document := m.discovery
		if document == nil {
			document = map[string]any{
				"issuer":                                m.server.URL,
				"authorization_endpoint":                m.server.URL + "/auth",
				"token_endpoint":                        m.server.URL + "/token",
				"jwks_uri":                              m.server.URL + "/jwks",
				"end_session_endpoint":                  m.server.URL + "/logout",
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(document)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pubKey := &privKey.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": keyID,
					"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
				},
			},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if m.tokenHandler != nil {
			m.tokenHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     m.customToken,
		})
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
		if redirectURI != "" {
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.hangUp != "" && r.URL.Path == m.hangUp {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(m.server.Close)
	return m
}

// frontIssuer is the issuer of a provider that the server reaches through a
// back channel, the mock: only browsers would reach the issuer, so the tests
// never call it.
const frontIssuer = "https://idp.example.test/realms/whitetower"

// backChannelDocument returns the discovery document that the mock serves as
// the back channel of the issuer, as Keycloak does with a fixed hostname and a
// dynamic back channel: the issuer and the endpoints that browsers use are
// the issuer's, and the endpoints that the server calls are the mock's.
func (m *mockIDP) backChannelDocument(issuer string) map[string]any {
	return map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/protocol/openid-connect/auth",
		"end_session_endpoint":                  issuer + "/protocol/openid-connect/logout",
		"token_endpoint":                        m.server.URL + "/token",
		"jwks_uri":                              m.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
}

func (m *mockIDP) signIDToken(header map[string]any, payload map[string]any) string {
	if header["alg"] == nil {
		header["alg"] = "RS256"
	}
	if header["kid"] == nil {
		header["kid"] = m.keyID
	}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	part1 := base64.RawURLEncoding.EncodeToString(headerJSON)
	part2 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := part1 + "." + part2

	if header["alg"] == "none" {
		return signingInput + "."
	}

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.privKey, crypto.SHA256, h[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// initiateLogin performs the login step: it returns the state cookie, and the
// state and nonce of the authorization request.
func initiateLogin(t *testing.T, svc *authn.OIDCService, returnURL string) (*http.Cookie, string, string) {
	t.Helper()
	reqURL := "/auth/login"
	if returnURL != "" {
		reqURL += "?return_url=" + url.QueryEscape(returnURL)
	}
	loginReq := httptest.NewRequest(http.MethodGet, reqURL, nil)
	loginRec := httptest.NewRecorder()
	svc.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found from /auth/login, got %d: %s", loginRec.Code, loginRec.Body.String())
	}

	cookies := loginRec.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "__Host-wt_oidc" || c.Name == "wt_oidc" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatalf("missing state cookie in login response")
	}

	location := loginRec.Header().Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parsing redirect Location: %v", err)
	}
	stateParam := locURL.Query().Get("state")
	nonceParam := locURL.Query().Get("nonce")
	return stateCookie, stateParam, nonceParam
}

// checkEndSessionRedirect checks that a logout sends the browser to the
// provider's end session endpoint with the client's ID, which Keycloak needs
// to accept a post-logout redirect without an ID token, and with the console's
// root on the redirect URL's origin as the page to come back to.
func checkEndSessionRedirect(t *testing.T, location, endSession, clientID string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parsing the logout's Location %q: %v", location, err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != endSession {
		t.Errorf("logout redirects to %s, want the end session endpoint %s", got, endSession)
	}
	want := url.Values{"client_id": {clientID}, "post_logout_redirect_uri": {"https://127.0.0.1:8443/"}}
	if got := u.Query(); got.Encode() != want.Encode() {
		t.Errorf("logout parameters %v, want %v", got, want)
	}
}

// Security test ST-15: Return URLs outside the console's own paths are refused
func TestReturnURLValidation(t *testing.T) {
	validCases := []string{
		"/",
		"/dashboard",
		"/agents/0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59",
		"/settings?tab=roles",
		"/audit#event-123",
	}

	for _, tc := range validCases {
		t.Run("valid:"+tc, func(t *testing.T) {
			got, err := authn.ValidateReturnURL(tc)
			if err != nil {
				t.Errorf("expected %q to be valid, got err %v", tc, err)
			}
			if got != tc {
				t.Errorf("got %q, want %q", got, tc)
			}
		})
	}

	refusedCases := []string{
		"http://evil.com",
		"https://evil.com/login",
		"//evil.com",
		"//evil.com/path",
		"/\\evil.com",
		"javascript:alert(1)",
		"data:text/html,evil",
		"\\evil.com",
		"relative/without/slash",
		"/path\r\nInjected: Header",
		"/path with space",
	}

	for _, tc := range refusedCases {
		t.Run("refused:"+tc, func(t *testing.T) {
			_, err := authn.ValidateReturnURL(tc)
			if err == nil {
				t.Errorf("expected return URL %q to be refused", tc)
			}
		})
	}
}

// Security test ST-22: Login attempts are rate-limited
func TestLoginRateLimiting(t *testing.T) {
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)

	// Rate limiter with capacity for 2 requests
	limiter := ratelimit.New(1, 2)

	svc, err := authn.NewOIDCService(context.Background(), authn.OIDCOptions{
		Issuer:       idp.server.URL,
		ClientID:     "whitetower-client",
		ClientSecret: "secret",
		RedirectURL:  "https://127.0.0.1:8443/auth/callback",
		Clock:        clk,
		Limiter:      limiter,
		HTTPClient:   idp.server.Client(),
	}, database, principalStore, sessionStore)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = "192.0.2.1:12345"

	// 1st request succeeds
	rec1 := httptest.NewRecorder()
	svc.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusFound {
		t.Errorf("request 1 expected 302 Found, got %d", rec1.Code)
	}

	// 2nd request succeeds (burst capacity 2)
	rec2 := httptest.NewRecorder()
	svc.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusFound {
		t.Errorf("request 2 expected 302 Found, got %d", rec2.Code)
	}

	// 3rd request refused by rate limiter (ST-22)
	rec3 := httptest.NewRecorder()
	svc.ServeHTTP(rec3, req)
	if rec3.Code != http.StatusTooManyRequests {
		t.Errorf("request 3 expected 429 Too Many Requests, got %d", rec3.Code)
	}
	if rec3.Header().Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}

	// After advancing time, new login request is permitted
	clk.Advance(2 * time.Second)
	rec4 := httptest.NewRecorder()
	svc.ServeHTTP(rec4, req)
	if rec4.Code != http.StatusFound {
		t.Errorf("request 4 after timeout expected 302 Found, got %d", rec4.Code)
	}
}

// Security test ST-16: ID tokens with a wrong issuer or audience, an expired one,
// a replayed nonce or an unexpected algorithm are refused
func TestIDTokenValidationAndSecurity(t *testing.T) {
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)

	const clientID = "whitetower-console"

	roleMapping := map[string]string{
		"wt-owners":    "owner",
		"wt-operators": "operator",
	}

	svc, err := authn.NewOIDCService(context.Background(), authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          clientID,
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		RoleMapping:       roleMapping,
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        idp.server.Client(),
	}, database, principalStore, sessionStore)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}

	t.Run("successful login provisions principal and session", func(t *testing.T) {
		stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/dashboard")

		now := clk.Now()
		token := idp.signIDToken(
			map[string]any{"alg": "RS256", "kid": idp.keyID},
			map[string]any{
				"iss":    idp.server.URL,
				"aud":    clientID,
				"sub":    "usr-alice-101",
				"exp":    now.Add(time.Hour).Unix(),
				"iat":    now.Unix(),
				"nonce":  nonceParam,
				"name":   "Alice Operator",
				"email":  "alice@example.com",
				"groups": []string{"/wt-owners", "wt-operators"},
			},
		)
		idp.customToken = token

		callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		callbackReq.AddCookie(stateCookie)
		callbackRec := httptest.NewRecorder()

		svc.ServeHTTP(callbackRec, callbackReq)

		if callbackRec.Code != http.StatusFound {
			t.Fatalf("expected 302 Found from callback, got %d: %s", callbackRec.Code, callbackRec.Body.String())
		}

		if loc := callbackRec.Header().Get("Location"); loc != "/dashboard" {
			t.Errorf("expected redirect to /dashboard, got %q", loc)
		}

		var sessionCookie *http.Cookie
		for _, c := range callbackRec.Result().Cookies() {
			if c.Name == authn.CookieNameSecure || c.Name == authn.CookieNameInsecure {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil || sessionCookie.Value == "" {
			t.Fatalf("missing session cookie in callback response")
		}

		// Verify session in store
		session, err := sessionStore.Get(context.Background(), sessionCookie.Value)
		if err != nil {
			t.Fatalf("fetching session from store: %v", err)
		}
		if len(session.Roles) != 2 || session.Roles[0] != "operator" || session.Roles[1] != "owner" {
			t.Errorf("unexpected effective roles in session: %v", session.Roles)
		}

		// Verify principal in store
		p, err := principalStore.GetByID(context.Background(), session.PrincipalID)
		if err != nil {
			t.Fatalf("fetching principal: %v", err)
		}
		if p.DisplayName != "Alice Operator" {
			t.Errorf("unexpected display name: %s", p.DisplayName)
		}
	})

	t.Run("ID token with wrong issuer is refused", func(t *testing.T) {
		stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
		now := clk.Now()
		idp.customToken = idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss":   "https://attacker.com",
				"aud":   clientID,
				"sub":   "usr-wrong-iss",
				"exp":   now.Add(time.Hour).Unix(),
				"nonce": nonceParam,
			},
		)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for wrong issuer, got %d", rec.Code)
		}
	})

	t.Run("ID token with wrong audience is refused", func(t *testing.T) {
		stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
		now := clk.Now()
		idp.customToken = idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss":   idp.server.URL,
				"aud":   "attacker-client-id",
				"sub":   "usr-wrong-aud",
				"exp":   now.Add(time.Hour).Unix(),
				"nonce": nonceParam,
			},
		)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for wrong audience, got %d", rec.Code)
		}
	})

	t.Run("expired ID token is refused", func(t *testing.T) {
		stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
		now := clk.Now()
		idp.customToken = idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss":   idp.server.URL,
				"aud":   clientID,
				"sub":   "usr-expired",
				"exp":   now.Add(-10 * time.Minute).Unix(),
				"nonce": nonceParam,
			},
		)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for expired token, got %d", rec.Code)
		}
	})

	t.Run("replayed or mismatched nonce is refused", func(t *testing.T) {
		stateCookie, stateParam, _ := initiateLogin(t, svc, "/")
		now := clk.Now()
		idp.customToken = idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss":   idp.server.URL,
				"aud":   clientID,
				"sub":   "usr-replayed-nonce",
				"exp":   now.Add(time.Hour).Unix(),
				"nonce": "replayed-or-forged-nonce-12345",
			},
		)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for replayed/mismatched nonce, got %d", rec.Code)
		}
	})

	t.Run("disallowed algorithm none is refused", func(t *testing.T) {
		stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
		now := clk.Now()
		idp.customToken = idp.signIDToken(
			map[string]any{"alg": "none"},
			map[string]any{
				"iss":   idp.server.URL,
				"aud":   clientID,
				"sub":   "usr-alg-none",
				"exp":   now.Add(time.Hour).Unix(),
				"nonce": nonceParam,
			},
		)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for algorithm none, got %d", rec.Code)
		}
	})

	t.Run("inactive principal cannot log in", func(t *testing.T) {
		// First deactivate principal
		deactEmail := "inactive@example.com"
		p, err := principalStore.UpsertHuman(context.Background(), idp.server.URL, "sub-inactive-123", "Inactive User", &deactEmail, []string{})
		if err != nil {
			t.Fatal(err)
		}
		adminActor := auth.Principal{ID: uuid.Must(uuid.NewV7()).String(), Kind: auth.Human}
		if err := principalStore.Deactivate(context.Background(), p.ID, adminActor, "test deactivation"); err != nil {
			t.Fatal(err)
		}

		stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
		now := clk.Now()
		idp.customToken = idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss":   idp.server.URL,
				"aud":   clientID,
				"sub":   "sub-inactive-123",
				"exp":   now.Add(time.Hour).Unix(),
				"nonce": nonceParam,
				"name":  "Inactive User",
			},
		)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for inactive principal login, got %d", rec.Code)
		}
	})

	t.Run("IdP error callback returns unauthorized and sanitizes input", func(t *testing.T) {
		stateCookie, stateParam, _ := initiateLogin(t, svc, "/")
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(stateParam)+"&error=access_denied&error_description=user%0Acanceled", nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for IdP error, got %d", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "\ncanceled") {
			t.Errorf("expected newlines to be sanitized in error response, got %q", rec.Body.String())
		}
	})

	t.Run("logout revokes session and redirects", func(t *testing.T) {
		// Create a session to log out from
		p, err := principalStore.UpsertHuman(context.Background(), idp.server.URL, "sub-logout-user", "Logout User", nil, []string{})
		if err != nil {
			t.Fatal(err)
		}
		sess, err := sessionStore.Create(context.Background(), p.ID, "oidc", []string{"user"})
		if err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
		req.AddCookie(sessionStore.Cookie(sess.Token, false))
		rec := httptest.NewRecorder()

		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Errorf("expected 302 Found on logout, got %d", rec.Code)
		}
		checkEndSessionRedirect(t, rec.Header().Get("Location"), idp.server.URL+"/logout", clientID)

		// Session in PostgreSQL must now be revoked
		_, err = sessionStore.Get(context.Background(), sess.Token)
		if !strings.Contains(fmt.Sprint(err), "revoked") {
			t.Errorf("expected session to be revoked, got %v", err)
		}
	})
}

func TestExchangeIDToken(t *testing.T) {
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)

	const clientID = "whitetower-console"
	const cliClientID = "wtctl"

	roleMapping := map[string]string{
		"wt-owners":    "owner",
		"wt-operators": "operator",
	}

	svc, err := authn.NewOIDCService(context.Background(), authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          clientID,
		CLIClientID:       cliClientID,
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		RoleMapping:       roleMapping,
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        idp.server.Client(),
		Tokens:            tokenStore,
	}, database, principalStore, sessionStore)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}

	t.Run("successful exchange for wtctl audience returns 12-hour API token", func(t *testing.T) {
		now := clk.Now()
		rawToken := idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss":    idp.server.URL,
				"aud":    cliClientID,
				"sub":    "cli-user-123",
				"exp":    now.Add(time.Hour).Unix(),
				"name":   "CLI User",
				"email":  "cli@example.com",
				"groups": []string{"wt-owners"},
			},
		)

		created, err := svc.ExchangeIDToken(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("ExchangeIDToken failed: %v", err)
		}

		if !strings.HasPrefix(created.Token, authn.TokenPrefix) {
			t.Errorf("expected token prefix %q, got %q", authn.TokenPrefix, created.Token)
		}
		if diff := created.ExpiresAt.Sub(now); diff != 12*time.Hour {
			t.Errorf("expected 12 hour expiry, got %v", diff)
		}
		if len(created.Scopes) == 0 {
			t.Error("expected non-empty scopes for owner role")
		}

		// Authenticate with the returned API token
		authenticator := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, roleMapping)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+created.Token)
		principal, err := authenticator.Authenticate(req)
		if err != nil {
			t.Fatalf("authenticating with exchanged token: %v", err)
		}
		if principal == nil {
			t.Fatal("expected principal, got nil")
		}
		if principal.ID != created.PrincipalID.String() {
			t.Errorf("principal ID: got %q, want %q", principal.ID, created.PrincipalID.String())
		}
		if principal.Name != "CLI User" {
			t.Errorf("principal Name: got %q, want %q", principal.Name, "CLI User")
		}
	})

	t.Run("wrong audience is refused", func(t *testing.T) {
		now := clk.Now()
		rawToken := idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss": idp.server.URL,
				"aud": "wrong-client-app",
				"sub": "cli-user-456",
				"exp": now.Add(time.Hour).Unix(),
			},
		)

		_, err := svc.ExchangeIDToken(context.Background(), rawToken)
		if err == nil {
			t.Error("expected exchange to fail for wrong audience")
		}
	})

	t.Run("expired ID token is refused", func(t *testing.T) {
		now := clk.Now()
		rawToken := idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss": idp.server.URL,
				"aud": cliClientID,
				"sub": "cli-user-789",
				"exp": now.Add(-time.Hour).Unix(),
			},
		)

		_, err := svc.ExchangeIDToken(context.Background(), rawToken)
		if err == nil {
			t.Error("expected exchange to fail for expired ID token")
		}
	})

	t.Run("deactivated principal is refused with ErrPrincipalInactive", func(t *testing.T) {
		now := clk.Now()
		sub := "cli-inactive-user"
		rawToken := idp.signIDToken(
			map[string]any{"alg": "RS256"},
			map[string]any{
				"iss":    idp.server.URL,
				"aud":    cliClientID,
				"sub":    sub,
				"exp":    now.Add(time.Hour).Unix(),
				"groups": []string{"wt-owners"},
			},
		)

		// First exchange provisions principal
		created, err := svc.ExchangeIDToken(context.Background(), rawToken)
		if err != nil {
			t.Fatalf("first exchange failed: %v", err)
		}

		// Deactivate principal
		if err := principalStore.Deactivate(context.Background(), created.PrincipalID, auth.Principal{ID: created.PrincipalID.String(), Kind: auth.Human}, "security offboarding"); err != nil {
			t.Fatalf("deactivating principal: %v", err)
		}

		// Subsequent exchange attempt must be refused
		_, err = svc.ExchangeIDToken(context.Background(), rawToken)
		if !errors.Is(err, authn.ErrPrincipalInactive) {
			t.Errorf("expected ErrPrincipalInactive, got %v", err)
		}
	})
}

// backChannelOptions returns the options of a service that reaches the mock at
// its discovery URL, as a core in a container reaches Keycloak, while browsers
// reach the provider at frontIssuer.
func backChannelOptions(idp *mockIDP, clk *clocktest.Fake) authn.OIDCOptions {
	return authn.OIDCOptions{
		Issuer:            frontIssuer,
		DiscoveryURL:      idp.server.URL,
		ClientID:          "whitetower-console",
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		RoleMapping:       map[string]string{"wt-owners": "owner"},
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        idp.server.Client(),
	}
}

// signInThroughBackChannel completes a sign-in whose ID token names issuer,
// and returns the service's answer to the callback.
func signInThroughBackChannel(t *testing.T, svc *authn.OIDCService, idp *mockIDP, clk *clocktest.Fake, issuer string) *httptest.ResponseRecorder {
	t.Helper()
	stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
	now := clk.Now()
	idp.customToken = idp.signIDToken(map[string]any{"alg": "RS256"}, map[string]any{
		"iss":    issuer,
		"aud":    "whitetower-console",
		"sub":    "usr-back-channel",
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"nonce":  nonceParam,
		"name":   "Bea Back",
		"groups": []string{"wt-owners"},
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
	req.AddCookie(stateCookie)
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)
	return rec
}

// Security test ST-16: a provider that the server reaches at a discovery URL,
// a back channel, keeps the configured issuer: browsers go to the issuer's
// endpoints, principals keep the issuer, and an ID token issued at the back
// channel is refused.
func TestTheProviderIsDiscoveredThroughItsBackChannel(t *testing.T) {
	idp := newMockIDP(t)
	idp.discovery = idp.backChannelDocument(frontIssuer)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)

	opts := backChannelOptions(idp, clk)
	opts.Tokens = tokenStore
	svc, err := authn.NewOIDCService(context.Background(), opts, database, principalStore, sessionStore)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}

	t.Run("sign-in sends the browser to the issuer, and the principal keeps it", func(t *testing.T) {
		loginRec := httptest.NewRecorder()
		svc.ServeHTTP(loginRec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		if loc := loginRec.Header().Get("Location"); !strings.HasPrefix(loc, frontIssuer+"/protocol/openid-connect/auth?") {
			t.Fatalf("login redirects to %q, want the issuer's authorization endpoint", loc)
		}

		rec := signInThroughBackChannel(t, svc, idp, clk, frontIssuer)
		if rec.Code != http.StatusFound {
			t.Fatalf("callback: got %d %q, want 302", rec.Code, rec.Body.String())
		}
		var session *authn.Session
		for _, c := range rec.Result().Cookies() {
			if c.Name == authn.CookieNameInsecure && c.Value != "" {
				s, err := sessionStore.Get(context.Background(), c.Value)
				if err != nil {
					t.Fatalf("reading the session: %v", err)
				}
				session = s
			}
		}
		if session == nil || len(session.Roles) != 1 || session.Roles[0] != "owner" {
			t.Fatalf("session %+v, want one with the owner role", session)
		}
		p, err := principalStore.GetByID(context.Background(), session.PrincipalID)
		if err != nil {
			t.Fatalf("reading the principal: %v", err)
		}
		if p.Issuer == nil || *p.Issuer != frontIssuer {
			t.Errorf("the principal's issuer is %v, want %s", p.Issuer, frontIssuer)
		}
	})

	t.Run("an ID token issued at the back channel is refused", func(t *testing.T) {
		if rec := signInThroughBackChannel(t, svc, idp, clk, idp.server.URL); rec.Code != http.StatusBadRequest {
			t.Errorf("callback: got %d %q, want 400", rec.Code, rec.Body.String())
		}
		now := clk.Now()
		rawToken := idp.signIDToken(map[string]any{"alg": "RS256"}, map[string]any{
			"iss": idp.server.URL,
			"aud": "wtctl",
			"sub": "cli-back-channel",
			"exp": now.Add(time.Hour).Unix(),
		})
		if _, err := svc.ExchangeIDToken(context.Background(), rawToken); !errors.Is(err, authn.ErrInvalidToken) {
			t.Errorf("exchange: got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("logout sends the browser to the issuer's end session endpoint", func(t *testing.T) {
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("logout: got %d, want 302", rec.Code)
		}
		checkEndSessionRedirect(t, rec.Header().Get("Location"), frontIssuer+"/protocol/openid-connect/logout", opts.ClientID)
	})
}

// Security test ST-16: a discovery document that names another issuer than
// the configured one is refused, whether the server fetched it at a discovery
// URL or at the issuer itself.
func TestADiscoveryDocumentThatNamesAnotherIssuerIsRefused(t *testing.T) {
	tests := []struct {
		name string
		// atIssuer runs discovery at the issuer, without a discovery URL.
		atIssuer bool
		// named returns the issuer that the document names; nil: none.
		named func(idp *mockIDP) string
	}{
		{"the back channel's URL", false, func(idp *mockIDP) string { return idp.server.URL }},
		{"the issuer with a trailing slash", false, func(*mockIDP) string { return frontIssuer + "/" }},
		{"no issuer", false, nil},
		{"another provider", false, func(*mockIDP) string { return "https://attacker.example/realms/whitetower" }},
		{"another provider, at the issuer", true, func(*mockIDP) string { return "https://attacker.example/realms/whitetower" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newMockIDP(t)
			opts := backChannelOptions(idp, clocktest.New(testEpoch))
			if tt.atIssuer {
				opts.Issuer, opts.DiscoveryURL = idp.server.URL, ""
			}
			idp.discovery = idp.backChannelDocument(opts.Issuer)
			delete(idp.discovery, "issuer")
			if tt.named != nil {
				idp.discovery["issuer"] = tt.named(idp)
			}

			_, err := authn.NewOIDCService(context.Background(), opts, nil, nil, nil)
			var mismatch *oidc.IssuerMismatchError
			if !errors.As(err, &mismatch) || mismatch.Provided != opts.Issuer {
				t.Fatalf("got %v, want an issuer mismatch with %s", err, opts.Issuer)
			}
			if document := idp.server.URL + "/.well-known/openid-configuration"; !strings.Contains(err.Error(), document) {
				t.Errorf("error %q does not name the document's URL %s", err, document)
			}
		})
	}
}

// A discovery that fails stops the service with an error that names the URL
// it fetched, for the operator who reads the server's log.
func TestAFailedDiscoveryNamesTheDocumentItFetched(t *testing.T) {
	idp := newMockIDP(t)
	idp.hangUp = "/.well-known/openid-configuration"
	_, err := authn.NewOIDCService(context.Background(), backChannelOptions(idp, clocktest.New(testEpoch)), nil, nil, nil)
	if document := idp.server.URL + "/.well-known/openid-configuration"; err == nil || !strings.Contains(err.Error(), document) {
		t.Fatalf("got %v, want an error that names %s", err, document)
	}
}

// The service refuses options that leave it no issuer to check documents and
// ID tokens against, or no origin to come back to after a logout.
func TestTheServiceNeedsAnIssuerAndAnAbsoluteRedirectURL(t *testing.T) {
	for name, change := range map[string]func(*authn.OIDCOptions){
		"no issuer":               func(o *authn.OIDCOptions) { o.Issuer = "" },
		"a relative redirect URL": func(o *authn.OIDCOptions) { o.RedirectURL = "/auth/callback" },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newMockIDP(t)
			opts := backChannelOptions(idp, clocktest.New(testEpoch))
			change(&opts)
			// The document names the configured issuer, even an empty one, so
			// that only the refusal under test can stop the service.
			idp.discovery = idp.backChannelDocument(opts.Issuer)
			if _, err := authn.NewOIDCService(context.Background(), opts, nil, nil, nil); err == nil {
				t.Fatal("the service was created")
			}
		})
	}
}

// Security test ST-16: the errors of a call on the back channel name its URL,
// and a browser that signs in gets none of them.
func TestAFailureOnTheBackChannelNamesNothingOfItToTheBrowser(t *testing.T) {
	for _, tt := range []struct {
		path string
		want int
	}{
		{"/token", http.StatusBadGateway},
		{"/jwks", http.StatusBadRequest},
	} {
		t.Run(tt.path, func(t *testing.T) {
			idp := newMockIDP(t)
			idp.discovery = idp.backChannelDocument(frontIssuer)
			idp.hangUp = tt.path
			clk := clocktest.New(testEpoch)
			svc, err := authn.NewOIDCService(context.Background(), backChannelOptions(idp, clk), nil, nil, nil)
			if err != nil {
				t.Fatalf("creating OIDC service: %v", err)
			}

			rec := signInThroughBackChannel(t, svc, idp, clk, frontIssuer)
			if rec.Code != tt.want {
				t.Errorf("callback: got %d, want %d", rec.Code, tt.want)
			}
			if backChannel := idp.server.Listener.Addr().String(); strings.Contains(rec.Body.String(), backChannel) {
				t.Errorf("the browser learns the back channel %s: %q", backChannel, rec.Body.String())
			}
		})
	}
}
