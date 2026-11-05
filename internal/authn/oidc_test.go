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
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
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
	// discoveryStatus, when set, is the HTTP status that the mock answers
	// for its discovery document, without the document; set it before the
	// first request.
	discoveryStatus int
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	return startMockIDP(t, httptest.NewServer)
}

// newTLSMockIDP returns a mock that serves HTTPS, with a certificate of the
// test server's own authority, which no system trusts.
func newTLSMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	return startMockIDP(t, httptest.NewTLSServer)
}

func startMockIDP(t *testing.T, start func(http.Handler) *httptest.Server) *mockIDP {
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
		if m.discoveryStatus != 0 {
			http.Error(w, http.StatusText(m.discoveryStatus), m.discoveryStatus)
			return
		}
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

	m.server = start(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// newStateKey returns a key of the shortest length that signs the state of a
// sign-in.
func newStateKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, authn.MinStateKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// newService returns a service of opts that has discovered its provider, with
// a state key of its own unless opts holds one.
func newService(t *testing.T, opts authn.OIDCOptions, principals *authn.PrincipalStore, sessions *authn.SessionStore) *authn.OIDCService {
	t.Helper()
	if opts.StateKey == nil {
		opts.StateKey = newStateKey(t)
	}
	svc, err := authn.NewOIDCService(opts, principals, sessions)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}
	if err := svc.Discover(context.Background()); err != nil {
		t.Fatalf("discovering the provider: %v", err)
	}
	return svc
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
		if c.Name == "__Host-wt_oidc" {
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
	sessionStore, principalStore, _, _ := setupAuthn(t, clk)

	// Rate limiter with capacity for 2 requests
	limiter := ratelimit.New(1, 2)

	svc := newService(t, authn.OIDCOptions{
		Issuer:       idp.server.URL,
		ClientID:     "whitetower-client",
		ClientSecret: "secret",
		RedirectURL:  "https://127.0.0.1:8443/auth/callback",
		Clock:        clk,
		Limiter:      limiter,
	}, principalStore, sessionStore)

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
	sessionStore, principalStore, _, _ := setupAuthn(t, clk)

	const clientID = "whitetower-console"

	roleMapping := map[string]string{
		"wt-owners":    "owner",
		"wt-operators": "operator",
	}

	svc := newService(t, authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          clientID,
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		RoleMapping:       roleMapping,
		AllowedAlgorithms: []string{"RS256"},
	}, principalStore, sessionStore)

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
			if c.Name == authn.CookieName {
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
		p, err := principalStore.SignIn(context.Background(), "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "sub-inactive-123", ExternalID: "sub-inactive-123", DisplayName: "Inactive User", Email: &deactEmail}, nil)
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

	t.Run("logout revokes session and sends the browser to the end session endpoint", func(t *testing.T) {
		// Create a session to log out from
		p, err := principalStore.SignIn(context.Background(), "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "sub-logout-user", ExternalID: "sub-logout-user", DisplayName: "Logout User"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := sessionStore.Create(context.Background(), p.ID, "oidc", []string{"user"})
		if err != nil {
			t.Fatal(err)
		}

		logout := authn.NewLogoutService(sessionStore, authn.LogoutOptions{EndSession: svc.EndSessionURL})
		rec := postLogout(t, logout, http.MethodPost, sess.Token, sess.CSRFToken)
		checkEndSessionRedirect(t, redirectOf(t, rec), idp.server.URL+"/logout", clientID)

		// Session in PostgreSQL must now be revoked
		_, err = sessionStore.Get(context.Background(), sess.Token)
		if !strings.Contains(fmt.Sprint(err), "revoked") {
			t.Errorf("expected session to be revoked, got %v", err)
		}
	})
}

// Security test ST-14: a sign-in revokes the session that the browser held,
// under the session cookie's name or the unprefixed one, whoever it belonged
// to; a sign-in that fails revokes nothing
func TestASignInRevokesTheSessionTheBrowserHeld(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, _ := setupAuthn(t, clk)

	const clientID = "whitetower-console"
	svc := newService(t, authn.OIDCOptions{
		Issuer:       idp.server.URL,
		ClientID:     clientID,
		ClientSecret: "test-secret",
		RedirectURL:  "https://127.0.0.1:8443/auth/callback",
		Clock:        clk,
	}, principalStore, sessionStore)

	// callback ends a sign-in whose ID token has the audience aud, with the
	// browser's cookies, and returns the answer.
	callback := func(t *testing.T, subject, aud string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
		idp.customToken = idp.signIDToken(map[string]any{"alg": "RS256"}, map[string]any{
			"iss":   idp.server.URL,
			"aud":   aud,
			"sub":   subject,
			"exp":   clk.Now().Add(time.Hour).Unix(),
			"nonce": nonceParam,
		})
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
		req.AddCookie(stateCookie)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		return rec
	}
	// signIn ends a sign-in that succeeds, and returns its session's token.
	signIn := func(t *testing.T, subject string, cookies ...*http.Cookie) string {
		t.Helper()
		rec := callback(t, subject, clientID, cookies...)
		if rec.Code != http.StatusFound {
			t.Fatalf("sign-in as %s: got %d %q, want 302", subject, rec.Code, rec.Body.String())
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == authn.CookieName && c.Value != "" {
				return c.Value
			}
		}
		t.Fatalf("sign-in as %s set no session cookie", subject)
		return ""
	}
	checkRevoked := func(t *testing.T, token string) {
		t.Helper()
		if _, err := sessionStore.Get(ctx, token); !errors.Is(err, authn.ErrSessionRevoked) {
			t.Errorf("the session the browser held: got %v, want it revoked", err)
		}
	}
	checkValid := func(t *testing.T, token string) {
		t.Helper()
		if _, err := sessionStore.Get(ctx, token); err != nil {
			t.Errorf("the session: got %v, want it valid", err)
		}
	}

	t.Run("the previous person's session", func(t *testing.T) {
		alice := signIn(t, "usr-alice")
		bob := signIn(t, "usr-bob", &http.Cookie{Name: authn.CookieName, Value: alice})
		checkRevoked(t, alice)
		checkValid(t, bob)
	})

	t.Run("the same person's session", func(t *testing.T) {
		first := signIn(t, "usr-carol")
		second := signIn(t, "usr-carol", &http.Cookie{Name: authn.CookieName, Value: first})
		checkRevoked(t, first)
		checkValid(t, second)
	})

	t.Run("a session planted under the unprefixed name", func(t *testing.T) {
		mallory, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "usr-mallory", ExternalID: "usr-mallory", DisplayName: "Mallory Planter"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		planted, err := sessionStore.Create(ctx, mallory.ID, "oidc", []string{"user"})
		if err != nil {
			t.Fatal(err)
		}
		dave := signIn(t, "usr-dave", &http.Cookie{Name: "wt_session", Value: planted.Token})
		checkRevoked(t, planted.Token)
		checkValid(t, dave)
	})

	t.Run("a sign-in that fails", func(t *testing.T) {
		held := signIn(t, "usr-erin")
		if rec := callback(t, "usr-frank", "another-client", &http.Cookie{Name: authn.CookieName, Value: held}); rec.Code != http.StatusBadRequest {
			t.Fatalf("a sign-in with an ID token for another client: got %d, want 400", rec.Code)
		}
		checkValid(t, held)
	})

	// The console is served over HTTPS only, development included, so the
	// cookies of a sign-in are always Secure, with the __Host- prefix.
	t.Run("the cookies of a sign-in are Secure", func(t *testing.T) {
		login := httptest.NewRecorder()
		svc.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		cookies := append(login.Result().Cookies(), callback(t, "usr-grace", clientID).Result().Cookies()...)
		names := map[string]bool{}
		for _, c := range cookies {
			names[c.Name] = true
			if !strings.HasPrefix(c.Name, "__Host-") || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
				t.Errorf("cookie %s: Secure %v, HttpOnly %v, path %q, domain %q", c.Name, c.Secure, c.HttpOnly, c.Path, c.Domain)
			}
		}
		if !names["__Host-wt_oidc"] || !names[authn.CookieName] {
			t.Errorf("cookies %v, want the state cookie and the session cookie", names)
		}
	})
}

// Security test ST-14: a sign-in that changes a person's groups, from which
// their roles come, revokes the person's other sessions in its transaction,
// through the callback and the CLI's exchange, so that no session keeps the
// roles of the groups before; the session of that sign-in is the one left. A
// sign-in with the same groups, another person's sign-in, a sign-in that
// fails after the change, and break-glass, whose custodian has no groups,
// revoke nothing
func TestASignInThatChangesThePersonsGroupsRevokesTheirOtherSessions(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	svc := eventsService(t, idp, clk, principalStore, sessionStore, tokenStore)
	// signIn signs in from a browser of its own, with no session cookie, and
	// returns the new session's token.
	signIn := func(t *testing.T, subject string, groups ...string) string {
		t.Helper()
		return sessionToken(t, browserSignIn(t, svc, idp, clk, map[string]any{"sub": subject, "name": "Ivy Canary", "groups": groups}))
	}
	check := func(t *testing.T, what, token string, want error) {
		t.Helper()
		if _, err := sessionStore.Get(ctx, token); !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", what, err, want)
		}
	}
	revocations := func() int { return len(eventsOf(t, database, sessionRevoked)) }

	first := signIn(t, "usr-ivy", "wt-owners")
	second := signIn(t, "usr-ivy", "wt-owners")
	jacks := signIn(t, "usr-jack", "wt-owners", "wt-auditors")
	check(t, "a session after a sign-in with the same groups", first, nil)
	check(t, "the session of a sign-in with the same groups", second, nil)

	recorded := revocations()
	third := signIn(t, "usr-ivy", "wt-owners", "wt-auditors")
	check(t, "a session of the groups before", first, authn.ErrSessionRevoked)
	check(t, "another session of the groups before", second, authn.ErrSessionRevoked)
	check(t, "the session of the sign-in that changed the groups", third, nil)
	check(t, "another person's session", jacks, nil)
	// The change of groups records the revocations, as a deactivation
	// records its own.
	if n := revocations(); n != recorded {
		t.Errorf("%d revocations of sessions recorded, want none: the change of groups records them", n-recorded)
	}
	if n := len(eventsOf(t, database, groupsChanged)); n != 1 {
		t.Errorf("%d changes of groups recorded, want 1", n)
	}

	if _, err := svc.ExchangeIDToken(ctx, exchangeToken(idp, clk, map[string]any{"sub": "usr-ivy", "groups": []string{"wt-owners"}})); err != nil {
		t.Fatal(err)
	}
	check(t, "a session after an exchange that changed the groups", third, authn.ErrSessionRevoked)
	check(t, "another person's session after the exchange", jacks, nil)

	fourth := signIn(t, "usr-ivy", "wt-owners")
	failed := errors.New("the rest of the sign-in fails")
	if _, err := principalStore.SignIn(ctx, "oidc", authn.Identity{
		Issuer: idp.server.URL, Subject: "usr-ivy", ExternalID: "usr-ivy", DisplayName: "Ivy Canary", Groups: []string{"wt-admins"},
	}, func(context.Context, *db.Tx, *authn.Principal) error { return failed }); !errors.Is(err, failed) {
		t.Fatalf("a sign-in that fails: got %v", err)
	}
	check(t, "a session after a sign-in that changed the groups, then failed", fourth, nil)

	// Break-glass signs in its custodian, whose groups are always none: two
	// custodians signed in at once both keep their sessions.
	rawCred, hashStr, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatal(err)
	}
	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	if err := os.WriteFile(hashFile, []byte(hashStr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	breakglass := authn.NewBreakglassService(authn.BreakglassOptions{
		Enabled: true, CredentialHashFile: hashFile, Clock: clk, Logger: slog.New(slog.DiscardHandler),
	}, database, sessionStore, audit.NewWriter(mustCatalog(t), clk))
	custodian := func() string {
		req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"credential":"`+rawCred+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		breakglass.ServeHTTP(rec, req)
		return sessionToken(t, rec)
	}
	one, two := custodian(), custodian()
	check(t, "the first custodian's session", one, nil)
	check(t, "the second custodian's session", two, nil)
}

func TestExchangeIDToken(t *testing.T) {
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, _ := setupAuthn(t, clk)

	const clientID = "whitetower-console"
	const cliClientID = "wtctl"

	roleMapping := map[string]string{
		"wt-owners":    "owner",
		"wt-operators": "operator",
	}

	svc := newService(t, authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          clientID,
		CLIClientID:       cliClientID,
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		RoleMapping:       roleMapping,
		AllowedAlgorithms: []string{"RS256"},
		Tokens:            tokenStore,
	}, principalStore, sessionStore)

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
	sessionStore, principalStore, tokenStore, _ := setupAuthn(t, clk)

	opts := backChannelOptions(idp, clk)
	opts.Tokens = tokenStore
	svc := newService(t, opts, principalStore, sessionStore)

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
			if c.Name == authn.CookieName && c.Value != "" {
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
		checkEndSessionRedirect(t, svc.EndSessionURL(), frontIssuer+"/protocol/openid-connect/logout", opts.ClientID)
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

			err := discover(t, opts)
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

// The endpoints that browsers use may leave the issuer's origin, as a
// provider whose sign-in pages have their own host does: the server checks
// the document's issuer, not where the document sends browsers.
func TestTheBrowsersEndpointsMayLeaveTheIssuersOrigin(t *testing.T) {
	idp := newMockIDP(t)
	idp.discovery = idp.backChannelDocument(frontIssuer)
	idp.discovery["authorization_endpoint"] = "https://login.example.test/authorize"
	idp.discovery["end_session_endpoint"] = "https://login.example.test/logout"
	clk := clocktest.New(testEpoch)
	opts := backChannelOptions(idp, clk)
	svc := newService(t, opts, nil, nil)

	login := httptest.NewRecorder()
	svc.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if loc := login.Header().Get("Location"); !strings.HasPrefix(loc, "https://login.example.test/authorize?") {
		t.Errorf("login redirects to %q, want the document's authorization endpoint", loc)
	}
	checkEndSessionRedirect(t, svc.EndSessionURL(), "https://login.example.test/logout", opts.ClientID)
}

// The console sends browsers to the provider's end session endpoint from its
// own origin, so the server keeps the endpoint only when it is an absolute
// https URL, or http when the issuer is plain HTTP too, as only development
// allows. Any other endpoint, a javascript: or data: URL, a relative one, one
// without a scheme or plain HTTP for an https issuer, leaves the sign-out the
// core's own: discovery still succeeds, and logs once, sanitized, why.
func TestOnlyAnHTTPSEndSessionEndpointIsKept(t *testing.T) {
	const notUsed = "not using the identity provider's end session endpoint: a sign-out ends the core's session only"
	for _, tt := range []struct {
		name     string
		endpoint string // "" for the http issuer's own endpoint
		kept     bool
	}{
		{"https", "https://login.example.test/logout", true},
		{"http for an http issuer", "", true},
		{"http for an https issuer", "http://login.example.test/logout", false},
		{"javascript:", "javascript:alert(1)", false},
		{"javascript: with a forged log line", "javascript:alert(1)\n" + `{"level":"INFO","msg":"forged"}`, false},
		{"data:", "data:text/html,<script>alert(1)</script>", false},
		{"a relative URL", "/protocol/openid-connect/logout", false},
		{"no scheme", "//login.example.test/logout", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			idp := newMockIDP(t)
			opts := backChannelOptions(idp, clocktest.New(testEpoch))
			endpoint := tt.endpoint
			if endpoint == "" {
				opts.Issuer, opts.DiscoveryURL = idp.server.URL, ""
				endpoint = idp.server.URL + "/logout"
			}
			idp.discovery = idp.backChannelDocument(opts.Issuer)
			idp.discovery["end_session_endpoint"] = endpoint
			logs := &logBuffer{}
			opts.Logger = slog.New(slog.NewJSONHandler(logs, nil))
			svc := newService(t, opts, nil, nil)

			records := logs.records(t, notUsed)
			if tt.kept {
				checkEndSessionRedirect(t, svc.EndSessionURL(), endpoint, opts.ClientID)
				if len(records) != 0 {
					t.Errorf("logged %v, want nothing", records)
				}
				return
			}
			if got := svc.EndSessionURL(); got != "" {
				t.Errorf("the end session URL is %q, want none", got)
			}
			if len(records) != 1 || records[0]["end_session_endpoint"] != logging.Sanitize(endpoint) {
				t.Errorf("logged %v, want one record with the endpoint, sanitized", records)
			}
		})
	}
}

// discover returns the error of a first discovery by a new service of opts.
func discover(t *testing.T, opts authn.OIDCOptions) error {
	t.Helper()
	opts.StateKey = newStateKey(t)
	svc, err := authn.NewOIDCService(opts, nil, nil)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}
	return svc.Discover(context.Background())
}

// A discovery that fails returns an error that names the URL it fetched, for
// the operator who reads the server's log. go-oidc names it when the
// connection fails, but not when the provider answers an HTTP error.
func TestAFailedDiscoveryNamesTheDocumentItFetched(t *testing.T) {
	for name, fail := range map[string]func(*mockIDP){
		"the provider hangs up":   func(idp *mockIDP) { idp.hangUp = "/.well-known/openid-configuration" },
		"the document is missing": func(idp *mockIDP) { idp.discoveryStatus = http.StatusNotFound },
		"the provider is down":    func(idp *mockIDP) { idp.discoveryStatus = http.StatusServiceUnavailable },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newMockIDP(t)
			fail(idp)
			err := discover(t, backChannelOptions(idp, clocktest.New(testEpoch)))
			if document := idp.server.URL + "/.well-known/openid-configuration"; err == nil || !strings.Contains(err.Error(), document) {
				t.Fatalf("got %v, want an error that names %s", err, document)
			}
		})
	}
}

// The service refuses options that leave it no issuer to check documents and
// ID tokens against, no origin to come back to after a logout, a state key
// too short to sign with, or certificate authorities it cannot read. These
// are configuration errors, which stop the start before the provider is
// reached.
func TestTheServiceRefusesOptionsItCannotWorkWith(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("no certificate here"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		change func(*authn.OIDCOptions)
		want   string
	}{
		{"no issuer", func(o *authn.OIDCOptions) { o.Issuer = "" }, "an OIDC issuer is required"},
		{"a relative redirect URL", func(o *authn.OIDCOptions) { o.RedirectURL = "/auth/callback" }, "must be an absolute URL"},
		{"no state key", func(o *authn.OIDCOptions) { o.StateKey = nil }, "the OIDC state key holds 0 bytes: want at least 32"},
		{"a short state key", func(o *authn.OIDCOptions) { o.StateKey = o.StateKey[:31] }, "the OIDC state key holds 31 bytes: want at least 32"},
		{"a CA file without certificates", func(o *authn.OIDCOptions) { o.CAFile = notPEM }, "the identity provider's CA file: no PEM certificate in " + notPEM},
		{"a CA file that does not exist", func(o *authn.OIDCOptions) { o.CAFile = notPEM + ".missing" }, "the identity provider's CA file: open " + notPEM + ".missing"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := backChannelOptions(newMockIDP(t), clocktest.New(testEpoch))
			opts.StateKey = newStateKey(t)
			tt.change(&opts)
			if _, err := authn.NewOIDCService(opts, nil, nil); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want a refusal that says %q", err, tt.want)
			}
		})
	}
}

// The errors of a call on the back channel name its URL, and a browser that
// signs in gets none of them: no internal detail reaches a client.
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
			svc := newService(t, backChannelOptions(idp, clk), nil, nil)

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

// The exchange of an ID token that does not verify fails without its cause,
// which can name the back channel, so that no caller can repeat it to a
// client.
func TestARefusedExchangeNamesNothingOfTheBackChannel(t *testing.T) {
	idp := newMockIDP(t)
	idp.discovery = idp.backChannelDocument(frontIssuer)
	idp.hangUp = "/jwks"
	clk := clocktest.New(testEpoch)
	opts := backChannelOptions(idp, clk)
	// The token store is never reached: the ID token does not verify.
	opts.Tokens = authn.NewTokenStore(nil, clk, nil, nil)
	svc := newService(t, opts, nil, nil)

	rawToken := idp.signIDToken(map[string]any{"alg": "RS256"}, map[string]any{
		"iss": frontIssuer,
		"aud": "wtctl",
		"sub": "cli-back-channel",
		"exp": clk.Now().Add(time.Hour).Unix(),
	})
	_, err := svc.ExchangeIDToken(context.Background(), rawToken)
	if !errors.Is(err, authn.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
	if backChannel := idp.server.Listener.Addr().String(); strings.Contains(err.Error(), backChannel) {
		t.Errorf("the client learns the back channel %s: %v", backChannel, err)
	}
}
