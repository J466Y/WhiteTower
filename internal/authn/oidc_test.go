package authn_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.server.URL,
			"authorization_endpoint":                m.server.URL + "/auth",
			"token_endpoint":                        m.server.URL + "/token",
			"jwks_uri":                              m.server.URL + "/jwks",
			"end_session_endpoint":                  m.server.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
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

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
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

	// Helper to perform the login step to obtain the state cookie and authorization URL
	initiateLogin := func(t *testing.T, returnURL string) (*http.Cookie, string, string) {
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

	t.Run("successful login provisions principal and session", func(t *testing.T) {
		stateCookie, stateParam, nonceParam := initiateLogin(t, "/dashboard")

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
		stateCookie, stateParam, nonceParam := initiateLogin(t, "/")
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
		stateCookie, stateParam, nonceParam := initiateLogin(t, "/")
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
		stateCookie, stateParam, nonceParam := initiateLogin(t, "/")
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
		stateCookie, stateParam, _ := initiateLogin(t, "/")
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
		stateCookie, stateParam, nonceParam := initiateLogin(t, "/")
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

		stateCookie, stateParam, nonceParam := initiateLogin(t, "/")
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
		stateCookie, stateParam, _ := initiateLogin(t, "/")
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

		// Session in PostgreSQL must now be revoked
		_, err = sessionStore.Get(context.Background(), sess.Token)
		if !strings.Contains(fmt.Sprint(err), "revoked") {
			t.Errorf("expected session to be revoked, got %v", err)
		}
	})
}
