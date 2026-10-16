package authn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
)

// TestSAMLThroughBroker verifies that an identity brokered from a SAML 2.0 IdP
// through Keycloak is accepted, correctly maps enterprise claims and groups into White Tower roles,
// provisions the human principal, and establishes an active session (HUM-08, plan P1-03 step 10).
func TestSAMLThroughBroker(t *testing.T) {
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)

	const clientID = "whitetower-console"

	// Role mapping matching the SAML broker guide (docs/guides/saml-broker.md)
	roleMapping := map[string]string{
		"CN=WhiteTower-Admins,OU=Groups,DC=corp,DC=example": "admin",
		"wt-operators": "operator",
	}

	svc, err := authn.NewOIDCService(context.Background(), authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          clientID,
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		RoleMapping:       roleMapping,
		GroupsClaim:       "groups",
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        idp.server.Client(),
	}, database, principalStore, sessionStore)
	if err != nil {
		t.Fatalf("initializing OIDCService: %v", err)
	}

	// 1. User initiates login
	loginReq := httptest.NewRequest(http.MethodGet, "/auth/login?return_url=/dashboard", nil)
	loginRec := httptest.NewRecorder()
	svc.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found from /auth/login, got %d", loginRec.Code)
	}

	var stateCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "wt_oidc") {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("missing OIDC state cookie in login response")
	}

	loc := loginRec.Header().Get("Location")
	stateParam := loc[strings.Index(loc, "state=")+6:]
	if idx := strings.Index(stateParam, "&"); idx != -1 {
		stateParam = stateParam[:idx]
	}

	nonceParam := loc[strings.Index(loc, "nonce=")+6:]
	if idx := strings.Index(nonceParam, "&"); idx != -1 {
		nonceParam = nonceParam[:idx]
	}

	// 2. Keycloak brokers the SAML IdP assertion and returns ID token with SAML attributes
	samlBrokeredClaims := map[string]any{
		"iss":   idp.server.URL,
		"aud":   clientID,
		"sub":   "saml-federated-alice-9876",
		"exp":   clk.Now().Add(time.Hour).Unix(),
		"iat":   clk.Now().Unix(),
		"nonce": nonceParam,
		"name":  "Alice Enterprise",
		"email": "alice@corp.example.com",
		"groups": []string{
			"CN=WhiteTower-Admins,OU=Groups,DC=corp,DC=example",
			"wt-operators",
		},
	}
	idp.customToken = idp.signIDToken(map[string]any{"alg": "RS256"}, samlBrokeredClaims)

	// 3. Callback from Keycloak broker
	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=valid-auth-code&state="+stateParam, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRec := httptest.NewRecorder()
	svc.ServeHTTP(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found from callback, got %d", callbackRec.Code)
	}

	// Verify redirect to return_url
	if redirectURL := callbackRec.Header().Get("Location"); redirectURL != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %q", redirectURL)
	}

	// Verify session cookie was set
	var sessionCookie *http.Cookie
	for _, c := range callbackRec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "wt_session") {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie in response")
	}

	// 4. Verify principal was provisioned in PostgreSQL with mapped roles
	p, err := principalStore.GetByIdentity(context.Background(), idp.server.URL, "saml-federated-alice-9876")
	if err != nil {
		t.Fatalf("fetching brokered principal from DB: %v", err)
	}
	if p.DisplayName != "Alice Enterprise" {
		t.Errorf("displayName %q, want Alice Enterprise", p.DisplayName)
	}
	if p.Email == nil || *p.Email != "alice@corp.example.com" {
		t.Errorf("email %v, want alice@corp.example.com", p.Email)
	}

	// 5. Verify effective roles resolved from SAML groups in active session
	session, err := sessionStore.Get(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("reading session for brokered user: %v", err)
	}
	// "admin" and "operator" mapped from the SAML group claims
	expectedRoles := []string{"admin", "operator"}
	if len(session.Roles) != len(expectedRoles) {
		t.Fatalf("expected roles %v, got %v", expectedRoles, session.Roles)
	}
	for i, r := range expectedRoles {
		if session.Roles[i] != r {
			t.Errorf("role[%d] = %q, want %q", i, session.Roles[i], r)
		}
	}
}
