package authn_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

// signInCount returns how many sign-ins whitetower_auth_sign_ins_total counts
// with the method and result given.
func signInCount(t *testing.T, reg *prometheus.Registry, method, result string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "whitetower_auth_sign_ins_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["method"] == method && labels["result"] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// A sign-in that the server refuses, through the callback, the CLI's exchange
// or break-glass, logs one line with its method and reason, and the ID of the
// principal when the refusal found one, and counts in
// whitetower_auth_sign_ins_total by method and result, as a sign-in that
// succeeds or fails counts too. A refusal writes no audit event, since it
// changes nothing, and the log holds no value of an ID token or a credential
// (the maintainer's decision 3 of 2026-11-05).
func TestARefusedSignInLogsOneLineAndCounts(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	logs := &logBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	reg := prometheus.NewRegistry()
	counts := metrics.NewSignIns(reg)
	counted := newService(t, authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          "whitetower-console",
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		Logger:            logger,
		RoleMapping:       map[string]string{"wt-owners": "owner"},
		AllowedAlgorithms: []string{"RS256"},
		ExternalIDClaim:   "oid",
		SignIns:           counts,
		Tokens:            tokenStore,
	}, principalStore, sessionStore)

	rawCred, hashStr, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatal(err)
	}
	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	if err := os.WriteFile(hashFile, []byte(hashStr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	breakglass := authn.NewBreakglassService(authn.BreakglassOptions{
		Enabled: true, CredentialHashFile: hashFile, Clock: clk, Logger: logger, SignIns: counts,
		// Three attempts, then the limit, which the fake clock never lifts.
		Limiter: ratelimit.New(1.0/3600, 3),
	}, database, sessionStore, audit.NewWriter(mustCatalog(t), clk))
	useBreakglass := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		breakglass.ServeHTTP(rec, req)
		return rec.Code
	}
	callback := func(query string, cookies ...*http.Cookie) int {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		counted.ServeHTTP(rec, req)
		return rec.Code
	}

	// Ines signed in, and was deactivated since. Lou signed in while the
	// external ID was the sub.
	ines, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "usr-ines", ExternalID: "idp-ines", DisplayName: "Ines Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := principalStore.Deactivate(ctx, ines.ID, auth.Principal{}, "left"); err != nil {
		t.Fatal(err)
	}
	lou, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "usr-lou", ExternalID: "usr-lou", DisplayName: "Lou Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := func(sub, oid, name string) func() map[string]any {
		return func() map[string]any {
			c := map[string]any{"sub": sub, "name": name}
			if oid != "" {
				c["oid"] = oid
			}
			return c
		}
	}
	inesClaims, jonClaims, louClaims := claims("usr-ines", "idp-ines", "Ines Canary"), claims("usr-jon", "", "Jon Canary"), claims("usr-lou", "idp-lou", "Lou Canary")
	auditEvents := func() int {
		t.Helper()
		var n int
		if err := database.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_events").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	for _, tt := range []struct {
		name, method, reason string
		principal            *uuid.UUID
		attempt              func()
	}{
		{"an inactive person, at the callback", "oidc", "inactive", &ines.ID, func() { browserSignIn(t, counted, idp, clk, inesClaims()) }},
		{"no external ID, at the callback", "oidc", "no_external_id", nil, func() { browserSignIn(t, counted, idp, clk, jonClaims()) }},
		{"another external ID, at the callback", "oidc", "external_id_conflict", &lou.ID, func() { browserSignIn(t, counted, idp, clk, louClaims()) }},
		{"an ID token of the CLI, at the callback", "oidc", "invalid_token", nil, func() {
			cookie, state, _ := initiateLogin(t, counted, "/")
			idp.customToken = exchangeToken(idp, clk, inesClaims())
			callback("code=mock-code&state="+url.QueryEscape(state), cookie)
		}},
		{"no state cookie, at the callback", "oidc", "invalid_request", nil, func() { callback("code=mock-code&state=forged") }},
		{"the provider's error, at the callback", "oidc", "provider_error", nil, func() {
			cookie, state, _ := initiateLogin(t, counted, "/")
			callback("error=access_denied&state="+url.QueryEscape(state), cookie)
		}},
		{"an inactive person, at the exchange", "token_exchange", "inactive", &ines.ID, func() { _, _ = counted.ExchangeIDToken(ctx, exchangeToken(idp, clk, inesClaims())) }},
		{"no external ID, at the exchange", "token_exchange", "no_external_id", nil, func() { _, _ = counted.ExchangeIDToken(ctx, exchangeToken(idp, clk, jonClaims())) }},
		{"an ID token that does not verify, at the exchange", "token_exchange", "invalid_token", nil, func() { _, _ = counted.ExchangeIDToken(ctx, "not-an-id-token") }},
		{"a wrong credential, at break-glass", "breakglass", "invalid_credential", nil, func() { useBreakglass(`{"credential":"wt_bg_not-the-credential"}`) }},
		{"no credential, at break-glass", "breakglass", "invalid_request", nil, func() { useBreakglass(`{}`) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before, recorded, count := len(logs.records(t, "refusing a sign-in")), auditEvents(), signInCount(t, reg, tt.method, tt.reason)
			tt.attempt()
			refusals := logs.records(t, "refusing a sign-in")
			if len(refusals) != before+1 {
				t.Fatalf("%d refusals logged, want one", len(refusals)-before)
			}
			r := refusals[before]
			if r["level"] != "WARN" || r["method"] != tt.method || r["reason"] != tt.reason {
				t.Errorf("the refusal logs %v, want the method %s and the reason %s", r, tt.method, tt.reason)
			}
			if id, logged := r["principal_id"]; (tt.principal == nil && logged) || (tt.principal != nil && id != tt.principal.String()) {
				t.Errorf("the refusal logs the principal %v, want %v", id, tt.principal)
			}
			if n := signInCount(t, reg, tt.method, tt.reason); n != count+1 {
				t.Errorf("%v sign-ins counted with the result %s, want %v", n, tt.reason, count+1)
			}
			if n := auditEvents(); n != recorded {
				t.Errorf("%d audit events written, want none", n-recorded)
			}
		})
	}

	// Kai signs in, from a browser and from the CLI, and the custodian
	// through break-glass: each counts once as a success, and logs no
	// refusal.
	refused := len(logs.records(t, "refusing a sign-in"))
	kai := func() map[string]any {
		return map[string]any{"sub": "usr-kai", "oid": "idp-kai", "name": "Kai Canary", "groups": []string{"wt-owners"}}
	}
	if rec := browserSignIn(t, counted, idp, clk, kai()); rec.Code != http.StatusFound {
		t.Errorf("Kai's sign-in: got %d %q, want 302", rec.Code, rec.Body.String())
	}
	if _, err := counted.ExchangeIDToken(ctx, exchangeToken(idp, clk, kai())); err != nil {
		t.Errorf("Kai's exchange: %v", err)
	}
	if code := useBreakglass(`{"credential":"` + rawCred + `"}`); code != http.StatusOK {
		t.Errorf("break-glass: got %d, want 200", code)
	}
	for _, method := range []string{"oidc", "token_exchange", "breakglass"} {
		if n := signInCount(t, reg, method, "success"); n != 1 {
			t.Errorf("%v successes of %s counted, want 1", n, method)
		}
	}

	// A failure of the provider counts as an error, which the log already
	// says, and is no refusal.
	idp.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
	cookie, state, _ := initiateLogin(t, counted, "/")
	if code := callback("code=mock-code&state="+url.QueryEscape(state), cookie); code != http.StatusBadGateway {
		t.Errorf("a callback whose code the provider cannot exchange: got %d, want 502", code)
	}
	if n := signInCount(t, reg, "oidc", "error"); n != 1 {
		t.Errorf("%v errors counted, want 1", n)
	}
	if n := len(logs.records(t, "refusing a sign-in")); n != refused {
		t.Errorf("%d refusals logged for successes and failures, want none", n-refused)
	}

	// The fourth attempt at break-glass is over its rate.
	if code := useBreakglass(`{"credential":"` + rawCred + `"}`); code != http.StatusTooManyRequests {
		t.Errorf("break-glass over its rate: got %d, want 429", code)
	}
	if refusals := logs.records(t, "refusing a sign-in"); len(refusals) != refused+1 || refusals[refused]["reason"] != "rate_limited" {
		t.Errorf("the refusals after the rate limit: %v, want one more, rate_limited", refusals[refused:])
	}
	if n := signInCount(t, reg, "breakglass", "rate_limited"); n != 1 {
		t.Errorf("%v sign-ins counted over the rate, want 1", n)
	}

	logged := logs.buf.String()
	for _, v := range []string{"usr-ines", "idp-ines", "Ines Canary", "usr-jon", "Jon Canary", "idp-lou", "Lou Canary", "not-an-id-token", "not-the-credential", rawCred} {
		if strings.Contains(logged, v) {
			t.Errorf("the log holds %q", v)
		}
	}
}
