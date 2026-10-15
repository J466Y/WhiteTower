package authn_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

// Security test ST-20: A break-glass session can halt agents and the fleet and read, and nothing else: not release, not change anything; it expires after one hour; attempts are rate-limited; each use raises the critical event and the alert
func TestBreakglassEmergencyAccess(t *testing.T) {
	startTime := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	clk := clocktest.New(startTime)

	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)

	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(cat, clk)

	authenticator := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, nil)
	authorizer := authz.NewAuthorizer()

	// 1. Generate credential and write hash file (without IdP running)
	rawCred, hashStr, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatalf("generating breakglass credential: %v", err)
	}
	if !strings.HasPrefix(rawCred, authn.BreakglassCredentialPrefix) {
		t.Errorf("expected credential prefix %q, got %q", authn.BreakglassCredentialPrefix, rawCred)
	}
	if !authn.VerifyCredential(hashStr, rawCred) {
		t.Fatal("VerifyCredential failed for freshly generated credential")
	}
	if authn.VerifyCredential(hashStr, "wrong-credential") {
		t.Fatal("VerifyCredential succeeded for wrong credential")
	}

	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	if err := os.WriteFile(hashFile, []byte(hashStr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Capture log entries to verify alert emission
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Limit to 5 attempts per minute (ST-20, ST-22)
	limiter := ratelimit.New(5.0/60.0, 5)

	svc := authn.NewBreakglassService(authn.BreakglassOptions{
		Enabled:            true,
		CredentialHashFile: hashFile,
		SecureCookies:      false,
		Clock:              clk,
		Logger:             logger,
		Limiter:            limiter,
	}, database, sessionStore, writer)

	// 2. Test rate limiting on failed and valid attempts (ST-20, ST-22)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"credential":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.10:12345"
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 Unauthorized, got %d", i+1, rec.Code)
		}
	}
	// 6th attempt within the same minute from the same IP must be rejected with 429
	{
		req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"credential":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.10:12345"
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 Too Many Requests after rate limit exhaustion, got %d", rec.Code)
		}
		if retryAfter := rec.Header().Get("Retry-After"); retryAfter == "" {
			t.Error("expected Retry-After header on 429 response")
		}
	}

	// 3. Successful login from a different IP (or after reset)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"credential":"`+rawCred+`"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.RemoteAddr = "192.0.2.20:54321"
	loginRec := httptest.NewRecorder()
	svc.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on valid break-glass login, got %d: %s\nLogs:\n%s", loginRec.Code, loginRec.Body.String(), logBuf.String())
	}

	// Verify session cookie was set with 1 hour expiry (ST-20)
	cookies := loginRec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == authn.CookieNameInsecure {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie in response")
	}
	if sessionCookie.MaxAge > int(time.Hour.Seconds()) || sessionCookie.MaxAge <= 0 {
		t.Errorf("expected session cookie max-age <= 3600s, got %d", sessionCookie.MaxAge)
	}

	// 4. Verify critical audit event whitetower.breakglass.used.v1 was emitted
	ctx := context.Background()
	var eventCount int
	err = database.QueryRow(ctx, "SELECT COUNT(*) FROM whitetower.audit_events WHERE type = 'whitetower.breakglass.used.v1' AND actor_id = $1", authn.BreakglassPrincipalID.String()).Scan(&eventCount)
	if err != nil {
		t.Fatalf("querying audit_events: %v", err)
	}
	if eventCount == 0 {
		t.Fatal("critical audit event whitetower.breakglass.used.v1 was not emitted")
	}

	// 5. Verify alert was logged at ERROR level (ST-20)
	if !strings.Contains(logBuf.String(), "SECURITY ALERT: break-glass emergency credential used") {
		t.Errorf("expected security alert in logs, got:\n%s", logBuf.String())
	}

	// 6. Authenticate request using session cookie and evaluate permissions
	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	authReq.AddCookie(sessionCookie)
	principal, err := authenticator.Authenticate(authReq)
	if err != nil {
		t.Fatalf("authenticating with break-glass session cookie: %v", err)
	}
	if principal == nil {
		t.Fatal("expected principal from break-glass session, got nil")
	}
	if principal.ID != authn.BreakglassPrincipalID.String() {
		t.Errorf("principal ID: got %q, want %q", principal.ID, authn.BreakglassPrincipalID.String())
	}
	if !principal.IsBreakglass {
		t.Error("expected principal.IsBreakglass to be true")
	}

	// 7. Test permission matrix enforcement (ST-20):
	// A break-glass session can halt agents and the fleet and read, and nothing else.
	allowedOps := []string{
		"haltAgent",
		"haltFleet",
		"getMe",
		"listAgents",
		"getAgent",
		"getAuditEvents",
		"getAuditCheckpoints",
		"exportAudit",
	}
	for _, op := range allowedOps {
		if err := authorizer.Authorize(ctx, principal, op); err != nil {
			t.Errorf("operation %q: expected ALLOWED for break-glass, got %v", op, err)
		}
	}

	forbiddenOps := []string{
		"requestHaltRelease",
		"approveHaltRelease",
		"activateAgent",
		"proposeAgent",
		"editAgent",
		"suspendAgent",
		"reinstateAgent",
		"retireAgent",
		"manageSettings",
		"manageModules",
		"createToken",
		"revokeToken",
		"createServiceAccount",
		"authorGlobalPolicy",
		"approveGlobalPolicy",
	}
	for _, op := range forbiddenOps {
		if err := authorizer.Authorize(ctx, principal, op); err == nil {
			t.Errorf("operation %q: expected REFUSED (forbidden) for break-glass, got allowed", op)
		}
	}

	// 8. Test 1-hour expiry (ST-20)
	// After advancing 61 minutes, the session must be expired
	clk.Advance(61 * time.Minute)

	expiredReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	expiredReq.AddCookie(sessionCookie)
	_, err = authenticator.Authenticate(expiredReq)
	if err == nil {
		t.Error("expected authentication to fail for expired break-glass session after 1 hour")
	}
}
