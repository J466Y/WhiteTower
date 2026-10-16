package authn_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
)

// Security test ST-21: SCIM refuses calls without its token; deactivations are audited and revoke sessions
func TestSCIMDeprovisioningAndSecurity(t *testing.T) {
	clk := clocktest.New(time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC))
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)

	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "scim.token")
	scimToken := "scim-secret-bearer-token-12345"
	if err := os.WriteFile(tokenFile, []byte(scimToken+"\n"), 0o600); err != nil {
		t.Fatalf("writing scim token file: %v", err)
	}

	scimSvc, err := authn.NewSCIMService(authn.SCIMOptions{
		Enabled:   true,
		TokenFile: tokenFile,
		Logger:    slog.New(slog.DiscardHandler),
	}, principalStore)
	if err != nil {
		t.Fatalf("initializing SCIMService: %v", err)
	}

	callSCIM := func(method, path string, token string, body io.Reader) *http.Response {
		req := httptest.NewRequest(method, path, body)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		scimSvc.ServeHTTP(rec, req)
		return rec.Result()
	}

	// 1. Refusal of calls without valid bearer token (ST-21, threat model T-18)
	t.Run("refuses calls without token or with invalid token", func(t *testing.T) {
		resNoToken := callSCIM(http.MethodGet, "/scim/v2/Users", "", nil)
		defer resNoToken.Body.Close()
		if resNoToken.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 without token, got %d", resNoToken.StatusCode)
		}
		if !strings.Contains(resNoToken.Header.Get("Content-Type"), "scim+json") {
			t.Errorf("expected scim+json content type, got %s", resNoToken.Header.Get("Content-Type"))
		}

		resBadToken := callSCIM(http.MethodGet, "/scim/v2/Users", "wrong-bearer-token", nil)
		defer resBadToken.Body.Close()
		if resBadToken.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 with wrong token, got %d", resBadToken.StatusCode)
		}
	})

	// 2. User provisioning via POST /scim/v2/Users
	var createdUserID string
	t.Run("provisions user via POST /scim/v2/Users", func(t *testing.T) {
		payload := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "olivia@example.com",
			"displayName": "Olivia Owner",
			"name": {
				"formatted": "Olivia Owner",
				"familyName": "Owner",
				"givenName": "Olivia"
			},
			"emails": [
				{
					"value": "olivia@example.com",
					"type": "work",
					"primary": true
				}
			],
			"active": true
		}`
		res := callSCIM(http.MethodPost, "/scim/v2/Users", scimToken, strings.NewReader(payload))
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 201 Created, got %d: %s", res.StatusCode, string(body))
		}
		loc := res.Header.Get("Location")
		if !strings.HasPrefix(loc, "/scim/v2/Users/") {
			t.Errorf("expected Location header to start with /scim/v2/Users/, got %q", loc)
		}

		var user map[string]any
		if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
			t.Fatalf("decoding response: %v", err)
		}
		if user["userName"] != "olivia@example.com" {
			t.Errorf("userName %v, want olivia@example.com", user["userName"])
		}
		if user["active"] != true {
			t.Errorf("active %v, want true", user["active"])
		}
		createdUserID = user["id"].(string)

		// Duplicate userName returns 409 Conflict
		resDup := callSCIM(http.MethodPost, "/scim/v2/Users", scimToken, strings.NewReader(payload))
		defer resDup.Body.Close()
		if resDup.StatusCode != http.StatusConflict {
			t.Errorf("expected 409 Conflict for duplicate user, got %d", resDup.StatusCode)
		}
	})

	// 3. User lookup by ID and list with filter
	t.Run("queries user by ID and filter", func(t *testing.T) {
		resGet := callSCIM(http.MethodGet, "/scim/v2/Users/"+createdUserID, scimToken, nil)
		defer resGet.Body.Close()
		if resGet.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resGet.StatusCode)
		}

		// List with matching filter
		resFilter := callSCIM(http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20"olivia@example.com"`, scimToken, nil)
		defer resFilter.Body.Close()
		if resFilter.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resFilter.StatusCode)
		}
		var listResp map[string]any
		_ = json.NewDecoder(resFilter.Body).Decode(&listResp)
		if int(listResp["totalResults"].(float64)) != 1 {
			t.Errorf("expected totalResults 1, got %v", listResp["totalResults"])
		}

		// List with non-matching filter
		resNoMatch := callSCIM(http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20"nobody@example.com"`, scimToken, nil)
		defer resNoMatch.Body.Close()
		var noMatchResp map[string]any
		_ = json.NewDecoder(resNoMatch.Body).Decode(&noMatchResp)
		if int(noMatchResp["totalResults"].(float64)) != 0 {
			t.Errorf("expected totalResults 0, got %v", noMatchResp["totalResults"])
		}
	})

	// 4. Deprovisioning via PATCH active: false revokes sessions and tokens, and emits audit event (ST-21)
	t.Run("deprovisioning via PATCH active=false audits and revokes sessions", func(t *testing.T) {
		userUUID := uuid.MustParse(createdUserID)
		ctx := context.Background()

		// Create an active session and token for Olivia
		session, err := sessionStore.Create(ctx, userUUID, "oidc", []string{"owner"})
		if err != nil {
			t.Fatalf("creating session: %v", err)
		}

		createdToken, err := tokenStore.Create(ctx, userUUID, "Olivia PAT", []string{"inventory.view"}, 30, auth.Principal{
			ID:    createdUserID,
			Kind:  auth.Human,
			Name:  "Olivia Owner",
			Roles: []string{"owner"},
		})
		if err != nil {
			t.Fatalf("creating api token: %v", err)
		}

		// Verify session and token are active before deprovisioning
		authReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		authReq.AddCookie(sessionStore.CookieForSession(session, false))
		authenticator := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, nil)
		p, err := authenticator.Authenticate(authReq)
		if err != nil || p == nil {
			t.Fatalf("authenticating session before deprovisioning: %v", err)
		}

		// Execute SCIM PATCH deprovisioning (active: false)
		patchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{
					"op": "replace",
					"path": "active",
					"value": false
				}
			]
		}`
		resPatch := callSCIM(http.MethodPatch, "/scim/v2/Users/"+createdUserID, scimToken, strings.NewReader(patchBody))
		defer resPatch.Body.Close()
		if resPatch.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resPatch.Body)
			t.Fatalf("expected 200 OK from PATCH, got %d: %s", resPatch.StatusCode, string(body))
		}

		// Verify user status in DB is inactive
		principal, err := principalStore.GetByID(ctx, userUUID)
		if err != nil {
			t.Fatalf("fetching principal: %v", err)
		}
		if principal.Status != "inactive" {
			t.Errorf("expected principal status inactive, got %s", principal.Status)
		}

		// Verify session is revoked and cannot authenticate (ST-21)
		pAfter, err := authenticator.Authenticate(authReq)
		if err == nil && pAfter != nil {
			t.Fatalf("expected authentication to be refused after deprovisioning, got %v", pAfter)
		}

		// Verify API token is revoked
		tokenReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		tokenReq.Header.Set("Authorization", "Bearer "+createdToken.Token)
		pTokAfter, err := authenticator.Authenticate(tokenReq)
		if err == nil && pTokAfter != nil {
			t.Fatalf("expected api token to be refused after deprovisioning, got %v", pTokAfter)
		}

		// Verify critical audit event whitetower.principal.deactivated.v1 was emitted
		var eventCount int
		err = database.QueryRow(ctx, "SELECT COUNT(*) FROM whitetower.audit_events WHERE type = 'whitetower.principal.deactivated.v1' AND convert_from(canonical, 'UTF8') LIKE '%' || $1 || '%'", createdUserID).Scan(&eventCount)
		if err != nil {
			t.Fatalf("querying audit_events: %v", err)
		}
		if eventCount == 0 {
			t.Fatal("expected whitetower.principal.deactivated.v1 audit event to be emitted")
		}

		// Verify actor in audit record is SCIM provisioner
		var actorID, actorType string
		err = database.QueryRow(ctx, "SELECT actor_id, actor_type FROM whitetower.audit_events WHERE type = 'whitetower.principal.deactivated.v1' AND convert_from(canonical, 'UTF8') LIKE '%' || $1 || '%'", createdUserID).Scan(&actorID, &actorType)
		if err != nil {
			t.Fatalf("querying audit actor: %v", err)
		}
		if actorType != "service_account" || actorID != authn.SCIMPrincipalID.String() {
			t.Errorf("expected actor service_account/%s, got %s/%s", authn.SCIMPrincipalID.String(), actorType, actorID)
		}
	})

	// 5. Delete as deactivation (Step 8, ST-21)
	t.Run("delete as deactivation", func(t *testing.T) {
		// Provision Bob
		bobPayload := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "bob@example.test",
			"displayName": "Bob Builder",
			"active": true
		}`
		resBob := callSCIM(http.MethodPost, "/scim/v2/Users", scimToken, strings.NewReader(bobPayload))
		defer resBob.Body.Close()
		if resBob.StatusCode != http.StatusCreated {
			t.Fatalf("failed to create bob: %d", resBob.StatusCode)
		}
		var bobUser map[string]any
		_ = json.NewDecoder(resBob.Body).Decode(&bobUser)
		bobID := bobUser["id"].(string)
		bobUUID := uuid.MustParse(bobID)

		ctx := context.Background()
		bobSession, err := sessionStore.Create(ctx, bobUUID, "oidc", []string{"operator"})
		if err != nil {
			t.Fatalf("creating session for bob: %v", err)
		}

		// Send DELETE /scim/v2/Users/{id}
		resDel := callSCIM(http.MethodDelete, "/scim/v2/Users/"+bobID, scimToken, nil)
		defer resDel.Body.Close()
		if resDel.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204 No Content, got %d", resDel.StatusCode)
		}

		// Verify Bob is inactive
		pBob, err := principalStore.GetByID(ctx, bobUUID)
		if err != nil {
			t.Fatalf("fetching bob: %v", err)
		}
		if pBob.Status != "inactive" {
			t.Errorf("expected bob status inactive, got %s", pBob.Status)
		}

		// Verify Bob's session was revoked
		bobAuthReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		bobAuthReq.AddCookie(sessionStore.CookieForSession(bobSession, false))
		authenticator := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, nil)
		if p, err := authenticator.Authenticate(bobAuthReq); err == nil && p != nil {
			t.Fatalf("expected bob's session to be revoked, got %v", p)
		}

		// Verify audit event was emitted for bob
		var bobEvents int
		err = database.QueryRow(ctx, "SELECT COUNT(*) FROM whitetower.audit_events WHERE type = 'whitetower.principal.deactivated.v1' AND convert_from(canonical, 'UTF8') LIKE '%' || $1 || '%'", bobID).Scan(&bobEvents)
		if err != nil {
			t.Fatalf("querying audit events for bob: %v", err)
		}
		if bobEvents == 0 {
			t.Fatal("expected audit event for bob deactivation")
		}
	})

	// 6. Reactivation via PATCH active: true
	t.Run("reactivates user via PATCH active=true", func(t *testing.T) {
		patchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{
					"op": "replace",
					"path": "active",
					"value": true
				}
			]
		}`
		resPatch := callSCIM(http.MethodPatch, "/scim/v2/Users/"+createdUserID, scimToken, strings.NewReader(patchBody))
		defer resPatch.Body.Close()
		if resPatch.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resPatch.Body)
			t.Fatalf("expected 200 OK from PATCH, got %d: %s", resPatch.StatusCode, string(body))
		}

		userUUID := uuid.MustParse(createdUserID)
		principal, err := principalStore.GetByID(context.Background(), userUUID)
		if err != nil {
			t.Fatalf("fetching principal: %v", err)
		}
		if principal.Status != "active" {
			t.Errorf("expected principal status active, got %s", principal.Status)
		}
	})
}
