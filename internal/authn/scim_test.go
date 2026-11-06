package authn_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/J466Y/WhiteTower/internal/audit"
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
			"externalId": "idp-olivia",
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
		authReq.AddCookie(sessionStore.CookieForSession(session))
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
			"externalId": "idp-bob",
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
		bobAuthReq.AddCookie(sessionStore.CookieForSession(bobSession))
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

// scimClient returns a function that calls the SCIM service of principals with
// its token, and returns the answer.
func scimClient(t *testing.T, principals *authn.PrincipalStore) func(method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "scim.token")
	if err := os.WriteFile(tokenFile, []byte("scim-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc, err := authn.NewSCIMService(authn.SCIMOptions{Enabled: true, TokenFile: tokenFile}, principals)
	if err != nil {
		t.Fatal(err)
	}
	return func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer scim-test-token")
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		return rec
	}
}

// scimList is the part of a SCIM list response that the tests read.
type scimList struct {
	TotalResults int `json:"totalResults"`
	Resources    []struct {
		ID         string `json:"id"`
		UserName   string `json:"userName"`
		ExternalID string `json:"externalId"`
		Active     bool   `json:"active"`
	} `json:"Resources"`
}

// decodeSCIMList decodes the list response of rec.
func decodeSCIMList(t *testing.T, rec *httptest.ResponseRecorder) scimList {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("the list: got %d %q, want 200", rec.Code, rec.Body.String())
	}
	var list scimList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	return list
}

// breakglassSignIn signs in through svc with credential, and returns the
// session token that it sets.
func breakglassSignIn(t *testing.T, svc *authn.BreakglassService, credential string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"credential":"`+credential+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("break-glass: got %d %q, want 200", rec.Code, rec.Body.String())
	}
	return sessionToken(t, rec)
}

// Security test ST-21: SCIM reaches people only. The break-glass custodian, a
// service account and SCIM's own principal are not found through a read, the
// list, a filter, a patch or a deletion, and break-glass still works after a
// SCIM client tried to deactivate the custodian (KIL-08, HUM-06; threat
// model T-18)
func TestSCIMReachesOnlyPeople(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	scim := scimClient(t, principalStore)
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

	// Break-glass's first use creates the custodian's principal.
	breakglassSignIn(t, breakglass, rawCred)
	email := "olga@example.test"
	olga, err := principalStore.SignIn(ctx, "oidc", authn.Identity{
		Issuer: "https://idp.example.com", Subject: "sub-olga", ExternalID: "sub-olga", DisplayName: "Olga Owner", Email: &email, Groups: []string{"wt-auditors"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	saEmail := "export@example.test"
	sa, err := principalStore.CreateServiceAccount(ctx, "Nightly export", &saEmail, []string{"auditor"},
		auth.Principal{ID: olga.ID.String(), Kind: auth.Human, Roles: []string{"auditor"}})
	if err != nil {
		t.Fatal(err)
	}
	// SCIM's own principal is no row: one with its ID stays out of reach too.
	if _, err := database.Exec(ctx, `INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name)
		VALUES ($1, 'human', 'whitetower:scim', 'scim-provisioner', 'SCIM Provisioner')`, authn.SCIMPrincipalID); err != nil {
		t.Fatal(err)
	}

	deactivate := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	unreachable := map[string]uuid.UUID{
		"the custodian":     authn.BreakglassPrincipalID,
		"a service account": sa.ID,
		"SCIM's principal":  authn.SCIMPrincipalID,
	}
	for name, id := range unreachable {
		for _, call := range []struct{ method, body string }{
			{http.MethodGet, ""}, {http.MethodPatch, deactivate}, {http.MethodDelete, ""},
		} {
			if rec := scim(call.method, "/scim/v2/Users/"+id.String(), call.body); rec.Code != http.StatusNotFound {
				t.Errorf("%s of %s: got %d %q, want 404", call.method, name, rec.Code, rec.Body.String())
			}
		}
		if p, err := principalStore.GetByID(ctx, id); err != nil || p.Status != "active" {
			t.Errorf("%s after SCIM's calls: %+v, %v, want it active", name, p, err)
		}
	}

	list := decodeSCIMList(t, scim(http.MethodGet, "/scim/v2/Users", ""))
	if len(list.Resources) != 1 || list.Resources[0].ID != olga.ID.String() || list.TotalResults != 1 {
		t.Errorf("the list: %+v, want olga alone", list)
	}
	for _, userName := range []string{"custodian", "scim-provisioner", saEmail} {
		filtered := decodeSCIMList(t, scim(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "`+userName+`"`), ""))
		if filtered.TotalResults != 0 || len(filtered.Resources) != 0 {
			t.Errorf("the filter on %q: %+v, want nothing", userName, filtered)
		}
	}

	token := breakglassSignIn(t, breakglass, rawCred)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: authn.CookieName, Value: token})
	if p, err := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, nil).Authenticate(req); err != nil || p == nil || !p.IsBreakglass {
		t.Errorf("a break-glass session after SCIM's calls: %+v, %v, want it to work", p, err)
	}
}

// checkSCIMError fails the test unless rec is a SCIM error with the status and
// scimType given, whose detail holds detail.
func checkSCIMError(t *testing.T, rec *httptest.ResponseRecorder, status int, scimType, detail string) {
	t.Helper()
	var e struct {
		ScimType string `json:"scimType"`
		Detail   string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || rec.Code != status || e.ScimType != scimType || !strings.Contains(e.Detail, detail) {
		t.Errorf("got %d %q, want %d %s with %q", rec.Code, rec.Body.String(), status, scimType, detail)
	}
}

// SCIM supports one filter, userName eq, which matches the userName that SCIM
// gave a user, and refuses every other rather than answering with every user.
func TestSCIMRefusesTheFiltersItDoesNotSupport(t *testing.T) {
	clk := clocktest.New(testEpoch)
	_, principalStore, _, _ := setupAuthn(t, clk)
	scim := scimClient(t, principalStore)
	created := scim(http.MethodPost, "/scim/v2/Users", `{"externalId":"idp-ruth","userName":"ruth@example.test"}`)
	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &user); err != nil || created.Code != http.StatusCreated {
		t.Fatalf("the creation: got %d %q, want 201", created.Code, created.Body.String())
	}

	for _, filter := range []string{
		`emails.value eq "ruth@example.test"`,
		`externalId eq "idp-ruth"`,
		`userName eq "nobody@example.test" or userName eq "ruth@example.test"`,
		`userName sw "ruth"`,
		`userName eq ruth@example.test`,
		`userName eq "ruth@example.test`,
	} {
		checkSCIMError(t, scim(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(filter), ""), http.StatusBadRequest, "invalidFilter", "userName eq")
	}
	for _, filter := range []string{`userName eq "ruth@example.test"`, `USERNAME EQ "ruth@example.test"`, "userName eq \"ruth\\u0040example.test\""} {
		found := decodeSCIMList(t, scim(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(filter), ""))
		if found.TotalResults != 1 || len(found.Resources) != 1 || found.Resources[0].ID != user.ID {
			t.Errorf("the filter %s: %+v, want the user", filter, found)
		}
	}
}

// SCIM compares userNames without regard to case, as RFC 7643 says (section
// 4.1.1): the filter finds a user whatever the case of the userName it is
// given, and a userName that differs from a user's only in case is one that
// exists, refused through the handler, whether it would create a principal or
// adopt one, through the store and in the database, with nothing created or
// recorded. A user keeps the userName as SCIM gave it.
func TestSCIMComparesUserNamesWithoutRegardToCase(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	_, principalStore, _, database := setupAuthn(t, clk)
	scim := scimClient(t, principalStore)
	const userName = "Ruth.Canary@Example.test"
	user := decodeSCIMUser(t, createSCIMUser(scim, "idp-ruth", userName))
	if user.UserName != userName {
		t.Errorf("the userName %q, want %q as SCIM gave it", user.UserName, userName)
	}
	for _, asked := range []string{userName, "ruth.canary@example.test", "RUTH.CANARY@EXAMPLE.TEST"} {
		found := decodeSCIMList(t, scim(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "`+asked+`"`), ""))
		if found.TotalResults != 1 || len(found.Resources) != 1 || found.Resources[0].ID != user.ID || found.Resources[0].UserName != userName {
			t.Errorf("the filter on %q: %+v, want the user, with its userName as given", asked, found)
		}
	}

	// A person who signed in first, whom SCIM would adopt under the userName.
	if _, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-una", ExternalID: "idp-una", DisplayName: "Una Canary"}, nil); err != nil {
		t.Fatal(err)
	}
	created := len(eventsOf(t, database, principalCreated))
	checkSCIMError(t, createSCIMUser(scim, "idp-new", "ruth.canary@example.test"), http.StatusConflict, "uniqueness", "userName")
	checkSCIMError(t, createSCIMUser(scim, "idp-una", "RUTH.CANARY@example.test"), http.StatusConflict, "uniqueness", "userName")
	if _, err := principalStore.ProvisionHuman(ctx, authn.Identity{Subject: "ruth.CANARY@example.test", ExternalID: "idp-vic", DisplayName: "Vic Canary"}, true); !errors.Is(err, authn.ErrPrincipalExists) {
		t.Errorf("the store's creation of the userName in another case: %v, want ErrPrincipalExists", err)
	}
	_, err := database.Exec(ctx, `INSERT INTO whitetower.principals (id, kind, issuer, subject, display_name) VALUES ($1, 'human', 'scim', 'RUTH.CANARY@EXAMPLE.TEST', 'Ruth')`, uuid.New())
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); !ok || pgErr.Code != "23505" || pgErr.ConstraintName != "principals_scim_user_name" {
		t.Errorf("the database's insert of the userName in another case: %v, want a unique violation of principals_scim_user_name", err)
	}

	var scimUsers int
	if err := database.QueryRow(ctx, "SELECT count(*) FROM whitetower.principals WHERE issuer = 'scim'").Scan(&scimUsers); err != nil || scimUsers != 1 {
		t.Errorf("%d users of SCIM, %v, want one", scimUsers, err)
	}
	if n := len(eventsOf(t, database, principalCreated)); n != created {
		t.Errorf("%d creations recorded, want %d", n, created)
	}
	if n := len(eventsOf(t, database, principalAdopted)); n != 0 {
		t.Errorf("%d adoptions recorded, want none", n)
	}
}

// Security test ST-21: a user that SCIM creates with active false is created
// inactive, in the transaction that creates it; a person who signed in first
// is adopted and deactivated in that transaction, which revokes their session.
// When the deactivation cannot be recorded, nothing is created, so that SCIM
// never leaves a user active against its request
func TestSCIMCreatesAUserInactiveInOneTransaction(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	const deactivated = "whitetower.principal.deactivated.v1"
	inactive := func(externalID, userName string) string {
		return `{"externalId":"` + externalID + `","userName":"` + userName + `","active":false}`
	}
	// recordedFor returns the events of the type given about the principal id.
	recordedFor := func(typ, id string) []recorded {
		var found []recorded
		for _, e := range eventsOf(t, database, typ) {
			if e.data["principal_id"] == id {
				found = append(found, e)
			}
		}
		return found
	}
	checkInactive := func(t *testing.T, user scimUser, record string) {
		t.Helper()
		if user.Active {
			t.Error("SCIM answered with an active user")
		}
		p, err := principalStore.GetByID(ctx, uuid.MustParse(user.ID))
		if err != nil || p.Status != "inactive" {
			t.Errorf("the principal: %+v, %v, want it inactive", p, err)
		}
		if n := len(recordedFor(record, user.ID)); n != 1 {
			t.Errorf("%d %s recorded, want 1", n, record)
		}
		events := recordedFor(deactivated, user.ID)
		if len(events) != 1 {
			t.Fatalf("%d deactivations recorded, want 1", len(events))
		}
		checkEvent(t, events[0], "service_account", authn.SCIMPrincipalID.String(), map[string]any{"reason": "SCIM initial provisioning as inactive"})
	}
	scim := scimClient(t, principalStore)

	t.Run("a new user", func(t *testing.T) {
		checkInactive(t, decodeSCIMUser(t, scim(http.MethodPost, "/scim/v2/Users", inactive("idp-wes", "wes@example.test"))), principalCreated)
	})

	t.Run("a person who signed in first", func(t *testing.T) {
		xia, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-xia", ExternalID: "idp-xia", DisplayName: "Xia Canary"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		session, err := sessionStore.Create(ctx, xia.ID, "oidc", []string{"owner"})
		if err != nil {
			t.Fatal(err)
		}
		user := decodeSCIMUser(t, scim(http.MethodPost, "/scim/v2/Users", inactive("idp-xia", "xia@example.test")))
		if user.ID != xia.ID.String() {
			t.Fatalf("SCIM created %s, want it to adopt %s", user.ID, xia.ID)
		}
		checkInactive(t, user, principalAdopted)
		if _, err := sessionStore.Get(ctx, session.Token); err == nil {
			t.Error("the person's session is still valid")
		}
	})

	t.Run("the deactivation cannot be recorded", func(t *testing.T) {
		refusing := authn.NewPrincipalStore(database, clk, refusingWriter(t, clk, deactivated), sessionStore, tokenStore)
		created := len(eventsOf(t, database, principalCreated))
		if rec := scimClient(t, refusing)(http.MethodPost, "/scim/v2/Users", inactive("idp-yan", "yan@example.test")); rec.Code != http.StatusInternalServerError {
			t.Errorf("got %d %q, want 500", rec.Code, rec.Body.String())
		}
		if p, err := principalStore.GetBySCIMUserName(ctx, "yan@example.test"); !errors.Is(err, authn.ErrPrincipalNotFound) {
			t.Errorf("the user: %+v, %v, want none", p, err)
		}
		if n := len(eventsOf(t, database, principalCreated)); n != created {
			t.Errorf("%d creations recorded, want %d", n, created)
		}
	})
}
