package authn_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

// The principal that SCIM provisions and the one that a person signs in as
// are one, matched by the external ID that the identity provider gives both
// (the fix of 2026-11-03 in plan P1-03's progress notes).

// claimService returns an OIDC service of the mock provider that has
// discovered it, takes the person's external ID from the claim given, logs to
// logs, maps wt-owners to owner and exchanges ID tokens.
func claimService(t *testing.T, idp *mockIDP, clk *clocktest.Fake, principals *authn.PrincipalStore, sessions *authn.SessionStore, tokens *authn.TokenStore, claim string, logs io.Writer) *authn.OIDCService {
	t.Helper()
	return newService(t, authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          "whitetower-console",
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		Logger:            slog.New(slog.NewJSONHandler(logs, nil)),
		RoleMapping:       map[string]string{"wt-owners": "owner"},
		AllowedAlgorithms: []string{"RS256"},
		ExternalIDClaim:   claim,
		Tokens:            tokens,
	}, principals, sessions)
}

// scimUser is the part of a SCIM user resource that the tests read.
type scimUser struct {
	ID         string `json:"id"`
	ExternalID string `json:"externalId"`
	UserName   string `json:"userName"`
	Active     bool   `json:"active"`
}

// createSCIMUser provisions a user through scim with the externalId and
// userName given, and returns the answer.
func createSCIMUser(scim func(method, target, body string) *httptest.ResponseRecorder, externalID, userName string) *httptest.ResponseRecorder {
	return scim(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"`+externalID+
		`","userName":"`+userName+`","displayName":"Ruth Canary","emails":[{"value":"ruth@example.test","primary":true}]}`)
}

// decodeSCIMUser decodes the user of rec, which must have the status given.
func decodeSCIMUser(t *testing.T, rec *httptest.ResponseRecorder, status int) scimUser {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("got %d %q, want %d", rec.Code, rec.Body.String(), status)
	}
	var user scimUser
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	return user
}

// scimDeactivate is the patch with which an identity provider deprovisions a
// user.
const scimDeactivate = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`

// countPrincipals returns how many human principals there are.
func countPrincipals(t *testing.T, database *db.DB) int {
	t.Helper()
	var n int
	if err := database.QueryRow(context.Background(), "SELECT count(*) FROM whitetower.principals WHERE kind = 'human'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Security test ST-21: a person whom SCIM provisions signs in, from a browser
// and from the CLI, as the principal that SCIM created, matched by the
// external ID that the identity provider sends to both, with the claim sub or
// oid; SCIM's deactivation then revokes their session and their tokens, and
// refuses their next sign-in
func TestSCIMAndSignInShareOnePrincipal(t *testing.T) {
	for _, tt := range []struct {
		claim string
		// The ID tokens of the console's client and of the CLI's: Entra ID
		// gives each client another sub, and the same oid.
		browser, cli map[string]any
	}{
		{"sub", map[string]any{"sub": "idp-ruth"}, map[string]any{"sub": "idp-ruth"}},
		{"oid", map[string]any{"sub": "console-sub-ruth", "oid": "idp-ruth"}, map[string]any{"sub": "cli-sub-ruth", "oid": "idp-ruth"}},
	} {
		t.Run(tt.claim, func(t *testing.T) {
			ctx := context.Background()
			idp := newMockIDP(t)
			clk := clocktest.New(testEpoch)
			sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
			svc := claimService(t, idp, clk, principalStore, sessionStore, tokenStore, tt.claim, io.Discard)
			scim := scimClient(t, principalStore)
			// Each sign-in gets its own claims: signing an ID token adds to them.
			claims := func(token map[string]any) map[string]any {
				c := maps.Clone(token)
				c["name"], c["email"], c["groups"] = "Ruth Canary", "ruth@example.test", []string{"wt-owners"}
				return c
			}

			user := decodeSCIMUser(t, createSCIMUser(scim, "idp-ruth", "ruth@example.test"), http.StatusCreated)
			if user.ExternalID != "idp-ruth" {
				t.Errorf("the user's externalId is %q, want idp-ruth", user.ExternalID)
			}

			session := sessionToken(t, browserSignIn(t, svc, idp, clk, claims(tt.browser)))
			if s, err := sessionStore.Get(ctx, session); err != nil || s.PrincipalID.String() != user.ID {
				t.Fatalf("the browser's session: %+v, %v, want one of SCIM's user %s", s, err, user.ID)
			}
			token, err := svc.ExchangeIDToken(ctx, exchangeToken(idp, clk, claims(tt.cli)))
			if err != nil || token.PrincipalID.String() != user.ID {
				t.Fatalf("the CLI's token: %+v, %v, want one of SCIM's user %s", token, err, user.ID)
			}
			if n := countPrincipals(t, database); n != 1 {
				t.Errorf("%d principals, want SCIM's alone", n)
			}

			if rec := scim(http.MethodPatch, "/scim/v2/Users/"+user.ID, scimDeactivate); rec.Code != http.StatusOK {
				t.Fatalf("the deactivation: got %d %q", rec.Code, rec.Body.String())
			}
			authenticator := authn.NewAuthenticator(sessionStore, principalStore, tokenStore, nil)
			byCookie := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			byCookie.AddCookie(&http.Cookie{Name: authn.CookieName, Value: session})
			if p, err := authenticator.Authenticate(byCookie); err == nil || p != nil {
				t.Errorf("the session after the deactivation: %+v, %v, want it refused", p, err)
			}
			byToken := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			byToken.Header.Set("Authorization", "Bearer "+token.Token)
			if p, err := authenticator.Authenticate(byToken); err == nil || p != nil {
				t.Errorf("the token after the deactivation: %+v, %v, want it refused", p, err)
			}
			if rec := browserSignIn(t, svc, idp, clk, claims(tt.browser)); rec.Code != http.StatusForbidden {
				t.Errorf("a sign-in after the deactivation: got %d %q, want 403", rec.Code, rec.Body.String())
			}
			if _, err := svc.ExchangeIDToken(ctx, exchangeToken(idp, clk, claims(tt.cli))); !errors.Is(err, authn.ErrPrincipalInactive) {
				t.Errorf("an exchange after the deactivation: %v, want ErrPrincipalInactive", err)
			}
		})
	}
}

// A person who signed in before SCIM provisioned them keeps their principal:
// SCIM adopts it, sets its userName and attributes on it, answers with its
// ID, and records the adoption, not a creation. Its groups, last login and
// sessions stay, the person's next sign-in finds it, and SCIM finds it by its
// userName and deactivates it.
func TestSCIMAdoptsThePrincipalOfAPersonWhoSignedInFirst(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	svc := claimService(t, idp, clk, principalStore, sessionStore, tokenStore, "oid", io.Discard)
	scim := scimClient(t, principalStore)
	claims := func() map[string]any {
		return map[string]any{"sub": "console-sub-ruth", "oid": "idp-ruth", "name": "Ruth Canary", "email": "ruth@example.test", "groups": []string{"wt-owners"}}
	}

	session := sessionToken(t, browserSignIn(t, svc, idp, clk, claims()))
	signedIn, err := principalStore.GetByIdentity(ctx, idp.server.URL, "console-sub-ruth")
	if err != nil {
		t.Fatal(err)
	}

	user := decodeSCIMUser(t, createSCIMUser(scim, "idp-ruth", "ruth.canary@example.test"), http.StatusCreated)
	if user.ID != signedIn.ID.String() || user.UserName != "ruth.canary@example.test" || !user.Active {
		t.Fatalf("SCIM's user %+v, want the principal %s that the sign-in created, with SCIM's userName", user, signedIn.ID)
	}
	adopted, err := principalStore.GetByID(ctx, signedIn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if *adopted.Issuer != "scim" || *adopted.Subject != "ruth.canary@example.test" || *adopted.ExternalID != "idp-ruth" ||
		adopted.Status != "active" || !reflect.DeepEqual(adopted.IDPGroups, signedIn.IDPGroups) || !adopted.LastLoginAt.Equal(*signedIn.LastLoginAt) {
		t.Errorf("the adopted principal %+v, want SCIM's issuer and userName, with the external ID, status, groups and last login it had", adopted)
	}
	if n := countPrincipals(t, database); n != 1 {
		t.Errorf("%d principals, want one", n)
	}
	if n := len(eventsOf(t, database, principalCreated)); n != 1 {
		t.Errorf("%d creations recorded, want the sign-in's alone", n)
	}
	recordedAdoptions := eventsOf(t, database, principalAdopted)
	if len(recordedAdoptions) != 1 {
		t.Fatalf("%d adoptions recorded, want 1", len(recordedAdoptions))
	}
	checkEvent(t, recordedAdoptions[0], "service_account", authn.SCIMPrincipalID.String(), map[string]any{"principal_id": signedIn.ID})
	if _, err := sessionStore.Get(ctx, session); err != nil {
		t.Errorf("the person's session after the adoption: %v, want it valid", err)
	}

	again := sessionToken(t, browserSignIn(t, svc, idp, clk, claims()))
	if s, err := sessionStore.Get(ctx, again); err != nil || s.PrincipalID != signedIn.ID {
		t.Errorf("the next sign-in's session: %+v, %v, want one of the adopted principal", s, err)
	}
	found := decodeSCIMList(t, scim(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "ruth.canary@example.test"`), ""))
	if found.TotalResults != 1 || found.Resources[0].ID != signedIn.ID.String() {
		t.Errorf("the filter on the userName: %+v, want the adopted principal", found)
	}
	if rec := scim(http.MethodPatch, "/scim/v2/Users/"+user.ID, scimDeactivate); rec.Code != http.StatusOK {
		t.Fatalf("the deactivation: got %d %q", rec.Code, rec.Body.String())
	}
	if _, err := sessionStore.Get(ctx, again); err == nil {
		t.Error("the session after SCIM's deactivation is valid, want it refused")
	}
	checkNoneHolds(t, database, "Ruth Canary", "ruth@example.test", "ruth.canary@example.test", "console-sub-ruth", "idp-ruth")
}

// A sign-in whose ID token has no external ID in the claim configured is
// refused, and creates nothing: a missing claim, one that is not a string, a
// blank one or one too long. No other claim stands in for it, sub included.
// The log names the claim, never its value.
func TestASignInWithoutAnExternalIDIsRefused(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	logs := &logBuffer{}
	svc := claimService(t, idp, clk, principalStore, sessionStore, tokenStore, "oid", logs)

	for name, oid := range map[string]any{
		"no claim":       nil,
		"a number":       42,
		"a list":         []string{"idp-sam"},
		"an empty claim": "",
		"a blank claim":  "   ",
		"too long":       strings.Repeat("x", authn.MaxExternalIDLength+1),
	} {
		t.Run(name, func(t *testing.T) {
			claims := func() map[string]any {
				c := map[string]any{"sub": "usr-sam-canary", "name": "Sam Canary"}
				if oid != nil {
					c["oid"] = oid
				}
				return c
			}
			rec := browserSignIn(t, svc, idp, clk, claims())
			if rec.Code != http.StatusForbidden {
				t.Errorf("the callback: got %d %q, want 403", rec.Code, rec.Body.String())
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == authn.CookieName {
					t.Errorf("the callback set a session cookie")
				}
			}
			if _, err := svc.ExchangeIDToken(ctx, exchangeToken(idp, clk, claims())); !errors.Is(err, authn.ErrNoExternalID) {
				t.Errorf("the exchange: %v, want ErrNoExternalID", err)
			}
		})
	}
	if n := countPrincipals(t, database); n != 0 {
		t.Errorf("%d principals, want none", n)
	}
	if n := len(eventsOf(t, database, principalCreated)); n != 0 {
		t.Errorf("%d creations recorded, want none", n)
	}
	refusals := logs.records(t, "refusing a sign-in: the ID token's external ID claim is missing, not a string, blank or too long")
	if len(refusals) != 12 {
		t.Errorf("%d refusals logged, want one per sign-in", len(refusals))
	}
	for _, r := range refusals {
		if r["claim"] != "oid" {
			t.Errorf("a refusal logs the claim %v, want oid", r["claim"])
		}
	}
	if logged := logs.buf.String(); strings.Contains(logged, "usr-sam-canary") || strings.Contains(logged, "idp-sam") || strings.Contains(logged, "Sam Canary") {
		t.Errorf("the log holds a claim's value: %s", logged)
	}
}

// The store signs in and provisions no person without an external ID, whoever
// calls it: such a principal is one that SCIM and sign-ins could not share.
func TestTheStoreRefusesAPersonWithoutAnExternalID(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	_, principalStore, _, database := setupAuthn(t, clk)
	for _, externalID := range []string{"", " ", strings.Repeat("x", authn.MaxExternalIDLength+1)} {
		if _, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-una", ExternalID: externalID, DisplayName: "Una Canary"}, nil); !errors.Is(err, authn.ErrInvalidExternalID) {
			t.Errorf("a sign-in with the external ID %q: %v, want ErrInvalidExternalID", externalID, err)
		}
		if _, err := principalStore.ProvisionHuman(ctx, authn.Identity{Subject: "una@example.test", ExternalID: externalID, DisplayName: "Una Canary"}); !errors.Is(err, authn.ErrInvalidExternalID) {
			t.Errorf("a provisioning with the external ID %q: %v, want ErrInvalidExternalID", externalID, err)
		}
	}
	if n := countPrincipals(t, database); n != 0 {
		t.Errorf("%d principals, want none", n)
	}
}

// A sign-in that finds no principal by its external ID, and finds by its
// issuer and subject a principal that holds another external ID, is refused
// and changes nothing: the identity provider names the person by another
// value than before, as when the claim configured changed.
func TestASignInOfAPrincipalWithAnotherExternalIDIsRefused(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	logs := &logBuffer{}
	svc := claimService(t, idp, clk, principalStore, sessionStore, tokenStore, "oid", logs)

	// Signed in while the external ID was the sub.
	before, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "usr-tom", ExternalID: "usr-tom", DisplayName: "Tom Canary", Groups: []string{"wt-owners"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := func() map[string]any {
		return map[string]any{"sub": "usr-tom", "oid": "idp-tom", "name": "Tom Canary", "groups": []string{"wt-admins"}}
	}
	if rec := browserSignIn(t, svc, idp, clk, claims()); rec.Code != http.StatusForbidden {
		t.Errorf("the callback: got %d %q, want 403", rec.Code, rec.Body.String())
	}
	if _, err := svc.ExchangeIDToken(ctx, exchangeToken(idp, clk, claims())); !errors.Is(err, authn.ErrExternalIDConflict) {
		t.Errorf("the exchange: %v, want ErrExternalIDConflict", err)
	}
	after, err := principalStore.GetByID(ctx, before.ID)
	if err != nil || *after.ExternalID != "usr-tom" || !reflect.DeepEqual(after.IDPGroups, []string{"wt-owners"}) || countPrincipals(t, database) != 1 {
		t.Errorf("the principal after the refusals: %+v, %v, want it alone and unchanged", after, err)
	}
	if n := len(eventsOf(t, database, groupsChanged)); n != 0 {
		t.Errorf("%d changes of groups recorded, want none", n)
	}
	refusals := append(logs.records(t, "refusing a sign-in"), logs.records(t, "refusing a token exchange")...)
	if len(refusals) != 2 {
		t.Fatalf("%d refusals logged, want 2", len(refusals))
	}
	for _, r := range refusals {
		if r["claim"] != "oid" || !strings.Contains(r["error"].(string), before.ID.String()) {
			t.Errorf("a refusal logs %v, want the claim's name and the principal's ID", r)
		}
	}
	if logged := logs.buf.String(); strings.Contains(logged, "usr-tom") || strings.Contains(logged, "idp-tom") || strings.Contains(logged, "Tom Canary") {
		t.Errorf("the log holds a value of the ID token: %s", logged)
	}
}

// SCIM refuses a user that sign-ins could never find: without an externalId,
// or with one that is blank or too long. It refuses an externalId that a user
// it manages holds, under another userName or the same, and a patch that
// changes or removes the externalId, whatever else the patch holds; one that
// gives the externalId the user has changes nothing and is accepted. Nothing
// is created, changed or recorded by a refusal.
func TestSCIMRefusesExternalIDsThatWouldNotReachThePerson(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	_, principalStore, _, database := setupAuthn(t, clk)
	scim := scimClient(t, principalStore)
	user := decodeSCIMUser(t, createSCIMUser(scim, "idp-ruth", "ruth@example.test"), http.StatusCreated)
	tooLong := strings.Repeat("x", authn.MaxExternalIDLength+1)

	for name, tt := range map[string]struct {
		body             string
		status           int
		scimType, detail string
	}{
		"no externalId":                        {`{"userName":"una@example.test"}`, http.StatusBadRequest, "invalidValue", "externalId is required"},
		"a blank one":                          {`{"userName":"una@example.test","externalId":"  "}`, http.StatusBadRequest, "invalidValue", "externalId is required"},
		"one too long":                         {`{"userName":"una@example.test","externalId":"` + tooLong + `"}`, http.StatusBadRequest, "invalidValue", "externalId is required"},
		"another user's, under a new userName": {`{"userName":"una@example.test","externalId":"idp-ruth"}`, http.StatusConflict, "uniqueness", "externalId"},
		"the same user again":                  {`{"userName":"ruth@example.test","externalId":"idp-ruth"}`, http.StatusConflict, "uniqueness", "userName"},
		"a userName that exists, with another": {`{"userName":"ruth@example.test","externalId":"idp-una"}`, http.StatusConflict, "uniqueness", "userName"},
	} {
		t.Run(name, func(t *testing.T) {
			checkSCIMError(t, scim(http.MethodPost, "/scim/v2/Users", tt.body), tt.status, tt.scimType, tt.detail)
		})
	}

	patch := func(ops string) *httptest.ResponseRecorder {
		return scim(http.MethodPatch, "/scim/v2/Users/"+user.ID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`+ops+`]}`)
	}
	deactivate := `{"op":"replace","path":"active","value":false}`
	for name, ops := range map[string]string{
		"a replace":               `{"op":"replace","path":"externalId","value":"idp-una"},` + deactivate,
		"a replace without path":  deactivate + `,{"op":"replace","value":{"externalId":"idp-una"}}`,
		"an add with the URN":     `{"op":"add","path":"urn:ietf:params:scim:schemas:core:2.0:User:externalId","value":"idp-una"}`,
		"a removal":               `{"op":"remove","path":"externalId"}`,
		"a value that is no text": `{"op":"replace","path":"externalId","value":7}`,
	} {
		t.Run("a patch with "+name, func(t *testing.T) {
			checkSCIMError(t, patch(ops), http.StatusBadRequest, "mutability", "externalId cannot change")
		})
	}
	if rec := patch(`{"op":"replace","path":"externalId","value":"idp-ruth"},{"op":"replace","value":{"externalId":"idp-ruth","displayName":"Ruth"}}`); rec.Code != http.StatusOK {
		t.Errorf("a patch with the externalId the user has: got %d %q, want 200", rec.Code, rec.Body.String())
	}

	ruth, err := principalStore.GetBySCIMUserName(ctx, "ruth@example.test")
	if err != nil || *ruth.ExternalID != "idp-ruth" || ruth.Status != "active" {
		t.Errorf("the user after the refusals: %+v, %v, want it unchanged", ruth, err)
	}
	if n := countPrincipals(t, database); n != 1 {
		t.Errorf("%d principals, want one", n)
	}
	for typ, want := range map[string]int{principalCreated: 1, principalAdopted: 0, "whitetower.principal.deactivated.v1": 0} {
		if n := len(eventsOf(t, database, typ)); n != want {
			t.Errorf("%s: %d recorded, want %d", typ, n, want)
		}
	}
}

// Two SCIM creations with one userName at once create one user, when the
// second would adopt the principal that a person signed in as: the
// adoption's userName meets the creation's, which commits first, and the
// adoption is refused as a userName that exists, with nothing recorded. The
// audit log holds the creation at its event until the adoption waits.
func TestASCIMAdoptionThatACreationOvertookIsRefused(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	d := dbtest.New(t)
	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(cat, clk)
	pool := d.Open(t)
	principals := authn.NewPrincipalStore(pool, clk, writer, authn.NewSessionStore(pool, clk, writer, authn.SessionOptions{}), authn.NewTokenStore(pool, clk, writer))
	signedIn, err := principals.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-vic", ExternalID: "idp-vic", DisplayName: "Vic Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	hold, err := d.Superuser(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(ctx, "LOCK TABLE whitetower.audit_events IN EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	created, adopted := make(chan error, 1), make(chan error, 1)
	provision := func(externalID string, result chan<- error) {
		_, err := principals.ProvisionHuman(ctx, authn.Identity{Subject: "vic@example.test", ExternalID: externalID, DisplayName: "Vic Canary"})
		result <- err
	}
	go provision("idp-other", created)
	awaitLockWaits(t, pool, 1)
	go provision("idp-vic", adopted)
	awaitLockWaits(t, pool, 2)
	if err := hold.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if errCreated, errAdopted := <-created, <-adopted; errCreated != nil || !errors.Is(errAdopted, authn.ErrPrincipalExists) {
		t.Fatalf("the creation: %v; the adoption: %v, want ErrPrincipalExists", errCreated, errAdopted)
	}
	still, err := principals.GetByID(ctx, signedIn.ID)
	if err != nil || *still.Issuer != "https://idp.example.com" || *still.Subject != "usr-vic" {
		t.Errorf("the principal of the sign-in: %+v, %v, want it unchanged", still, err)
	}
	if n := len(eventsOf(t, pool, principalAdopted)); n != 0 {
		t.Errorf("%d adoptions recorded, want none", n)
	}
}
