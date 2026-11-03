package authn_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

const (
	principalCreated = "whitetower.principal.created.v1"
	groupsChanged    = "whitetower.principal.groups_changed.v1"
	sessionCreated   = "whitetower.session.created.v1"
	sessionRevoked   = "whitetower.session.revoked.v1"
)

// recorded is an audit event as the log stores it.
type recorded struct {
	typ       string
	subject   string
	actorType string
	actorID   string
	reason    string
	data      map[string]any
	canonical string
}

// eventsOf returns the audit events of the type given, oldest first. The
// writer stores only events whose data their type's schema accepts, so every
// event returned passed it.
func eventsOf(t *testing.T, database *db.DB, eventType string) []recorded {
	t.Helper()
	rows, err := database.Query(context.Background(),
		`SELECT coalesce(subject_agent_id::text, ''), actor_type, coalesce(actor_id, ''), coalesce(reason, ''), canonical
		 FROM whitetower.audit_events WHERE type = $1 ORDER BY id`, eventType)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var found []recorded
	for rows.Next() {
		e := recorded{typ: eventType}
		var canonical []byte
		if err := rows.Scan(&e.subject, &e.actorType, &e.actorID, &e.reason, &canonical); err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(canonical, &envelope); err != nil {
			t.Fatal(err)
		}
		e.data, e.canonical = envelope.Data, string(canonical)
		found = append(found, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return found
}

// checkEvent fails the test unless e names the principal of its data as its
// subject, was done by the actor given, and its data holds want, member by
// member.
func checkEvent(t *testing.T, e recorded, actorType, actorID string, want map[string]any) {
	t.Helper()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	for name, value := range members {
		if !reflect.DeepEqual(e.data[name], value) {
			t.Errorf("%s: %s is %v, want %v", e.typ, name, e.data[name], value)
		}
	}
	actor, _ := e.data["actor"].(map[string]any)
	if e.actorType != actorType || e.actorID != actorID || actor["type"] != actorType || actor["id"] != actorID {
		t.Errorf("%s: actor %s %s, data %v, want %s %s", e.typ, e.actorType, e.actorID, actor, actorType, actorID)
	}
	if e.subject == "" || e.subject != e.data["principal_id"] {
		t.Errorf("%s: subject %q, principal %v", e.typ, e.subject, e.data["principal_id"])
	}
}

// checkNoneHolds fails the test if an event of people or their sessions holds
// one of values: names, email addresses, IdP subjects and tokens.
func checkNoneHolds(t *testing.T, database *db.DB, values ...string) {
	t.Helper()
	for _, typ := range []string{principalCreated, groupsChanged, sessionCreated, sessionRevoked} {
		for _, e := range eventsOf(t, database, typ) {
			for _, v := range values {
				if strings.Contains(e.canonical, v) {
					t.Errorf("%s holds %q: %s", typ, v, e.canonical)
				}
			}
		}
	}
}

// tokenForms returns a token, and the forms of its SHA-256 that an event could
// hold: sessions are kept by that hash.
func tokenForms(token string) []string {
	sum := sha256.Sum256([]byte(token))
	return []string{token, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:])}
}

// refusingWriter returns a writer whose catalog refuses every event of the
// types given, as a writer that cannot record them.
func refusingWriter(t *testing.T, clk clock.Clock, types ...string) *audit.Writer {
	t.Helper()
	files := fstest.MapFS{}
	err := fs.WalkDir(events.Files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(events.Files, name)
		files[name] = &fstest.MapFile{Data: data}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range types {
		files["schemas/"+typ+".json"] = &fstest.MapFile{Data: []byte("false")}
	}
	cat, err := audit.LoadCatalog(files)
	if err != nil {
		t.Fatal(err)
	}
	return audit.NewWriter(cat, clk)
}

// eventsService returns an OIDC service of the mock provider that has
// discovered it, maps wt-owners to owner and exchanges ID tokens.
func eventsService(t *testing.T, idp *mockIDP, clk *clocktest.Fake, principals *authn.PrincipalStore, sessions *authn.SessionStore, tokens *authn.TokenStore) *authn.OIDCService {
	t.Helper()
	return newService(t, authn.OIDCOptions{
		Issuer:            idp.server.URL,
		ClientID:          "whitetower-console",
		ClientSecret:      "test-secret",
		RedirectURL:       "https://127.0.0.1:8443/auth/callback",
		Clock:             clk,
		RoleMapping:       map[string]string{"wt-owners": "owner"},
		AllowedAlgorithms: []string{"RS256"},
		Tokens:            tokens,
	}, principals, sessions)
}

// browserSignIn ends a sign-in through svc whose ID token, which the mock
// issues to the console, holds claims, with the browser's cookies, and returns
// the answer.
func browserSignIn(t *testing.T, svc *authn.OIDCService, idp *mockIDP, clk *clocktest.Fake, claims map[string]any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	stateCookie, stateParam, nonceParam := initiateLogin(t, svc, "/")
	claims["iss"] = idp.server.URL
	claims["aud"] = "whitetower-console"
	claims["exp"] = clk.Now().Add(time.Hour).Unix()
	claims["nonce"] = nonceParam
	idp.customToken = idp.signIDToken(map[string]any{"alg": "RS256"}, claims)
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
	req.AddCookie(stateCookie)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)
	return rec
}

// sessionToken returns the session token that an answer sets.
func sessionToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == authn.CookieName && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("no session cookie: %d %q", rec.Code, rec.Body.String())
	return ""
}

// exchangeToken returns an ID token that the mock issues to the CLI, with
// claims.
func exchangeToken(idp *mockIDP, clk *clocktest.Fake, claims map[string]any) string {
	claims["iss"] = idp.server.URL
	claims["aud"] = "wtctl"
	claims["exp"] = clk.Now().Add(time.Hour).Unix()
	return idp.signIDToken(map[string]any{"alg": "RS256"}, claims)
}

// A first sign-in records the principal's creation with its groups, as a set,
// and no change of groups. A later sign-in records a change only when the set
// changed, with the groups before and after.
func TestASignInRecordsThePrincipalsCreationAndAChangeOfItsGroups(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	_, principalStore, _, database := setupAuthn(t, clk)
	email := "carol@example.com"
	id := authn.Identity{
		Issuer: "https://idp.example.com", Subject: "sub-carol", DisplayName: "Carol Canary", Email: &email,
		Groups: []string{"wt-owners", "wt-auditors", "wt-owners"},
	}

	carol, err := principalStore.SignIn(ctx, "oidc", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	created := eventsOf(t, database, principalCreated)
	if len(created) != 1 {
		t.Fatalf("%d creations recorded, want 1", len(created))
	}
	checkEvent(t, created[0], "human", carol.ID.String(), map[string]any{
		"principal_id": carol.ID, "method": "oidc", "idp_groups": []string{"wt-auditors", "wt-owners"},
	})
	if !reflect.DeepEqual(carol.IDPGroups, []string{"wt-auditors", "wt-owners"}) {
		t.Errorf("the principal keeps the groups %v, want them as a set", carol.IDPGroups)
	}
	if changed := eventsOf(t, database, groupsChanged); len(changed) != 0 {
		t.Errorf("the first sign-in recorded a change of groups: %v", changed[0].data)
	}

	id.Groups = []string{"wt-owners", "wt-auditors"}
	clk.Advance(time.Hour)
	if _, err := principalStore.SignIn(ctx, "oidc", id, nil); err != nil {
		t.Fatal(err)
	}
	if changed := eventsOf(t, database, groupsChanged); len(changed) != 0 {
		t.Errorf("the same groups in another order recorded a change: %v", changed[0].data)
	}

	id.Groups = []string{"wt-owners", "wt-operators"}
	if _, err := principalStore.SignIn(ctx, "token_exchange", id, nil); err != nil {
		t.Fatal(err)
	}
	changed := eventsOf(t, database, groupsChanged)
	if len(changed) != 1 {
		t.Fatalf("%d changes recorded, want 1", len(changed))
	}
	checkEvent(t, changed[0], "human", carol.ID.String(), map[string]any{
		"principal_id": carol.ID, "method": "token_exchange",
		"before": []string{"wt-auditors", "wt-owners"}, "after": []string{"wt-operators", "wt-owners"},
	})
	if n := len(eventsOf(t, database, principalCreated)); n != 1 {
		t.Errorf("%d creations recorded, want 1", n)
	}
	checkNoneHolds(t, database, "Carol Canary", email, "sub-carol")
}

// Sign-ins of one person at once, on two replicas, record one creation, and
// each change of groups from the groups before it: the second sign-in waits
// for the first, which holds the principal it created or changed, until the
// first commits. The audit log holds the first sign-in at its event until the
// second waits.
func TestSignInsOfOnePersonAtOnceRecordEachChangeOnce(t *testing.T) {
	for _, tt := range []struct {
		name    string
		known   bool
		changes [][2][]string // before and after, oldest first
	}{
		{"first sign-ins", false, [][2][]string{{{"first"}, {"second"}}}},
		{"sign-ins of a known person", true, [][2][]string{{{"known"}, {"first"}}, {{"first"}, {"second"}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			clk := clocktest.New(testEpoch)
			d := dbtest.New(t)
			cat, err := audit.LoadCatalog(events.Files)
			if err != nil {
				t.Fatal(err)
			}
			writer := audit.NewWriter(cat, clk)
			replica := func(name string) (*db.DB, *authn.PrincipalStore) {
				pool := d.OpenReplica(t, name)
				sessions := authn.NewSessionStore(pool, clk, writer, authn.SessionOptions{})
				return pool, authn.NewPrincipalStore(pool, clk, writer, sessions, authn.NewTokenStore(pool, clk, writer))
			}
			pool, first := replica("replica-a")
			_, second := replica("replica-b")
			dana := func(groups ...string) authn.Identity {
				return authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-dana", DisplayName: "Dana Canary", Groups: groups}
			}
			if tt.known {
				if _, err := first.SignIn(ctx, "oidc", dana("known"), nil); err != nil {
					t.Fatal(err)
				}
			}

			hold, err := d.Superuser(t).Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(ctx, "LOCK TABLE whitetower.audit_events IN EXCLUSIVE MODE"); err != nil {
				t.Fatal(err)
			}
			type result struct {
				p   *authn.Principal
				err error
			}
			results := make(chan result, 2)
			signIn := func(store *authn.PrincipalStore, groups string) {
				p, err := store.SignIn(ctx, "oidc", dana(groups), nil)
				results <- result{p, err}
			}
			go signIn(first, "first")
			awaitLockWaits(t, pool, 1)
			go signIn(second, "second")
			awaitLockWaits(t, pool, 2)
			if err := hold.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			a, b := <-results, <-results
			if a.err != nil || b.err != nil || a.p.ID != b.p.ID {
				t.Fatalf("the sign-ins: %v, %v; principals %v and %v, want one", a.err, b.err, a.p, b.p)
			}

			if created := eventsOf(t, pool, principalCreated); len(created) != 1 {
				t.Errorf("%d creations recorded, want 1", len(created))
			}
			changed := eventsOf(t, pool, groupsChanged)
			if len(changed) != len(tt.changes) {
				t.Fatalf("%d changes recorded, want %d", len(changed), len(tt.changes))
			}
			for i, want := range tt.changes {
				checkEvent(t, changed[i], "human", a.p.ID.String(), map[string]any{"before": want[0], "after": want[1]})
			}
			stored, err := first.GetByID(ctx, a.p.ID)
			if err != nil || !reflect.DeepEqual(stored.IDPGroups, []string{"second"}) {
				t.Errorf("the principal keeps %v (%v), want the second sign-in's groups", stored, err)
			}
		})
	}
}

// awaitLockWaits waits until n sessions of the test's database wait for a
// lock.
func awaitLockWaits(t *testing.T, pool *db.DB, n int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		var waiting int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions never waited for a lock", n)
		}
	}
}

// A sign-in's change to the principal and its event commit together: when the
// rest of the sign-in fails, the change rolls back with its event, and when
// the event cannot be recorded, nothing changes. A sign-out that cannot be
// recorded leaves the session valid.
func TestAChangeAndItsEventCommitTogether(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)
	erin := authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-erin", DisplayName: "Erin Canary", Groups: []string{"wt-owners"}}
	failed := errors.New("the session cannot be created")
	failing := func(context.Context, *db.Tx, *authn.Principal) error { return failed }
	unchanged := func(t *testing.T, id authn.Identity, groups []string) {
		t.Helper()
		p, err := principalStore.GetByIdentity(ctx, id.Issuer, id.Subject)
		switch {
		case groups == nil && !errors.Is(err, authn.ErrPrincipalNotFound):
			t.Errorf("the principal: %v, %v, want none", p, err)
		case groups != nil && (err != nil || !reflect.DeepEqual(p.IDPGroups, groups)):
			t.Errorf("the principal: %v, %v, want the groups %v", p, err, groups)
		}
	}
	count := func(typ string) int { return len(eventsOf(t, database, typ)) }

	t.Run("the rest of the sign-in fails", func(t *testing.T) {
		if _, err := principalStore.SignIn(ctx, "oidc", erin, failing); !errors.Is(err, failed) {
			t.Fatalf("a first sign-in whose session fails: %v", err)
		}
		unchanged(t, erin, nil)
		if n := count(principalCreated); n != 0 {
			t.Errorf("%d creations recorded, want none", n)
		}

		if _, err := principalStore.SignIn(ctx, "oidc", erin, nil); err != nil {
			t.Fatal(err)
		}
		other := erin
		other.Groups = []string{"wt-admins"}
		if _, err := principalStore.SignIn(ctx, "oidc", other, failing); !errors.Is(err, failed) {
			t.Fatalf("a sign-in with other groups whose session fails: %v", err)
		}
		unchanged(t, erin, []string{"wt-owners"})
		if n := count(groupsChanged); n != 0 {
			t.Errorf("%d changes recorded, want none", n)
		}
	})

	t.Run("the event cannot be recorded", func(t *testing.T) {
		refusing := authn.NewPrincipalStore(database, clk, refusingWriter(t, clk, principalCreated, groupsChanged), nil, nil)
		frank := authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-frank", DisplayName: "Frank Canary"}
		if _, err := refusing.SignIn(ctx, "oidc", frank, nil); err == nil {
			t.Fatal("a creation that cannot be recorded succeeded")
		}
		unchanged(t, frank, nil)
		other := erin
		other.Groups = []string{"wt-admins"}
		if _, err := refusing.SignIn(ctx, "oidc", other, nil); err == nil {
			t.Fatal("a change of groups that cannot be recorded succeeded")
		}
		unchanged(t, erin, []string{"wt-owners"})

		p, err := principalStore.GetByIdentity(ctx, erin.Issuer, erin.Subject)
		if err != nil {
			t.Fatal(err)
		}
		session, err := sessionStore.Create(ctx, p.ID, "oidc", []string{"owner"})
		if err != nil {
			t.Fatal(err)
		}
		sessions := authn.NewSessionStore(database, clk, refusingWriter(t, clk, sessionRevoked), authn.SessionOptions{})
		if err := sessions.SignOut(ctx, session.Token); err == nil {
			t.Fatal("a sign-out that cannot be recorded succeeded")
		}
		if _, err := sessionStore.Get(ctx, session.Token); err != nil {
			t.Errorf("the session after a sign-out that could not be recorded: %v, want it valid", err)
		}
	})
}

// A browser sign-in records, in its transaction, the principal's creation, the
// sign-in with the session's roles, and the revocation of the session that the
// browser held, which can be another person's. No event holds a name, an email
// address, an IdP subject or a token.
func TestABrowserSignInIsRecorded(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	svc := eventsService(t, idp, clk, principalStore, sessionStore, tokenStore)

	aliceToken := sessionToken(t, browserSignIn(t, svc, idp, clk, map[string]any{
		"sub": "usr-alice", "name": "Alice Canary", "email": "alice@example.com", "groups": []string{"wt-owners", "unmapped"},
	}))
	alice, err := principalStore.GetByIdentity(ctx, idp.server.URL, "usr-alice")
	if err != nil {
		t.Fatal(err)
	}
	created := eventsOf(t, database, principalCreated)
	if len(created) != 1 {
		t.Fatalf("%d creations recorded, want 1", len(created))
	}
	checkEvent(t, created[0], "human", alice.ID.String(), map[string]any{
		"principal_id": alice.ID, "method": "oidc", "idp_groups": []string{"unmapped", "wt-owners"},
	})
	signedIn := eventsOf(t, database, sessionCreated)
	if len(signedIn) != 1 {
		t.Fatalf("%d sign-ins recorded, want 1", len(signedIn))
	}
	checkEvent(t, signedIn[0], "human", alice.ID.String(), map[string]any{
		"principal_id": alice.ID, "method": "oidc", "roles": []string{"owner"},
		"expires_at": clk.Now().Add(12 * time.Hour).Format("2006-01-02T15:04:05.000Z"),
	})
	if revoked := eventsOf(t, database, sessionRevoked); len(revoked) != 0 {
		t.Errorf("a sign-in without a held session recorded a revocation: %v", revoked[0].data)
	}

	bobToken := sessionToken(t, browserSignIn(t, svc, idp, clk, map[string]any{
		"sub": "usr-bob", "name": "Bob Canary", "email": "bob@example.com",
	}, &http.Cookie{Name: authn.CookieName, Value: aliceToken}))
	bob, err := principalStore.GetByIdentity(ctx, idp.server.URL, "usr-bob")
	if err != nil {
		t.Fatal(err)
	}
	revoked := eventsOf(t, database, sessionRevoked)
	if len(revoked) != 1 || revoked[0].reason != "replaced" {
		t.Fatalf("revocations %v, want alice's, replaced", revoked)
	}
	checkEvent(t, revoked[0], "human", bob.ID.String(), map[string]any{
		"principal_id": alice.ID, "method": "oidc", "reason": "replaced",
	})
	if signedIn := eventsOf(t, database, sessionCreated); len(signedIn) != 2 || signedIn[1].data["principal_id"] != bob.ID.String() {
		t.Errorf("sign-ins %v, want alice's and bob's", signedIn)
	}

	values := []string{"Alice Canary", "alice@example.com", "usr-alice", "Bob Canary", "bob@example.com", "usr-bob"}
	values = append(values, tokenForms(aliceToken)...)
	checkNoneHolds(t, database, append(values, tokenForms(bobToken)...)...)
}

// The CLI's exchange records the principal's creation and a change of its
// groups. Its sign-in is recorded as the token's creation, and no session's.
func TestAnExchangeIsRecordedAsItsToken(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	svc := eventsService(t, idp, clk, principalStore, sessionStore, tokenStore)
	exchange := func(groups ...string) *authn.CreatedToken {
		t.Helper()
		created, err := svc.ExchangeIDToken(ctx, exchangeToken(idp, clk, map[string]any{
			"sub": "usr-ivy", "name": "Ivy Canary", "email": "ivy@example.com", "groups": groups,
		}))
		if err != nil {
			t.Fatal(err)
		}
		return created
	}

	first := exchange("wt-owners", "wt-operators")
	created := eventsOf(t, database, principalCreated)
	if len(created) != 1 {
		t.Fatalf("%d creations recorded, want 1", len(created))
	}
	checkEvent(t, created[0], "human", first.PrincipalID.String(), map[string]any{
		"principal_id": first.PrincipalID, "method": "token_exchange", "idp_groups": []string{"wt-operators", "wt-owners"},
	})
	second := exchange("wt-operators", "wt-owners")
	if changed := eventsOf(t, database, groupsChanged); len(changed) != 0 {
		t.Errorf("the same groups in another order recorded a change: %v", changed[0].data)
	}
	third := exchange("wt-owners")
	changed := eventsOf(t, database, groupsChanged)
	if len(changed) != 1 {
		t.Fatalf("%d changes recorded, want 1", len(changed))
	}
	checkEvent(t, changed[0], "human", first.PrincipalID.String(), map[string]any{
		"method": "token_exchange", "before": []string{"wt-operators", "wt-owners"}, "after": []string{"wt-owners"},
	})
	if n := len(eventsOf(t, database, "whitetower.token.created.v1")); n != 3 {
		t.Errorf("%d tokens recorded, want 3", n)
	}
	if n := len(eventsOf(t, database, sessionCreated)); n != 0 {
		t.Errorf("an exchange recorded %d sessions", n)
	}
	values := []string{"Ivy Canary", "ivy@example.com", "usr-ivy"}
	for _, token := range []*authn.CreatedToken{first, second, third} {
		values = append(values, tokenForms(token.Token)...)
	}
	checkNoneHolds(t, database, values...)
}

// An inactive principal is refused at the callback and at the exchange, and
// nothing is written: not its groups or its last login, no event, no token,
// and no revocation of the session that the browser held.
func TestAnInactivePrincipalsSignInWritesNothing(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	svc := eventsService(t, idp, clk, principalStore, sessionStore, tokenStore)

	gina, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "usr-gina", DisplayName: "Gina Canary", Groups: []string{"wt-owners"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := principalStore.Deactivate(ctx, gina.ID, auth.Principal{}, "left the company"); err != nil {
		t.Fatal(err)
	}
	// Later, so that a sign-in that wrote the last login would show.
	clk.Advance(time.Hour)
	hank, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "usr-hank", DisplayName: "Hank Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	held, err := sessionStore.Create(ctx, hank.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	types := []string{principalCreated, groupsChanged, sessionCreated, sessionRevoked, "whitetower.token.created.v1"}
	before := map[string]int{}
	for _, typ := range types {
		before[typ] = len(eventsOf(t, database, typ))
	}

	claims := map[string]any{"sub": "usr-gina", "name": "Gina Canary", "groups": []string{"wt-admins"}}
	if rec := browserSignIn(t, svc, idp, clk, claims, &http.Cookie{Name: authn.CookieName, Value: held.Token}); rec.Code != http.StatusForbidden {
		t.Errorf("the callback: got %d %q, want 403", rec.Code, rec.Body.String())
	}
	if _, err := svc.ExchangeIDToken(ctx, exchangeToken(idp, clk, map[string]any{"sub": "usr-gina", "groups": []string{"wt-admins"}})); !errors.Is(err, authn.ErrPrincipalInactive) {
		t.Errorf("the exchange: %v, want ErrPrincipalInactive", err)
	}

	for _, typ := range types {
		if n := len(eventsOf(t, database, typ)); n != before[typ] {
			t.Errorf("%s: %d events, want %d", typ, n, before[typ])
		}
	}
	p, err := principalStore.GetByID(ctx, gina.ID)
	if err != nil || !reflect.DeepEqual(p.IDPGroups, []string{"wt-owners"}) || p.LastLoginAt == nil || !p.LastLoginAt.Equal(*gina.LastLoginAt) {
		t.Errorf("the inactive principal: %+v, %v, want it unchanged", p, err)
	}
	if _, err := sessionStore.Get(ctx, held.Token); err != nil {
		t.Errorf("the session the browser held: %v, want it valid", err)
	}
}

// A sign-out records the revocation of the session it ended, with the
// session's principal and how it signed in, a break-glass session's included.
// A cookie of no active session, revoked, expired, unknown or empty, writes
// nothing: signing out needs no authentication.
func TestASignOutIsRecordedOnlyWhenItEndsAnActiveSession(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)
	svc := eventsService(t, idp, clk, principalStore, sessionStore, tokenStore)
	signOut := func(t *testing.T, value string) []recorded {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
		if value != "-" {
			req.AddCookie(&http.Cookie{Name: authn.CookieName, Value: value})
		}
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("logout: got %d, want 302", rec.Code)
		}
		return eventsOf(t, database, sessionRevoked)
	}

	jane, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.server.URL, Subject: "usr-jane", DisplayName: "Jane Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessionStore.Create(ctx, jane.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	revoked := signOut(t, session.Token)
	if len(revoked) != 1 || revoked[0].reason != "signed_out" {
		t.Fatalf("revocations %v, want jane's, signed out", revoked)
	}
	checkEvent(t, revoked[0], "human", jane.ID.String(), map[string]any{
		"principal_id": jane.ID, "method": "oidc", "reason": "signed_out",
	})

	expired, err := sessionStore.Create(ctx, jane.ID, "oidc", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(31 * time.Minute)
	for name, value := range map[string]string{
		"a revoked session": session.Token, "an expired session": expired.Token,
		"an unknown session": "not-a-session", "an empty cookie": "", "no cookie": "-",
	} {
		if n := len(signOut(t, value)); n != 1 {
			t.Errorf("a sign-out with %s recorded %d revocations, want none", name, n-1)
		}
	}

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
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"credential":"`+rawCred+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	breakglass.ServeHTTP(rec, req)
	revoked = signOut(t, sessionToken(t, rec))
	if len(revoked) != 2 {
		t.Fatalf("%d revocations recorded, want the break-glass session's too", len(revoked))
	}
	custodian := authn.BreakglassPrincipalID.String()
	checkEvent(t, revoked[1], "breakglass", custodian, map[string]any{
		"principal_id": custodian, "method": "breakglass", "reason": "signed_out",
	})
}

// mustCatalog returns the event catalog.
func mustCatalog(t *testing.T) *audit.Catalog {
	t.Helper()
	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// A break-glass sign-in is recorded once, as whitetower.breakglass.used.v1,
// and never as a session's creation. Its first use records the creation of
// the custodian's principal, and the revocation of the session that the
// browser held, as replaced by the custodian.
func TestABreakglassSignInIsRecordedOnce(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)
	rawCred, hashStr, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatal(err)
	}
	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	if err := os.WriteFile(hashFile, []byte(hashStr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := authn.NewBreakglassService(authn.BreakglassOptions{
		Enabled: true, CredentialHashFile: hashFile, Clock: clk, Logger: slog.New(slog.DiscardHandler),
	}, database, sessionStore, audit.NewWriter(mustCatalog(t), clk))
	signIn := func(cookies ...*http.Cookie) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/auth/breakglass", strings.NewReader(`{"credential":"`+rawCred+`"}`))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("break-glass: got %d %q, want 200", rec.Code, rec.Body.String())
		}
	}

	alice, err := principalStore.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "sub-alice", DisplayName: "Alice Canary"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	held, err := sessionStore.Create(ctx, alice.ID, "oidc", []string{"operator"})
	if err != nil {
		t.Fatal(err)
	}
	signIn(&http.Cookie{Name: authn.CookieName, Value: held.Token})
	signIn()

	custodian := authn.BreakglassPrincipalID.String()
	var custodianCreated []recorded
	for _, e := range eventsOf(t, database, principalCreated) {
		if e.data["principal_id"] == custodian {
			custodianCreated = append(custodianCreated, e)
		}
	}
	if len(custodianCreated) != 1 {
		t.Fatalf("%d creations of the custodian's principal recorded, want 1", len(custodianCreated))
	}
	checkEvent(t, custodianCreated[0], "breakglass", custodian, map[string]any{"method": "breakglass", "idp_groups": []string{}})
	if n := len(eventsOf(t, database, "whitetower.breakglass.used.v1")); n != 2 {
		t.Errorf("%d uses of break-glass recorded, want 2", n)
	}
	if n := len(eventsOf(t, database, sessionCreated)); n != 0 {
		t.Errorf("break-glass recorded %d sessions' creation, want none", n)
	}
	revoked := eventsOf(t, database, sessionRevoked)
	if len(revoked) != 1 {
		t.Fatalf("%d revocations recorded, want the held session's", len(revoked))
	}
	checkEvent(t, revoked[0], "breakglass", custodian, map[string]any{
		"principal_id": alice.ID, "method": "oidc", "reason": "replaced",
	})
}

// SCIM's creation of a person records the principal's creation, with SCIM's
// service account as actor, and no sign-in. A userName that exists is not
// created again, nor recorded, whether the handler finds it or the store does,
// as for a create that another one overtook.
func TestASCIMProvisioningIsRecordedAsSCIMs(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	_, principalStore, _, database := setupAuthn(t, clk)
	tokenFile := filepath.Join(t.TempDir(), "scim.token")
	if err := os.WriteFile(tokenFile, []byte("scim-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scim, err := authn.NewSCIMService(authn.SCIMOptions{Enabled: true, TokenFile: tokenFile}, principalStore)
	if err != nil {
		t.Fatal(err)
	}
	create := func() int {
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"kim@example.test","displayName":"Kim Canary"}`))
		req.Header.Set("Authorization", "Bearer scim-test-token")
		rec := httptest.NewRecorder()
		scim.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := create(); code != http.StatusCreated {
		t.Fatalf("the creation: got %d, want 201", code)
	}
	kim, err := principalStore.GetByIdentity(ctx, "scim", "kim@example.test")
	if err != nil {
		t.Fatal(err)
	}
	created := eventsOf(t, database, principalCreated)
	if len(created) != 1 {
		t.Fatalf("%d creations recorded, want 1", len(created))
	}
	checkEvent(t, created[0], "service_account", authn.SCIMPrincipalID.String(), map[string]any{
		"principal_id": kim.ID, "method": "scim", "idp_groups": []string{},
	})
	if kim.LastLoginAt != nil {
		t.Errorf("SCIM gave the principal a last login, %v: it never signs in", kim.LastLoginAt)
	}

	if code := create(); code != http.StatusConflict {
		t.Errorf("the same userName again: got %d, want 409", code)
	}
	_, err = principalStore.ProvisionHuman(ctx, authn.Identity{Issuer: "scim", Subject: "kim@example.test", DisplayName: "Kim Canary"})
	if !errors.Is(err, authn.ErrPrincipalExists) {
		t.Errorf("the store's creation of a principal that exists: %v, want ErrPrincipalExists", err)
	}
	if n := len(eventsOf(t, database, principalCreated)); n != 1 {
		t.Errorf("%d creations recorded, want 1", n)
	}
	if n := len(eventsOf(t, database, sessionCreated)); n != 0 {
		t.Errorf("SCIM recorded %d sign-ins, want none", n)
	}
	checkNoneHolds(t, database, "Kim Canary", "kim@example.test")
}
