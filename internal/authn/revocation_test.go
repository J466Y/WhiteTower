package authn_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

const accessRevokedAll = "whitetower.access.revoked_all.v1"

// breakglassService returns a break-glass service of sessions, and its
// credential.
func breakglassService(t *testing.T, clk *clocktest.Fake, database *db.DB, sessions *authn.SessionStore) (*authn.BreakglassService, string) {
	t.Helper()
	credential, hash, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatal(err)
	}
	hashFile := filepath.Join(t.TempDir(), "breakglass.hash")
	if err := os.WriteFile(hashFile, []byte(hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return authn.NewBreakglassService(authn.BreakglassOptions{
		Enabled: true, CredentialHashFile: hashFile, Clock: clk, Logger: slog.New(slog.DiscardHandler),
	}, database, sessions, audit.NewWriter(mustCatalog(t), clk)), credential
}

// Security test ST-89: an emergency revocation ends every session and API
// token, of people and of service accounts, the CLI's tokens and the other
// break-glass sessions included, but the break-glass session that runs it;
// an administrator's own session ends. Revoked and expired ones are left as
// they were, and principals and their roles stay. Each run records its event,
// with how many it ended, and raises the alert; a second run ends nothing new
func TestAnEmergencyRevocationEndsEverySessionAndToken(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	sessions, principals, tokens, database := setupAuthn(t, clk)
	var logs bytes.Buffer
	revocation := authn.NewEmergencyRevocation(sessions, slog.New(slog.NewJSONHandler(&logs, nil)))
	breakglass, credential := breakglassService(t, clk, database, sessions)
	person := func(subject string, roles ...string) (auth.Principal, *authn.Session) {
		t.Helper()
		p, err := principals.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: subject, ExternalID: subject, DisplayName: subject}, nil)
		if err != nil {
			t.Fatal(err)
		}
		session, err := sessions.Create(ctx, p.ID, "oidc", roles)
		if err != nil {
			t.Fatal(err)
		}
		return auth.Principal{ID: p.ID.String(), Kind: auth.Human, Roles: roles}, session
	}
	token := func(owner auth.Principal, lifetime time.Duration) *authn.CreatedToken {
		t.Helper()
		created, err := tokens.CreateWithLifetime(ctx, uuid.MustParse(owner.ID), "key", []string{string(authz.PermissionIdentityMeRead)}, lifetime, owner)
		if err != nil {
			t.Fatal(err)
		}
		return created
	}

	// What is no longer valid stays as it was: a session and a token that
	// expired, and a token revoked before.
	otto, staleSession := person("usr-otto", "owner")
	staleToken := token(otto, time.Minute)
	revokedToken := token(otto, time.Hour)
	if err := tokens.Revoke(ctx, revokedToken.ID, otto, "rotated"); err != nil {
		t.Fatal(err)
	}
	revokedAt := clk.Now().UTC()
	clk.Advance(31 * time.Minute)

	ada, adaSession := person("usr-ada", "admin")
	_, ottoSession := person("usr-otto", "owner")
	bot, err := principals.CreateServiceAccount(ctx, "Otto's bot", nil, []string{"owner"}, otto)
	if err != nil {
		t.Fatal(err)
	}
	ottosToken := token(otto, 24*time.Hour)
	botsToken := token(auth.Principal{ID: bot.ID.String(), Kind: auth.ServiceAccount}, 24*time.Hour)
	cliToken, err := eventsService(t, idp, clk, principals, sessions, tokens).ExchangeIDToken(ctx, exchangeToken(idp, clk, map[string]any{"sub": "usr-ivy", "groups": []string{"wt-owners"}}))
	if err != nil {
		t.Fatal(err)
	}
	running, other := breakglassSignIn(t, breakglass, credential), breakglassSignIn(t, breakglass, credential)
	custodian := authn.BreakglassPrincipalID.String()
	runningSession, err := sessions.Get(ctx, running)
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := revocation.Revoke(ctx, runningSession, "INC-2041: the identity provider was compromised")
	if err != nil {
		t.Fatal(err)
	}
	if want := (authn.Revocation{Sessions: 3, Tokens: 3, At: clk.Now().UTC()}); revoked != want {
		t.Errorf("the revocation: %+v, want %+v", revoked, want)
	}
	for name, session := range map[string]string{"an administrator's": adaSession.Token, "an owner's": ottoSession.Token, "another break-glass": other} {
		if _, err := sessions.Get(ctx, session); !errors.Is(err, authn.ErrSessionRevoked) {
			t.Errorf("%s session: %v, want it revoked", name, err)
		}
	}
	for name, created := range map[string]*authn.CreatedToken{"a person's": ottosToken, "a service account's": botsToken, "the CLI's": cliToken} {
		if _, _, err := tokens.GetByToken(ctx, created.Token); !errors.Is(err, authn.ErrTokenRevoked) {
			t.Errorf("%s token: %v, want it revoked", name, err)
		}
	}
	if _, err := sessions.Get(ctx, running); err != nil {
		t.Errorf("the break-glass session that ran it: %v, want it valid", err)
	}
	if _, err := sessions.Get(ctx, staleSession.Token); !errors.Is(err, authn.ErrSessionExpired) {
		t.Errorf("an expired session: %v, want it expired, not revoked", err)
	}
	if _, _, err := tokens.GetByToken(ctx, staleToken.Token); !errors.Is(err, authn.ErrTokenExpired) {
		t.Errorf("an expired token: %v, want it expired, not revoked", err)
	}
	if listed, err := tokens.ListByPrincipal(ctx, uuid.MustParse(otto.ID)); err != nil || !slices.ContainsFunc(listed, func(tok *authn.APIToken) bool {
		return tok.ID == revokedToken.ID && tok.RevokedAt != nil && tok.RevokedAt.Equal(revokedAt)
	}) {
		t.Errorf("the token revoked before: %v, want its revocation unchanged", err)
	}
	for _, p := range []auth.Principal{ada, otto, {ID: bot.ID.String()}} {
		if got, err := principals.GetByID(ctx, uuid.MustParse(p.ID)); err != nil || got.Status != "active" {
			t.Errorf("principal %s: %+v, %v, want it active", p.ID, got, err)
		}
	}
	if roles, err := principals.GetRoles(ctx, bot.ID); err != nil || !slices.Equal(roles, []string{"owner"}) {
		t.Errorf("the service account's roles: %v, %v, want its binding kept", roles, err)
	}

	// A second run ends nothing new, and is recorded too. An administrator's
	// run ends their own session and the break-glass session.
	if again, err := revocation.Revoke(ctx, runningSession, "INC-2041, again"); err != nil || again.Sessions != 0 || again.Tokens != 0 {
		t.Errorf("a second run: %+v, %v, want nothing ended", again, err)
	}
	_, adaAgain := person("usr-ada", "admin")
	byAda, err := revocation.Revoke(ctx, adaAgain, "INC-2042")
	if err != nil || byAda.Sessions != 2 || byAda.Tokens != 0 || !byAda.SignedOut {
		t.Errorf("an administrator's run: %+v, %v, want their session and the break-glass session ended", byAda, err)
	}
	for _, session := range []string{running, adaAgain.Token} {
		if _, err := sessions.Get(ctx, session); !errors.Is(err, authn.ErrSessionRevoked) {
			t.Errorf("after an administrator's run: %v, want the session revoked", err)
		}
	}

	recorded := eventsOf(t, database, accessRevokedAll)
	want := []struct {
		actorType, actorID, reason string
		sessions, tokens           float64
	}{
		{"breakglass", custodian, "INC-2041: the identity provider was compromised", 3, 3},
		{"breakglass", custodian, "INC-2041, again", 0, 0},
		{"human", ada.ID, "INC-2042", 2, 0},
	}
	if len(recorded) != len(want) {
		t.Fatalf("%d emergency revocations recorded, want %d", len(recorded), len(want))
	}
	for i, w := range want {
		e := recorded[i]
		if e.actorType != w.actorType || e.actorID != w.actorID || e.reason != w.reason || e.data["sessions"] != w.sessions || e.data["tokens"] != w.tokens {
			t.Errorf("revocation %d: %s %s %q %v, want %+v", i, e.actorType, e.actorID, e.reason, e.data, w)
		}
		for _, value := range append(tokenForms(running), tokenForms(cliToken.Token)...) {
			if strings.Contains(e.canonical, value) {
				t.Errorf("revocation %d holds a token or its hash: %s", i, e.canonical)
			}
		}
	}
	if n := strings.Count(logs.String(), `"level":"ERROR","msg":"SECURITY ALERT: emergency revocation ended every session and API token"`); n != 3 {
		t.Errorf("%d alerts logged, want 3:\n%s", n, logs.String())
	}
}

// An emergency revocation that cannot be recorded, or whose reason is blank or
// too long, changes nothing and raises no alert.
func TestAnEmergencyRevocationThatFailsChangesNothing(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.New(testEpoch)
	sessions, principals, tokens, database := setupAuthn(t, clk)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ada, err := principals.SignIn(ctx, "oidc", authn.Identity{Issuer: "https://idp.example.com", Subject: "usr-ada", ExternalID: "usr-ada", DisplayName: "Ada"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessions.Create(ctx, ada.ID, "oidc", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	actor := auth.Principal{ID: ada.ID.String(), Kind: auth.Human, Roles: []string{"admin"}}
	created, err := tokens.Create(ctx, ada.ID, "key", []string{string(authz.PermissionIdentityMeRead)}, 1, actor)
	if err != nil {
		t.Fatal(err)
	}

	refusing := authn.NewEmergencyRevocation(authn.NewSessionStore(database, clk, refusingWriter(t, clk, accessRevokedAll), authn.SessionOptions{}), logger)
	if _, err := refusing.Revoke(ctx, session, "INC-2041"); err == nil {
		t.Error("a revocation that cannot be recorded succeeded")
	}
	revocation := authn.NewEmergencyRevocation(sessions, logger)
	for name, reason := range map[string]string{"none": "", "blank": " \t\n", "too long": strings.Repeat("é", authn.MaxRevocationReason+1)} {
		if _, err := revocation.Revoke(ctx, session, reason); !errors.Is(err, authn.ErrInvalidReason) {
			t.Errorf("a reason %s: %v, want it refused", name, err)
		}
	}
	if _, err := sessions.Get(ctx, session.Token); err != nil {
		t.Errorf("the session: %v, want it valid", err)
	}
	if _, _, err := tokens.GetByToken(ctx, created.Token); err != nil {
		t.Errorf("the token: %v, want it valid", err)
	}
	if n := len(eventsOf(t, database, accessRevokedAll)); n != 0 || logs.Len() != 0 {
		t.Errorf("%d revocations recorded and logs %q, want none", n, logs.String())
	}
	// The longest reason is accepted.
	if _, err := revocation.Revoke(ctx, session, strings.Repeat("é", authn.MaxRevocationReason)); err != nil {
		t.Errorf("a reason of %d characters: %v", authn.MaxRevocationReason, err)
	}
}

// Security test ST-89: a session or a token that another replica creates
// while an emergency revocation runs does not survive it once its creation
// commits first, and one whose creation waits for the revocation's commit is
// created after it, and stays. The audit log holds each transaction at its
// event until the others wait.
func TestAnEmergencyRevocationEndsWhatCommitsBeforeIt(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t)
	clk := clocktest.New(testEpoch)
	d := dbtest.New(t)
	writer := audit.NewWriter(mustCatalog(t), clk)
	type replica struct {
		pool       *db.DB
		sessions   *authn.SessionStore
		principals *authn.PrincipalStore
		tokens     *authn.TokenStore
	}
	open := func(name string) replica {
		pool := d.OpenReplica(t, name)
		sessions := authn.NewSessionStore(pool, clk, writer, authn.SessionOptions{})
		tokens := authn.NewTokenStore(pool, clk, writer, authz.NewAuthorizer(), authn.SignInConfiguration{})
		return replica{pool, sessions, authn.NewPrincipalStore(pool, clk, writer, sessions, tokens), tokens}
	}
	a, b := open("replica-a"), open("replica-b")
	revocation := authn.NewEmergencyRevocation(a.sessions, slog.New(slog.DiscardHandler))
	cli := eventsService(t, idp, clk, b.principals, b.sessions, b.tokens)
	sam := authn.Identity{Issuer: idp.server.URL, Subject: "usr-sam", ExternalID: "usr-sam", DisplayName: "Sam"}
	// Ivy exchanges, and Sam signs in, so that neither waits for the other's
	// principal.
	exchange := func() (*authn.CreatedToken, error) {
		return cli.ExchangeIDToken(ctx, exchangeToken(idp, clk, map[string]any{"sub": "usr-ivy", "name": "Ivy", "groups": []string{"wt-owners"}}))
	}
	signIn := func() (*authn.Session, error) {
		var session *authn.Session
		_, err := b.principals.SignIn(ctx, "oidc", sam, func(ctx context.Context, tx *db.Tx, p *authn.Principal) (err error) {
			session, err = b.sessions.ReplaceTx(ctx, tx, nil, p.ID, "oidc", []string{"owner"}, 0)
			return err
		})
		return session, err
	}
	// They signed in before, so that neither sign-in nor exchange records
	// anything before it writes its session or token. Sam's session runs the
	// revocations.
	caller, err := signIn()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(); err != nil {
		t.Fatal(err)
	}
	type created struct {
		session *authn.Session
		token   *authn.CreatedToken
		err     error
	}
	// holdAuditLog locks the audit log, so that every transaction waits at
	// its event, and returns its release.
	holdAuditLog := func() func() {
		t.Helper()
		hold, err := d.Superuser(t).Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hold.Exec(ctx, "LOCK TABLE whitetower.audit_events IN EXCLUSIVE MODE"); err != nil {
			t.Fatal(err)
		}
		return func() {
			if err := hold.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	revoke := func(done chan<- authn.Revocation) {
		r, err := revocation.Revoke(ctx, caller, "INC-2041")
		if err != nil {
			t.Error(err)
		}
		done <- r
	}

	t.Run("created before the revocation commits", func(t *testing.T) {
		release := holdAuditLog()
		results := make(chan created, 2)
		go func() { s, err := signIn(); results <- created{session: s, err: err} }()
		go func() { tok, err := exchange(); results <- created{token: tok, err: err} }()
		awaitLockWaits(t, a.pool, 2)
		done := make(chan authn.Revocation, 1)
		go revoke(done)
		awaitLockWaits(t, a.pool, 3)
		release()
		first, second := <-results, <-results
		if first.err != nil || second.err != nil {
			t.Fatalf("the sign-in and the exchange: %v, %v", first.err, second.err)
		}
		session, token := first.session, second.token
		if session == nil {
			session, token = second.session, first.token
		}
		if r := <-done; r.Sessions != 2 || r.Tokens != 2 {
			t.Errorf("the revocation ended %+v, want the sessions and the tokens of before and of meanwhile", r)
		}
		if _, err := a.sessions.Get(ctx, session.Token); !errors.Is(err, authn.ErrSessionRevoked) {
			t.Errorf("the session created meanwhile: %v, want it revoked", err)
		}
		if _, _, err := a.tokens.GetByToken(ctx, token.Token); !errors.Is(err, authn.ErrTokenRevoked) {
			t.Errorf("the token created meanwhile: %v, want it revoked", err)
		}
	})

	t.Run("created after the revocation commits", func(t *testing.T) {
		release := holdAuditLog()
		done := make(chan authn.Revocation, 1)
		go revoke(done)
		awaitLockWaits(t, a.pool, 1)
		results := make(chan created, 1)
		go func() { s, err := signIn(); results <- created{session: s, err: err} }()
		awaitLockWaits(t, a.pool, 2)
		release()
		if r := <-done; r.Sessions != 0 || r.Tokens != 0 {
			t.Errorf("the revocation ended %+v, want nothing", r)
		}
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if _, err := a.sessions.Get(ctx, result.session.Token); err != nil {
			t.Errorf("the session created after the revocation: %v, want it valid", err)
		}
	})
}
