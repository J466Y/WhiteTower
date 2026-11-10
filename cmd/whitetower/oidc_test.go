package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

// signingProvider is an OpenID Connect provider, on plain HTTP, that answers
// 503 until it is up. Its token endpoint signs an ID token for any code, with
// the code as the token's nonce, so that a test that sends the nonce of a
// sign-in as its code completes it.
type signingProvider struct {
	*httptest.Server
	key *rsa.PrivateKey
	up  atomic.Bool
}

func newSigningProvider(t *testing.T) *signingProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &signingProvider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.URL,
			"authorization_endpoint":                p.URL + "/auth",
			"token_endpoint":                        p.URL + "/token",
			"jwks_uri":                              p.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "signing-provider",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "an access token",
			"token_type":   "Bearer",
			"id_token": p.sign(t, map[string]any{
				"iss":    p.URL,
				"aud":    "whitetower-console",
				"sub":    "usr-signs-in",
				"name":   "Sam Signs-In",
				"groups": []string{"wt-owners"},
				"nonce":  r.PostFormValue("code"),
				"exp":    time.Now().Add(time.Hour).Unix(),
				"iat":    time.Now().Unix(),
			}),
		})
	})
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.up.Load() {
			http.Error(w, "the provider is down", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

// sign returns an ID token with claims, signed with RS256.
func (p *signingProvider) sign(t *testing.T, claims map[string]any) string {
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "signing-provider"})
	if err != nil {
		t.Error(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Error(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Error(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// oidcEnv turns on sign-in through the provider at issuer, with the state
// key of stateKeyFile.
func oidcEnv(t *testing.T, issuer, stateKeyFile string) []string {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "oidc-client-secret")
	writeSecret(t, secret, "a client secret\n")
	return []string{
		"WT_AUTH_OIDC_ISSUER=" + issuer,
		"WT_AUTH_OIDC_CLIENT_ID=whitetower-console",
		"WT_AUTH_OIDC_CLIENT_SECRET_FILE=" + secret,
		"WT_AUTH_OIDC_STATE_KEY_FILE=" + stateKeyFile,
		"WT_AUTH_OIDC_REDIRECT_URL=https://127.0.0.1:8443/auth/callback",
	}
}

// writeStateKey writes a new state key to a file, as openssl rand -base64 32
// does, and returns the file.
func writeStateKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "oidc-state-key")
	writeSecret(t, path, base64.StdEncoding.EncodeToString(key)+"\n")
	return path
}

// waitForLog waits until the server has logged a record whose message is msg.
func (s *serving) waitForLog(t *testing.T, msg string) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); len(s.logs.records(t, msg)) == 0; {
		if time.Now().After(deadline) {
			t.Fatalf("the server did not log %q; it logged:\n%s", msg, s.logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForDiscovery waits until the server has discovered its identity
// provider, which it does in the background.
func (s *serving) waitForDiscovery(t *testing.T) {
	t.Helper()
	s.waitForLog(t, "discovered the identity provider: sign-in is available")
}

// finishSignIn ends at console a sign-in that started anywhere, through a
// signingProvider, and returns the answer's status and the session cookie it
// set, if any.
func finishSignIn(t *testing.T, console string, s signInStart) (int, string) {
	t.Helper()
	query := url.Values{"code": {s.nonce}, "state": {s.state}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, console+"/auth/callback?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", s.cookie)
	resp, err := noRedirects.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == authn.CookieName && c.Value != "" {
			return resp.StatusCode, c.Name + "=" + c.Value
		}
	}
	return resp.StatusCode, ""
}

// The core starts while its identity provider is down (KIL-08, HUM-06): it
// serves break-glass, the API with API tokens and sessions, and the machine
// listener, stays ready, and answers 503 on sign-in and the token exchange.
// Once the provider is up, the core discovers it in the background, and a
// sign-in works without a restart.
func TestTheCoreStartsWhileTheIdentityProviderIsDown(t *testing.T) {
	d := dbtest.New(t)
	idp := newSigningProvider(t)
	credential, hash, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatal(err)
	}
	hashFile := filepath.Join(t.TempDir(), "breakglass-hash")
	writeSecret(t, hashFile, hash+"\n")
	s := startServeOn(t, d, append(oidcEnv(t, idp.URL, writeStateKey(t)),
		"WT_AUTH_BREAKGLASS_ENABLED=true", "WT_AUTH_BREAKGLASS_CREDENTIAL_HASH_FILE="+hashFile)...)

	// An API token made before the outage.
	pool := d.Open(t)
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(catalog, clock.System)
	tokens := authn.NewTokenStore(pool, clock.System, writer, authz.NewAuthorizer(), authn.SignInConfiguration{})
	principals := authn.NewPrincipalStore(pool, clock.System, writer, authn.NewSessionStore(pool, clock.System, writer, authn.SessionOptions{}), tokens)
	owner, err := principals.SignIn(context.Background(), "oidc", authn.Identity{Issuer: idp.URL, Subject: "usr-before-the-outage", ExternalID: "usr-before-the-outage", DisplayName: "Olga Before", Groups: []string{"wt-owners"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tokens.Create(context.Background(), owner.ID, "before the outage", []string{string(authz.PermissionIdentityMeRead)}, 1,
		auth.Principal{ID: owner.ID.String(), Kind: auth.Human})
	if err != nil {
		t.Fatal(err)
	}

	// The provider is down, and the core says so.
	for _, path := range []string{"/auth/login", "/auth/callback?code=a-code&state=a-state"} {
		header, body := call(t, http.StatusServiceUnavailable, http.MethodGet, s.console+path, "", nil)
		if header.Get("Retry-After") != "10" || !strings.Contains(body, "sign-in is unavailable") {
			t.Errorf("%s: Retry-After %q, %q", path, header.Get("Retry-After"), body)
		}
	}
	header, body := call(t, http.StatusServiceUnavailable, http.MethodPost, s.console+"/api/v1/tokens/exchange",
		`{"idToken":"an ID token"}`, http.Header{"Content-Type": {"application/json"}})
	if header.Get("Retry-After") != "10" || !strings.Contains(body, `"code":"unavailable"`) {
		t.Errorf("the exchange: Retry-After %q, %s", header.Get("Retry-After"), body)
	}

	// Break-glass, the API with its session and with the API token, and the
	// machine listener all work.
	header, _ = call(t, http.StatusOK, http.MethodPost, s.console+"/auth/breakglass",
		`{"credential":"`+credential+`"}`, http.Header{"Content-Type": {"application/json"}})
	var breakglass string
	for _, c := range (&http.Response{Header: header}).Cookies() {
		if c.Name == authn.CookieName {
			breakglass = c.Name + "=" + c.Value
		}
	}
	if _, me := get(t, s.console+"/api/v1/me", http.Header{"Cookie": {breakglass}}); !strings.Contains(me, `"isBreakglass":true`) {
		t.Errorf("/me with the break-glass session: %s", me)
	}
	if _, me := get(t, s.console+"/api/v1/me", http.Header{"Authorization": {"Bearer " + token.Token}}); !strings.Contains(me, "Olga Before") {
		t.Errorf("/me with the API token: %s", me)
	}
	if _, refused := call(t, http.StatusUnauthorized, http.MethodPost, s.machine+"/whitetower.module.v1alpha1.MetaService/GetServerInfo", "{}",
		http.Header{"Content-Type": {"application/json"}, "Authorization": {"Bearer anything"}}); !strings.Contains(refused, `"code":"unauthenticated"`) {
		t.Errorf("the machine listener: %s", refused)
	}

	// Health and readiness stay up, so that no load balancer cuts off
	// break-glass; the logs and the metric say that sign-in is unavailable.
	get(t, s.operations+"/healthz", nil)
	if status, body := s.readiness(t); status != http.StatusOK {
		t.Errorf("readyz while the provider is down: %d %q", status, body)
	}
	if _, metrics := get(t, s.operations+"/metrics", nil); !strings.Contains(metrics, "\nwhitetower_oidc_provider_discovered 0\n") {
		t.Error("the metrics do not say that the provider is not discovered")
	}
	s.waitForLog(t, "sign-in is unavailable: discovering the identity provider failed")

	// The provider comes up: the core discovers it, without a restart.
	idp.up.Store(true)
	s.waitForDiscovery(t)
	status, session := finishSignIn(t, s.console, startSignIn(t, s.console))
	if status != http.StatusFound || session == "" {
		t.Fatalf("a sign-in once the provider is up: %d, session cookie %q", status, session)
	}
	if _, me := get(t, s.console+"/api/v1/me", http.Header{"Cookie": {session}}); !strings.Contains(me, "Sam Signs-In") {
		t.Errorf("/me after the sign-in: %s", me)
	}
	if _, metrics := get(t, s.operations+"/metrics", nil); !strings.Contains(metrics, "\nwhitetower_oidc_provider_discovered 1\n") {
		t.Error("the metrics do not say that the provider is discovered")
	}
}

// Replicas that read the same state key file share sign-ins: one that starts
// on a replica ends on another, as it does on a replica that restarted in
// between. A replica with another key refuses it (NFR-06).
func TestASignInEndsOnAnotherReplicaWithTheSameStateKey(t *testing.T) {
	d := dbtest.New(t)
	idp := newSigningProvider(t)
	idp.up.Store(true)
	env := oidcEnv(t, idp.URL, writeStateKey(t))
	first, second := startServeOn(t, d, env...), startServeOn(t, d, env...)
	other := startServeOn(t, d, append(slices.Clone(env), "WT_AUTH_OIDC_STATE_KEY_FILE="+writeStateKey(t))...)
	for _, s := range []*serving{first, second, other} {
		s.waitForDiscovery(t)
	}

	status, session := finishSignIn(t, second.console, startSignIn(t, first.console))
	if status != http.StatusFound || session == "" {
		t.Fatalf("a sign-in that ends on another replica: %d, session cookie %q", status, session)
	}
	for _, s := range []*serving{first, second} {
		if _, me := get(t, s.console+"/api/v1/me", http.Header{"Cookie": {session}}); !strings.Contains(me, "Sam Signs-In") {
			t.Errorf("/me after the sign-in: %s", me)
		}
	}
	if status, session := finishSignIn(t, other.console, startSignIn(t, first.console)); status != http.StatusBadRequest || session != "" {
		t.Errorf("a sign-in that ends on a replica with another key: %d, session cookie %q; want it refused", status, session)
	}
}

// Security test ST-14: of the settings of auth.oidc, a change of those that
// decide which ID tokens the server accepts, which person a sign-in is and
// what roles it gives refuses what the settings before signed in, as after a
// restart: the sessions, unless the setting is auth.oidc.cli_client_id, and
// the tokens of the CLI's exchange, unless it is auth.oidc.client_id. A
// change of the others, of transport and routine, keeps both, and the tokens
// that people and service accounts create are kept whatever the change
// (ST-19). The test names every setting of auth.oidc, so that a setting added
// later is put on one side or the other
func TestOnlyTheSignInSettingsEndTheSessionsAndTheCLIsTokens(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t).Open(t)
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(catalog, clock.System)
	// sessionsOf and tokensOf are the stores of a server that runs the
	// settings oidc, as main wires them.
	sessionsOf := func(oidc config.OIDC) *authn.SessionStore {
		return authn.NewSessionStore(pool, clock.System, writer, authn.SessionOptions{SignInConfiguration: signInConfiguration(oidc)})
	}
	tokensOf := func(oidc config.OIDC) *authn.TokenStore {
		return authn.NewTokenStore(pool, clock.System, writer, authz.NewAuthorizer(), signInConfiguration(oidc))
	}
	idp := newSigningProvider(t)
	idp.up.Store(true)

	before := config.Defaults().Auth.OIDC
	before.Issuer = idp.URL
	before.DiscoveryURL = "https://keycloak.internal:8443/realms/whitetower"
	before.CAFile = "/etc/whitetower/idp-ca.pem"
	before.ClientID = "whitetower-console"
	before.ClientSecretFile = "/etc/whitetower/secrets/oidc-client-secret"
	before.StateKeyFile = "/etc/whitetower/secrets/oidc-state-key"
	before.RedirectURL = "https://whitetower.example.com/auth/callback"

	principals := authn.NewPrincipalStore(pool, clock.System, writer, sessionsOf(before), tokensOf(before))
	person, err := principals.SignIn(ctx, "oidc", authn.Identity{Issuer: idp.URL, Subject: "usr-rotates", ExternalID: "usr-rotates", DisplayName: "Rita Rotates", Groups: []string{"wt-owners"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A token of the person's own, and one of a service account of theirs.
	rita := auth.Principal{ID: person.ID.String(), Kind: auth.Human, Roles: []string{"owner"}}
	scopes := []string{string(authz.PermissionIdentityMeRead)}
	own, err := tokensOf(before).Create(ctx, person.ID, "rita's laptop", scopes, 1, rita)
	if err != nil {
		t.Fatal(err)
	}
	bot, err := principals.CreateServiceAccount(ctx, "Rita's deployer", nil, []string{"owner"}, rita)
	if err != nil {
		t.Fatal(err)
	}
	botToken, err := tokensOf(before).Create(ctx, bot.ID, "deploys", scopes, 1, auth.Principal{ID: bot.ID.String(), Kind: auth.ServiceAccount})
	if err != nil {
		t.Fatal(err)
	}

	// The CLI's exchange of the settings before. Its service takes from
	// before the settings that decide which ID tokens it accepts, and the
	// others from the test: before names files that do not exist.
	stateKey := make([]byte, authn.MinStateKeyBytes)
	if _, err := rand.Read(stateKey); err != nil {
		t.Fatal(err)
	}
	exchanger, err := authn.NewOIDCService(authn.OIDCOptions{
		Issuer:            before.Issuer,
		ClientID:          before.ClientID,
		CLIClientID:       before.CLIClientID,
		AllowedAlgorithms: before.AllowedAlgorithms,
		ExternalIDClaim:   before.ExternalIDClaim,
		GroupsClaim:       before.GroupsClaim,
		RoleMapping:       before.RoleMapping,
		RedirectURL:       before.RedirectURL,
		StateKey:          stateKey,
		Tokens:            tokensOf(before),
	}, principals, sessionsOf(before))
	if err != nil {
		t.Fatal(err)
	}
	if err := exchanger.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	exchange := func(t *testing.T) string {
		t.Helper()
		created, err := exchanger.ExchangeIDToken(ctx, idp.sign(t, map[string]any{
			"iss":    idp.URL,
			"aud":    before.CLIClientID,
			"sub":    "usr-rotates",
			"name":   "Rita Rotates",
			"groups": []string{"wt-owners"},
			"exp":    time.Now().Add(time.Hour).Unix(),
			"iat":    time.Now().Unix(),
		}))
		if err != nil {
			t.Fatalf("exchanging an ID token: %v", err)
		}
		return created.Token
	}

	named := map[string]bool{}
	for _, tt := range []struct {
		setting                     string
		change                      func(c *config.OIDC) // assigns, and never edits a list or a map of before
		endsSessions, endsCLITokens bool
	}{
		{"issuer", func(c *config.OIDC) { c.Issuer = "https://idp.example.net/realms/whitetower" }, true, true},
		{"client_id", func(c *config.OIDC) { c.ClientID = "whitetower-console-2" }, true, false},
		{"cli_client_id", func(c *config.OIDC) { c.CLIClientID = "wtctl-rotated" }, false, true},
		{"allowed_algorithms", func(c *config.OIDC) { c.AllowedAlgorithms = []string{"RS256"} }, true, true},
		{"external_id_claim", func(c *config.OIDC) { c.ExternalIDClaim = "oid" }, true, true},
		{"groups_claim", func(c *config.OIDC) { c.GroupsClaim = "roles" }, true, true},
		{"role_mapping", func(c *config.OIDC) { c.RoleMapping = map[string]string{"wt-owners": "user"} }, true, true},
		{"discovery_url", func(c *config.OIDC) { c.DiscoveryURL = "https://keycloak.internal:9443/realms/whitetower" }, false, false},
		{"ca_file", func(c *config.OIDC) { c.CAFile = "/etc/whitetower/idp-ca-rotated.pem" }, false, false},
		{"client_secret_file", func(c *config.OIDC) { c.ClientSecretFile = "/etc/whitetower/secrets/oidc-client-secret-rotated" }, false, false},
		{"state_key_file", func(c *config.OIDC) { c.StateKeyFile = "/etc/whitetower/secrets/oidc-state-key-rotated" }, false, false},
		{"redirect_url", func(c *config.OIDC) { c.RedirectURL = "https://whitetower.example.net/auth/callback" }, false, false},
		{"scopes", func(c *config.OIDC) { c.Scopes = []string{"openid", "profile", "email"} }, false, false},
	} {
		named[tt.setting] = true
		t.Run(tt.setting, func(t *testing.T) {
			after := before
			tt.change(&after)
			if reflect.DeepEqual(after, before) {
				t.Fatal("the change changes nothing")
			}
			session, err := sessionsOf(before).Create(ctx, person.ID, "oidc", []string{"owner"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = sessionsOf(after).Get(ctx, session.Token)
			switch {
			case tt.endsSessions && !errors.Is(err, authn.ErrSessionExpired):
				t.Errorf("a session after a change of auth.oidc.%s: got %v, want it refused as expired", tt.setting, err)
			case !tt.endsSessions && err != nil:
				t.Errorf("a session after a change of auth.oidc.%s: got %v, want it accepted", tt.setting, err)
			}
			_, _, err = tokensOf(after).GetByToken(ctx, exchange(t))
			switch {
			case tt.endsCLITokens && !errors.Is(err, authn.ErrInvalidToken):
				t.Errorf("a token of the CLI's exchange after a change of auth.oidc.%s: got %v, want it refused as an invalid token", tt.setting, err)
			case !tt.endsCLITokens && err != nil:
				t.Errorf("a token of the CLI's exchange after a change of auth.oidc.%s: got %v, want it accepted", tt.setting, err)
			}
			for what, token := range map[string]string{"a person's token": own.Token, "a service account's token": botToken.Token} {
				if _, _, err := tokensOf(after).GetByToken(ctx, token); err != nil {
					t.Errorf("%s after a change of auth.oidc.%s: got %v, want it accepted", what, tt.setting, err)
				}
			}
		})
	}
	for _, f := range reflect.VisibleFields(reflect.TypeFor[config.OIDC]()) {
		if setting := strings.Split(f.Tag.Get("yaml"), ",")[0]; !named[setting] {
			t.Errorf("auth.oidc.%s: the test does not say whether a change of it ends the sessions and the CLI's tokens", setting)
		}
	}
}

// Security test ST-14: a session keeps the roles of its sign-in, so a replica
// that runs another sign-in configuration than the one that created the
// session refuses it, as the server does after a change and a restart: a
// replica that still runs the role mapping before refuses the sessions of the
// new one, and the other way round, and replicas of another issuer, another
// external ID claim or another client ID refuse them too, each as it refuses
// a session that does not exist. A replica that lists the same mapping and
// algorithms in another order, an algorithm twice, and other settings of
// transport and routine accepts them, and so does a replica of another CLI
// client ID. A token of the CLI's exchange is refused, as a token that does
// not exist, by every replica of another configuration but the one of
// another client ID, and the tokens that people create are accepted by every
// replica (ST-19). A break-glass session, which no sign-in configuration
// creates, is accepted by every replica
func TestAReplicaRefusesTheSessionsAndTheCLIsTokensOfAnotherSignInConfiguration(t *testing.T) {
	credential, hash, err := authn.GenerateBreakglassCredential()
	if err != nil {
		t.Fatal(err)
	}
	hashFile := filepath.Join(t.TempDir(), "breakglass-hash")
	writeSecret(t, hashFile, hash+"\n")
	d := dbtest.New(t)
	idp := newSigningProvider(t)
	idp.up.Store(true)
	another := newSigningProvider(t)
	another.up.Store(true)
	rotatedSecret := filepath.Join(t.TempDir(), "oidc-client-secret")
	writeSecret(t, rotatedSecret, "a rotated client secret\n")
	env := append(oidcEnv(t, idp.URL, writeStateKey(t)),
		"WT_AUTH_BREAKGLASS_ENABLED=true", "WT_AUTH_BREAKGLASS_CREDENTIAL_HASH_FILE="+hashFile,
		"WT_AUTH_OIDC_ROLE_MAPPING=wt-owners=owner,wt-admins=admin")
	// The person who signs in is in wt-owners, whose members the mapping
	// after makes users.
	before := startServeOn(t, d, env...)
	rotated := startServeOn(t, d, append(slices.Clone(env),
		"WT_AUTH_OIDC_ROLE_MAPPING=wt-admins=admin,wt-owners=owner",
		"WT_AUTH_OIDC_ALLOWED_ALGORITHMS=PS256,ES512,ES384,ES256,RS256,RS256",
		// The provider, at another address than the issuer's.
		"WT_AUTH_OIDC_DISCOVERY_URL="+strings.Replace(idp.URL, "127.0.0.1", "localhost", 1),
		"WT_AUTH_OIDC_CLIENT_SECRET_FILE="+rotatedSecret,
		"WT_AUTH_OIDC_STATE_KEY_FILE="+writeStateKey(t),
		"WT_AUTH_OIDC_REDIRECT_URL=https://localhost:8443/auth/callback",
		"WT_AUTH_OIDC_SCOPES=openid,profile,email")...)
	after := startServeOn(t, d, append(slices.Clone(env), "WT_AUTH_OIDC_ROLE_MAPPING=wt-owners=user,wt-admins=admin")...)
	otherIssuer := startServeOn(t, d, append(slices.Clone(env), "WT_AUTH_OIDC_ISSUER="+another.URL)...)
	otherClaim := startServeOn(t, d, append(slices.Clone(env), "WT_AUTH_OIDC_EXTERNAL_ID_CLAIM=oid")...)
	otherClient := startServeOn(t, d, append(slices.Clone(env), "WT_AUTH_OIDC_CLIENT_ID=whitetower-console-rotated")...)
	otherCLIClient := startServeOn(t, d, append(slices.Clone(env), "WT_AUTH_OIDC_CLI_CLIENT_ID=wtctl-rotated")...)
	for _, s := range []*serving{before, rotated, after, otherIssuer, otherClaim, otherClient, otherCLIClient} {
		s.waitForDiscovery(t)
	}

	signIn := func(s *serving) http.Header {
		t.Helper()
		status, session := finishSignIn(t, s.console, startSignIn(t, s.console))
		if status != http.StatusFound || session == "" {
			t.Fatalf("a sign-in: %d, session cookie %q", status, session)
		}
		return http.Header{"Cookie": {session}}
	}
	// refuses checks that s refuses a session with the answer it gives a
	// session that does not exist, which says nothing of the configuration.
	type problem struct {
		Type, Title, Detail, Code string
		Status                    int
	}
	problemOf := func(body string) problem {
		t.Helper()
		var p problem
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatalf("a refusal: %v: %s", err, body)
		}
		return p
	}
	// A session or an API token is refused with the answer to a credential
	// of its kind that does not exist.
	refuses := func(s *serving, what string, credential http.Header) {
		t.Helper()
		unknownCredential := http.Header{"Cookie": {authn.CookieName + "=unknown"}}
		if credential.Get("Authorization") != "" {
			unknownCredential = http.Header{"Authorization": {"Bearer " + authn.TokenPrefix + "unknown"}}
		}
		_, got := call(t, http.StatusUnauthorized, http.MethodGet, s.console+"/api/v1/me", "", credential)
		_, unknown := call(t, http.StatusUnauthorized, http.MethodGet, s.console+"/api/v1/me", "", unknownCredential)
		if problemOf(got) != problemOf(unknown) {
			t.Errorf("%s: refused with %s, want the refusal of a credential that does not exist, %s", what, got, unknown)
		}
	}

	ownerSession := signIn(before)
	for _, s := range []*serving{before, rotated, otherCLIClient} {
		if _, me := get(t, s.console+"/api/v1/me", ownerSession); !strings.Contains(me, `"roles":["owner"]`) {
			t.Errorf("/me with the session of the mapping before: %s, want the role owner", me)
		}
	}
	refuses(after, "the session of the mapping before, on a replica of the mapping after", ownerSession)
	refuses(otherIssuer, "the session of the mapping before, on a replica of another issuer", ownerSession)
	refuses(otherClaim, "the session of the mapping before, on a replica of another external ID claim", ownerSession)
	refuses(otherClient, "the session of the mapping before, on a replica of another client ID", ownerSession)

	// The person of the session logs in with the CLI on the replica before,
	// and creates a token of their own with the CLI's token.
	idToken := idp.sign(t, map[string]any{
		"iss":    idp.URL,
		"aud":    "wtctl",
		"sub":    "usr-signs-in",
		"name":   "Sam Signs-In",
		"groups": []string{"wt-owners"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	})
	tokenOf := func(body string) http.Header {
		t.Helper()
		var created struct{ Token string }
		if err := json.Unmarshal([]byte(body), &created); err != nil || created.Token == "" {
			t.Fatalf("a created token: %v: %s", err, body)
		}
		return http.Header{"Authorization": {"Bearer " + created.Token}}
	}
	_, exchanged := call(t, http.StatusOK, http.MethodPost, before.console+"/api/v1/tokens/exchange",
		`{"idToken":"`+idToken+`"}`, http.Header{"Content-Type": {"application/json"}})
	cliToken := tokenOf(exchanged)
	_, created := call(t, http.StatusCreated, http.MethodPost, before.console+"/api/v1/tokens",
		`{"name":"sam's script","scopes":["`+string(authz.PermissionIdentityMeRead)+`"],"expiresInDays":1}`,
		http.Header{"Content-Type": {"application/json"}, "Authorization": cliToken["Authorization"]})
	ownToken := tokenOf(created)
	for _, s := range []*serving{before, rotated, otherClient} {
		if _, me := get(t, s.console+"/api/v1/me", cliToken); !strings.Contains(me, "Sam Signs-In") {
			t.Errorf("/me with the CLI's token of the mapping before: %s", me)
		}
	}
	refuses(after, "the CLI's token of the mapping before, on a replica of the mapping after", cliToken)
	refuses(otherIssuer, "the CLI's token of the mapping before, on a replica of another issuer", cliToken)
	refuses(otherClaim, "the CLI's token of the mapping before, on a replica of another external ID claim", cliToken)
	refuses(otherCLIClient, "the CLI's token of the mapping before, on a replica of another CLI client ID", cliToken)
	for _, s := range []*serving{before, rotated, after, otherIssuer, otherClaim, otherClient, otherCLIClient} {
		if _, me := get(t, s.console+"/api/v1/me", ownToken); !strings.Contains(me, "Sam Signs-In") {
			t.Errorf("/me with a token that the person created: %s", me)
		}
	}

	userSession := signIn(after)
	if _, me := get(t, after.console+"/api/v1/me", userSession); !strings.Contains(me, `"roles":["user"]`) {
		t.Errorf("/me with the session of the mapping after: %s, want the role user", me)
	}
	refuses(before, "the session of the mapping after, on a replica of the mapping before", userSession)
	refuses(rotated, "the session of the mapping after, on a replica of the mapping before in another order", userSession)

	header, _ := call(t, http.StatusOK, http.MethodPost, before.console+"/auth/breakglass",
		`{"credential":"`+credential+`"}`, http.Header{"Content-Type": {"application/json"}})
	var custodian http.Header
	for _, c := range (&http.Response{Header: header}).Cookies() {
		if c.Name == authn.CookieName {
			custodian = http.Header{"Cookie": {c.Name + "=" + c.Value}}
		}
	}
	for _, s := range []*serving{after, otherIssuer, otherClaim, otherClient} {
		if _, me := get(t, s.console+"/api/v1/me", custodian); !strings.Contains(me, `"isBreakglass":true`) {
			t.Errorf("/me with a break-glass session, on a replica of another configuration: %s", me)
		}
	}
}
