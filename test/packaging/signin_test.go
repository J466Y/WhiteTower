package packaging

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

// Signing in ties each stack's core to its Keycloak and its realm, and the
// evaluation seed to the realm's users. CI starts only the development stack,
// so these checks keep the evaluation stack and `task run` from drifting.

// realm holds what sign-in needs of a Keycloak realm file.
type realm struct {
	Name         string        `json:"realm"`
	Clients      []realmClient `json:"clients"`
	ClientScopes []struct {
		Name string `json:"name"`
	} `json:"clientScopes"`
	Users []realmUser `json:"users"`
}

type realmUser struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Enabled  bool     `json:"enabled"`
	Groups   []string `json:"groups"`
}

type realmClient struct {
	ClientID     string            `json:"clientId"`
	Secret       string            `json:"secret"`
	RedirectURIs []string          `json:"redirectUris"`
	Attributes   map[string]string `json:"attributes"`
}

func loadRealm(t *testing.T, stack string) realm {
	t.Helper()
	path := root + "/deploy/compose/" + stack + "/keycloak/whitetower-realm.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var r realm
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return r
}

// checkClient checks that the realm registers the client of a core with
// these settings: its redirect URL, the console's root on the same origin,
// where the core sends the browser after a logout, its secret, and the
// scopes it asks for, which Keycloak refuses unless it defines them.
func (r realm) checkClient(t *testing.T, env map[string]string, secret string) {
	t.Helper()
	i := slices.IndexFunc(r.Clients, func(c realmClient) bool { return c.ClientID == env["WT_AUTH_OIDC_CLIENT_ID"] })
	if i < 0 {
		t.Fatalf("the realm has no client %q", env["WT_AUTH_OIDC_CLIENT_ID"])
	}
	client := r.Clients[i]

	redirect := withDefaults(env["WT_AUTH_OIDC_REDIRECT_URL"])
	if !slices.Contains(client.RedirectURIs, redirect) {
		t.Errorf("the redirect URL %s is not among the realm's redirect URIs %v", redirect, client.RedirectURIs)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parsing the redirect URL: %v", err)
	}
	postLogout := u.Scheme + "://" + u.Host + "/"
	postLogoutURIs := strings.Split(client.Attributes["post.logout.redirect.uris"], "##")
	if !slices.Contains(postLogoutURIs, postLogout) {
		t.Errorf("the console's root %s is not among the realm's post-logout redirect URIs %v", postLogout, postLogoutURIs)
	}
	// Exact URIs only: with a wildcard, Keycloak would send a code, or a
	// browser after a logout, to any path that matches it.
	for _, uri := range append(slices.Clone(client.RedirectURIs), postLogoutURIs...) {
		if strings.Contains(uri, "*") {
			t.Errorf("the realm registers the wildcard URI %s, where exact URIs belong", uri)
		}
	}
	if strings.TrimSpace(secret) != client.Secret {
		t.Error("the core's client secret is not the realm's")
	}

	// Keycloak accepts openid, and defines profile and email in every realm.
	defined := []string{"openid", "profile", "email"}
	for _, s := range r.ClientScopes {
		defined = append(defined, s.Name)
	}
	scopes := config.Defaults().Auth.OIDC.Scopes
	if s := env["WT_AUTH_OIDC_SCOPES"]; s != "" {
		scopes = strings.Split(s, ",")
	}
	for _, scope := range scopes {
		if !slices.Contains(defined, strings.TrimSpace(scope)) {
			t.Errorf("the core asks for the scope %q, which the realm does not define", scope)
		}
	}
}

// defaultValue matches Compose's ${VAR:-default} and Task's
// {{.VAR | default "default"}}.
var defaultValue = regexp.MustCompile(`\$\{\w+:-([^}]*)\}|\{\{\s*\.\w+\s*\|\s*default\s*"([^"]*)"\s*\}\}`)

// withDefaults returns s as Compose or Task expand it when no variable is set.
func withDefaults(s string) string {
	return defaultValue.ReplaceAllString(s, "$1$2")
}

func TestEachStackSignsInThroughItsKeycloak(t *testing.T) {
	for _, stack := range []string{"dev", "eval"} {
		t.Run(stack, func(t *testing.T) {
			dir := root + "/deploy/compose/" + stack
			cfg := loadCompose(t, dir+"/compose.yaml")
			r := loadRealm(t, stack)
			keycloak, core := cfg.Services["keycloak"], cfg.Services["whitetower"]
			env := core.Environment

			// Keycloak names itself after the address that it is published
			// at, which browsers use, and answers containers at its address
			// in the stack's network.
			published := ""
			for _, p := range keycloak.Ports {
				if strings.HasSuffix(p, ":8080") {
					published = strings.TrimSuffix(p, ":8080")
				}
			}
			hostname := keycloak.Environment["KC_HOSTNAME"]
			if hostname == "" || hostname != "http://"+published {
				t.Errorf("Keycloak's hostname %q is not its published address %q", hostname, published)
			}
			if keycloak.Environment["KC_HOSTNAME_BACKCHANNEL_DYNAMIC"] != "true" {
				t.Error("Keycloak's back channel must follow each request, so that the core reaches it in the stack's network")
			}
			if got, want := env["WT_AUTH_OIDC_ISSUER"], hostname+"/realms/"+r.Name; got != want {
				t.Errorf("the core's issuer is %q, want Keycloak's hostname and realm, %q", got, want)
			}
			if got, want := env["WT_AUTH_OIDC_DISCOVERY_URL"], "http://keycloak:8080/realms/"+r.Name; got != want {
				t.Errorf("the core's discovery URL is %q, want Keycloak's address in the stack's network, %q", got, want)
			}

			// The redirect URL is the address that the console is published
			// at: on another port, Keycloak refuses a redirect that the realm
			// does not register, rather than send the code to whatever
			// listens on 8443.
			console := ""
			for _, p := range core.Ports {
				if strings.HasSuffix(p, ":8443") {
					console = strings.TrimSuffix(p, ":8443")
				}
			}
			if got, want := env["WT_AUTH_OIDC_REDIRECT_URL"], "https://"+console+"/auth/callback"; console == "" || got != want {
				t.Errorf("the core's redirect URL is %q, want the console's published address, %q", got, want)
			}

			// The core reads the client's secret and the state key from
			// files. It discovers the provider in the background, and
			// starts once Keycloak is ready, so that sign-in is available
			// as soon as the core is.
			if env["WT_AUTH_OIDC_CLIENT_SECRET_FILE"] != "/run/secrets/oidc-client-secret" || !slices.Contains(core.Secrets, "oidc-client-secret") {
				t.Error("the core does not receive the secret oidc-client-secret")
			}
			secret, err := os.ReadFile(filepath.Join(dir, cfg.Secrets["oidc-client-secret"].File))
			if err != nil {
				t.Fatalf("reading the client secret: %v", err)
			}
			if env["WT_AUTH_OIDC_STATE_KEY_FILE"] != "/run/secrets/oidc-state-key" || !slices.Contains(core.Secrets, "oidc-state-key") {
				t.Error("the core does not receive the secret oidc-state-key")
			}
			checkStateKey(t, filepath.Join(dir, cfg.Secrets["oidc-state-key"].File))
			if core.DependsOn["keycloak"].Condition != "service_healthy" {
				t.Error("the core does not wait for a healthy Keycloak")
			}
			r.checkClient(t, env, string(secret))
		})
	}
}

// `task run` runs the core on the host, which reaches the development
// Keycloak at its issuer.
func TestTaskRunSignsInThroughTheDevelopmentKeycloak(t *testing.T) {
	data, err := os.ReadFile(root + "/Taskfile.yml")
	if err != nil {
		t.Fatal(err)
	}
	// Only the run task is decoded: the others may take any form that Task
	// accepts, such as a variable that a command computes.
	var taskfile struct {
		Tasks map[string]yaml.Node `yaml:"tasks"`
	}
	if err := yaml.Unmarshal(data, &taskfile); err != nil {
		t.Fatalf("parsing Taskfile.yml: %v", err)
	}
	var run struct {
		Env map[string]string `yaml:"env"`
	}
	node, ok := taskfile.Tasks["run"]
	if !ok {
		t.Fatal("Taskfile.yml has no run task")
	}
	if err := node.Decode(&run); err != nil {
		t.Fatalf("parsing the run task: %v", err)
	}
	env := run.Env
	dev := loadCompose(t, root+"/deploy/compose/dev/compose.yaml").Services["whitetower"].Environment

	if got, want := withDefaults(env["WT_AUTH_OIDC_ISSUER"]), withDefaults(dev["WT_AUTH_OIDC_ISSUER"]); got != want {
		t.Errorf("task run's issuer is %q, want the development core's, %q", got, want)
	}
	if env["WT_AUTH_OIDC_DISCOVERY_URL"] != "" {
		t.Error("task run needs no discovery URL: the host reaches Keycloak at the issuer")
	}
	secret, err := os.ReadFile(root + "/" + env["WT_AUTH_OIDC_CLIENT_SECRET_FILE"])
	if err != nil {
		t.Fatalf("reading task run's client secret: %v", err)
	}
	loadRealm(t, "dev").checkClient(t, env, string(secret))
	checkStateKey(t, root+"/"+env["WT_AUTH_OIDC_STATE_KEY_FILE"])
}

// checkStateKey checks that the file holds a key that the core accepts to
// sign the state of a sign-in.
func checkStateKey(t *testing.T, path string) {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the state key: %v", err)
	}
	if _, err := authn.ParseStateKey(text); err != nil {
		t.Errorf("the state key of %s: %v", path, err)
	}
}

// Both realms have the same users. Each has a fixed ID, which Keycloak puts in
// the sub of the user's tokens: it survives a new import of the realm. CI
// signs in through the development realm only, so its users' groups, and the
// disabled account, must be the evaluation realm's too.
func TestBothRealmsHaveTheSameUsers(t *testing.T) {
	dev, eval := loadRealm(t, "dev"), loadRealm(t, "eval")
	users := map[string]realmUser{}
	for _, u := range dev.Users {
		if _, err := uuid.Parse(u.ID); err != nil {
			t.Errorf("user %s: ID %q is not a UUID", u.Username, u.ID)
		}
		for name, other := range users {
			if other.ID == u.ID {
				t.Errorf("users %s and %s share the ID %s", name, u.Username, u.ID)
			}
		}
		users[u.Username] = u
	}
	if len(eval.Users) != len(dev.Users) {
		t.Errorf("the realms have %d and %d users", len(dev.Users), len(eval.Users))
	}
	for _, u := range eval.Users {
		d := users[u.Username]
		switch {
		case d.ID != u.ID:
			t.Errorf("user %s: ID %q in the evaluation realm, %q in the development realm", u.Username, u.ID, d.ID)
		case d.Enabled != u.Enabled:
			t.Errorf("user %s: enabled %t in the evaluation realm, %t in the development realm", u.Username, u.Enabled, d.Enabled)
		case !slices.Equal(d.Groups, u.Groups):
			t.Errorf("user %s: groups %v in the evaluation realm, %v in the development realm", u.Username, u.Groups, d.Groups)
		}
	}
}

// Signing in as a user of the evaluation realm finds the principal that the
// seed wrote for it: the seed's principals have the core's issuer, and the
// IDs of the realm's users as subjects. The seed runs on every start of the
// stack, so a second run changes nothing, not even the head of the
// governance versions.
func TestTheEvaluationSeedMatchesTheRealmsUsers(t *testing.T) {
	d := dbtest.New(t)
	pool := d.Open(t)
	su := d.Superuser(t)
	ctx := context.Background()

	seed, err := os.ReadFile(root + "/deploy/compose/eval/seed/seed.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, string(seed)); err != nil {
		t.Fatalf("executing seed.sql: %v", err)
	}

	issuer := withDefaults(loadCompose(t, root+"/deploy/compose/eval/compose.yaml").Services["whitetower"].Environment["WT_AUTH_OIDC_ISSUER"])
	type user struct {
		id     string
		groups []string
	}
	users := map[string]user{}
	for _, u := range loadRealm(t, "eval").Users {
		groups := make([]string, len(u.Groups))
		for i, g := range u.Groups {
			groups[i] = strings.TrimPrefix(g, "/")
		}
		users[u.Email] = user{u.ID, groups}
	}

	readPrincipals := func() int {
		t.Helper()
		rows, err := pool.Query(ctx, "SELECT issuer, subject, email, idp_groups FROM whitetower.principals WHERE kind = 'human' ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var principalIssuer, subject, email string
			var groups []string
			if err := rows.Scan(&principalIssuer, &subject, &email, &groups); err != nil {
				t.Fatal(err)
			}
			n++
			u, ok := users[email]
			switch {
			case !ok:
				t.Errorf("%s: no user of the realm has this email", email)
			case principalIssuer != issuer:
				t.Errorf("%s: issuer %q, want the core's, %q", email, principalIssuer, issuer)
			case subject != u.id:
				t.Errorf("%s: subject %q, want the ID of the realm's user, %q", email, subject, u.id)
			case !slices.Equal(groups, u.groups):
				t.Errorf("%s: groups %v, want those of its ID tokens, %v", email, groups, u.groups)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if seeded := readPrincipals(); seeded < 7 {
		t.Fatalf("the seed wrote %d principals, want at least 7", seeded)
	}

	// snapshot returns the number and a digest of the rows of each table
	// that the seed writes, and of the head that its governance states take
	// their version from.
	snapshot := func() map[string]string {
		t.Helper()
		rows := map[string]string{}
		for _, table := range []string{"principals", "role_bindings", "use_cases", "agents", "agent_owners", "governance_state", "governance_head"} {
			var digest string
			if err := su.QueryRow(ctx, "SELECT count(*) || ' rows, ' || coalesce(md5(string_agg(t::text, ',' ORDER BY t::text)), '') FROM whitetower."+table+" t").Scan(&digest); err != nil {
				t.Fatal(err)
			}
			rows[table] = digest
		}
		return rows
	}
	before := snapshot()
	if _, err := su.Exec(ctx, string(seed)); err != nil {
		t.Fatalf("executing seed.sql a second time: %v", err)
	}
	for table, after := range snapshot() {
		if after != before[table] {
			t.Errorf("a second run of the seed changed whitetower.%s: %s, then %s", table, before[table], after)
		}
	}
}
