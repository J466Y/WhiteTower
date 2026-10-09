package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

// Security test ST-02: a release build refuses to start with a development
// setting. The test builds the binary as the release pipeline does, with its
// version set at link time.
func TestAReleaseBuildRefusesDevelopmentSettings(t *testing.T) {
	gotool, err := exec.LookPath("go")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal(err)
		}
		t.Skip("the go command is not on PATH")
	}
	bin := filepath.Join(t.TempDir(), "whitetower")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.CommandContext(context.Background(), gotool, "build", "-o", bin,
		"-ldflags", "-X github.com/J466Y/WhiteTower/internal/version.version=0.1.0", ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if out, err := exec.CommandContext(context.Background(), bin, "version").Output(); err != nil ||
		!strings.HasPrefix(string(out), "whitetower 0.1.0 ") {
		t.Fatalf("version: %q, %v; the release version was not set", out, err)
	}

	serve := exec.CommandContext(context.Background(), bin, "serve")
	serve.Env = []string{"WT_DEV_SELF_SIGNED_TLS=true", "WT_DATABASE_URL=postgres://whitetower_app@db.invalid/whitetower"}
	out, err := serve.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
		!strings.Contains(string(out), "dev.self_signed_tls: for development only; a release build refuses it") {
		t.Fatalf("serve: %v\n%s", err, out)
	}
}

// secretFiles are the settings that name a file holding a secret, and
// otherFiles those that name a file holding none. Every setting ending in
// _file is in one of them, so that TestSecretsNeverLeak puts a canary in
// every secret file there is.
var (
	secretFiles = []string{
		"listeners.console.key_file", "listeners.machine.key_file",
		"database.password_file", "database.migration.password_file",
	}
	otherFiles = []string{"listeners.console.cert_file", "listeners.machine.cert_file", "tracing.otlp.ca_file"}
)

// fileSettings returns the keys of the configuration that end in _file.
func fileSettings(t reflect.Type, prefix string) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		key := prefix + strings.Split(f.Tag.Get("yaml"), ",")[0]
		switch {
		case f.Type.Kind() == reflect.Struct:
			out = append(out, fileSettings(f.Type, key+".")...)
		case strings.HasSuffix(key, "_file"):
			out = append(out, key)
		}
	}
	return out
}

func TestEverySecretFileIsCovered(t *testing.T) {
	got := fileSettings(reflect.TypeFor[config.Config](), "")
	want := slices.Concat(secretFiles, otherFiles)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("settings ending in _file: %v; classified: %v. Add a new one to secretFiles or otherFiles", got, want)
	}
}

// keyPair writes a certificate and its private key for 127.0.0.1, and
// returns the base64 lines of the key, which must never leave its file.
func keyPair(t *testing.T, dir string) (certFile, keyFile string, keyLines []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "whitetower canary"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for line := range strings.Lines(string(keyPEM)) {
		if !strings.HasPrefix(line, "-----") {
			keyLines = append(keyLines, strings.TrimSpace(line))
		}
	}
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSecret(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeSecret(t, keyFile, string(keyPEM))
	return certFile, keyFile, keyLines
}

func writeSecret(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fetch makes a request that may fail, and returns all of its answer.
func fetch(t *testing.T, method, url, body string, header http.Header) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := insecure.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_ = resp.Header.Write(&b)
	_, _ = io.Copy(&b, resp.Body)
	return resp.Status + "\n" + b.String()
}

// Security test ST-03: canary values in every secret file, and in the
// credentials that callers send, never appear in the logs, the answers, the
// metrics or the traces: not as the server works, nor when the database
// refuses a password, nor from config print or a failed migrate.
func TestSecretsNeverLeak(t *testing.T) {
	d := dbtest.New(t)
	dir := t.TempDir()
	canary := func(name string) string { return "canary-" + name + "-" + rand.Text() }
	canaries := map[string]string{
		"runtime password":   canary("runtime"),
		"migration password": canary("migration"),
		"refused password":   canary("refused"),
		"bearer token":       canary("token"),
		"session cookie":     canary("cookie"),
	}

	// The runtime role's password is a canary: a role of the test's own,
	// with the runtime role's rights, has it, so that the server works.
	role := "wt_canary_" + strings.ToLower(rand.Text()[:10])
	superuser := d.Superuser(t)
	if _, err := superuser.Exec(context.Background(),
		"CREATE ROLE "+role+" LOGIN PASSWORD '"+canaries["runtime password"]+"' IN ROLE whitetower_runtime"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = superuser.Exec(context.Background(), "DROP ROLE "+role) })
	url := strings.Replace(d.Config.URL, "//"+dbtest.RuntimeRole+"@", "//"+role+"@", 1)

	certFile, keyFile, keyLines := keyPair(t, dir)
	for i, line := range keyLines {
		canaries["TLS key, line "+strconv.Itoa(i+1)] = line
	}
	runtimeFile, migrationFile, refusedFile := filepath.Join(dir, "runtime"), filepath.Join(dir, "migration"), filepath.Join(dir, "refused")
	writeSecret(t, runtimeFile, canaries["runtime password"]+"\n")
	writeSecret(t, migrationFile, canaries["migration password"]+"\n")
	writeSecret(t, refusedFile, canaries["refused password"]+"\n")

	c := newCollector(t)
	env := []string{
		"WT_DEV_SELF_SIGNED_TLS=false",
		"WT_LISTENERS_CONSOLE_CERT_FILE=" + certFile, "WT_LISTENERS_CONSOLE_KEY_FILE=" + keyFile,
		"WT_LISTENERS_MACHINE_CERT_FILE=" + certFile, "WT_LISTENERS_MACHINE_KEY_FILE=" + keyFile,
		"WT_DATABASE_URL=" + url, "WT_DATABASE_PASSWORD_FILE=" + runtimeFile,
		"WT_DATABASE_MIGRATION_URL=" + d.Config.Migration.URL, "WT_DATABASE_MIGRATION_PASSWORD_FILE=" + migrationFile,
		"WT_TRACING_OTLP_ENDPOINT=" + c.URL,
	}
	s := startServeOn(t, d, env...)
	if status, body := s.readiness(t); status != http.StatusOK {
		t.Fatalf("readyz with the canary role: %d %q", status, body)
	}

	// The answers: successes, refusals and errors on every listener, with
	// the callers' credentials.
	credentials := http.Header{
		"Authorization": {"Bearer " + canaries["bearer token"]},
		"Cookie":        {"__Host-wt_session=" + canaries["session cookie"]},
	}
	connect := http.Header{"Content-Type": {"application/json"}, "Authorization": credentials["Authorization"]}
	var answers strings.Builder
	for _, r := range []struct{ method, url, body string }{
		{http.MethodGet, s.console + "/", ""},
		{http.MethodGet, s.console + "/api/v1/version", ""},
		{http.MethodGet, s.console + "/api/v1/openapi.json", ""},
		{http.MethodGet, s.console + "/api/v1/me", ""},
		{http.MethodGet, s.console + "/api/v1/nothing-here", ""},
		{http.MethodDelete, s.console + "/api/v1/version", ""},
		{http.MethodPost, s.console + "/api/v1/me", strings.Repeat("x", 1<<20+1)},
		{http.MethodGet, s.operations + "/healthz", ""},
		{http.MethodGet, s.operations + "/readyz", ""},
		{http.MethodGet, s.operations + "/nothing-here", ""},
	} {
		answers.WriteString(fetch(t, r.method, r.url, r.body, credentials))
	}
	for _, body := range []string{"{}", "not JSON", strings.Repeat("x", 5<<20)} {
		answers.WriteString(fetch(t, http.MethodPost, s.machine+"/whitetower.module.v1alpha1.MetaService/GetServerInfo", body, connect))
	}
	answers.WriteString(fetch(t, http.MethodPost, s.machine+"/whitetower.module.v1alpha1.NoService/Nothing", "{}", connect))
	metrics := fetch(t, http.MethodGet, s.operations+"/metrics", "", nil)

	// A server whose password the database refuses logs why, but not the
	// password.
	refused := startServeOn(t, d, append(slices.Clone(env), "WT_DATABASE_PASSWORD_FILE="+refusedFile)...)
	for deadline := time.Now().Add(10 * time.Second); len(refused.logs.records(t, "readiness check failing")) == 0; {
		if status, _ := refused.readiness(t); status == http.StatusOK || time.Now().After(deadline) {
			t.Fatal("the server with a refused password did not report it")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// config print, and a migrate whose password the database refuses.
	var printed, migrated bytes.Buffer
	if code := run([]string{"config", "print"}, env, &printed, &printed); code != 0 {
		t.Fatalf("config print: exit code %d\n%s", code, printed.String())
	}
	if code := run([]string{"migrate"}, append(slices.Clone(env), "WT_DATABASE_MIGRATION_PASSWORD_FILE="+refusedFile),
		&migrated, &migrated); code == 0 {
		t.Fatal("migrate with a refused password succeeded")
	}

	if err := s.stop(); err != nil { // the last spans leave
		t.Fatalf("serve returned %v", err)
	}
	_, spans := c.got()
	if len(spans) == 0 {
		t.Fatal("no span was exported")
	}
	var traces strings.Builder
	for _, span := range spans {
		b, err := protojson.Marshal(span)
		if err != nil {
			t.Fatal(err)
		}
		traces.Write(b)
	}

	for what, output := range map[string]string{
		"logs": s.logs.String() + refused.logs.String(), "answers": answers.String(), "metrics": metrics,
		"traces": traces.String(), "config print": printed.String(), "migrate": migrated.String(),
	} {
		if output == "" {
			t.Errorf("no %s to search", what)
		}
		for name, secret := range canaries {
			if strings.Contains(output, secret) {
				t.Errorf("the %s hold the %s", what, name)
			}
		}
	}
}

// Security test ST-04: the server works with the runtime role's credentials
// only, in every session it opens; whitetower migrate is the only command
// that reads the migration role's.
func TestOnlyMigrateReadsTheMigrationRole(t *testing.T) {
	d := dbtest.New(t)
	notMounted := []string{
		"WT_DATABASE_MIGRATION_URL=" + d.Config.Migration.URL,
		"WT_DATABASE_MIGRATION_PASSWORD_FILE=" + filepath.Join(t.TempDir(), "not-mounted-here"),
	}
	s := startServeOn(t, d, notMounted...)
	if status, body := s.readiness(t); status != http.StatusOK {
		t.Fatalf("readyz: %d %q", status, body)
	}
	rows, err := d.Superuser(t).Query(context.Background(),
		"SELECT DISTINCT usename, application_name FROM pg_stat_activity WHERE datname = $1 AND application_name LIKE 'whitetower%'",
		d.Name)
	if err != nil {
		t.Fatal(err)
	}
	var sessions []string
	for rows.Next() {
		var user, application string
		if err := rows.Scan(&user, &application); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, application+" as "+user)
		if user != dbtest.RuntimeRole {
			t.Errorf("the server opened the session %q as %s", application, user)
		}
	}
	if rows.Err() != nil || !slices.Contains(sessions, "whitetower notify as "+dbtest.RuntimeRole) {
		t.Fatalf("sessions %v, %v: the listening session is missing", sessions, rows.Err())
	}

	env := slices.Concat(databaseEnv(d), devEnv, notMounted,
		[]string{"WT_LISTENERS_OPERATIONS_ADDRESS=" + strings.TrimPrefix(s.operations, "http://")})
	for _, args := range [][]string{{"config", "print"}, {"version"}, {"healthcheck"}} {
		var out bytes.Buffer
		if code := run(args, env, &out, &out); code != 0 {
			t.Errorf("%v without the migration role's password file: exit code %d\n%s", args, code, out.String())
		}
	}
	var out bytes.Buffer
	if code := run([]string{"migrate"}, env, &out, &out); code == 0 ||
		!strings.Contains(out.String(), "database.migration.password_file") {
		t.Fatalf("migrate without its password file: exit code %d\n%s", code, out.String())
	}
}
