package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "whitetower.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEachCommandChecksWhatItNeeds(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("the defaults hold invalid values: %v", err)
	}

	err := Defaults().CheckServe()
	for _, key := range []string{
		"listeners.console.cert_file", "listeners.console.key_file",
		"listeners.machine.cert_file", "listeners.machine.key_file", "database.url",
	} {
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("serving with the defaults: error %v, want it to name %s", err, key)
		}
	}
	cfg := Defaults()
	cfg.Dev.SelfSignedTLS = true
	cfg.Database.URL = "postgres://whitetower_app@db/whitetower"
	if err := cfg.CheckServe(); err != nil {
		t.Errorf("serving with development TLS and a database: %v", err)
	}

	if err := Defaults().CheckMigrate(); err == nil || !strings.Contains(err.Error(), "database.migration.url") {
		t.Errorf("migrating with the defaults: error %v, want it to name database.migration.url", err)
	}
	// whitetower migrate needs no certificate, and no runtime role.
	cfg = Defaults()
	cfg.Database.Migration.URL = "postgres://whitetower_migrator@db/whitetower"
	if err := cfg.CheckMigrate(); err != nil {
		t.Errorf("migrating without certificates: %v", err)
	}
}

func TestLoadPrecedence(t *testing.T) {
	path := writeFile(t, `
listeners:
  console:
    address: "0.0.0.0:8443"
    cert_file: /etc/whitetower/console.crt
    key_file: /etc/whitetower/console.key
  machine:
    cert_file: /etc/whitetower/machine.crt
    key_file: /etc/whitetower/machine.key
shutdown:
  timeout: 5s
`)
	cfg, err := Load(path, []string{
		"WT_LISTENERS_CONSOLE_ADDRESS=:18443",
		"WT_LOG_LEVEL=debug",
		"OTHER_VARIABLE=ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Listeners.Console.Address; got != ":18443" {
		t.Errorf("console address %q: the environment must win over the file", got)
	}
	if got := cfg.Shutdown.Timeout; got != 5*time.Second {
		t.Errorf("shutdown timeout %s: the file must win over the default", got)
	}
	if got := cfg.Listeners.Machine.Address; got != "127.0.0.1:9443" {
		t.Errorf("machine address %q: unset settings keep their default", got)
	}
	if got := cfg.Log.Level; got != "debug" {
		t.Errorf("log level %q", got)
	}
}

func TestLoadWithoutFile(t *testing.T) {
	cfg, err := Load("", []string{"WT_DEV_SELF_SIGNED_TLS=true", "WT_SHUTDOWN_TIMEOUT=3s"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Dev.SelfSignedTLS || cfg.Shutdown.Timeout != 3*time.Second {
		t.Fatalf("got %+v", cfg)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := writeFile(t, "listeners:\n  console:\n    no_such_setting: \":8443\"\n")
	_, err := Load(path, nil)
	if err == nil || !strings.Contains(err.Error(), "no_such_setting") {
		t.Fatalf("error %v, want it to name the unknown key", err)
	}
}

func TestLoadNamesTheBadSetting(t *testing.T) {
	tests := []struct {
		name    string
		environ []string
		want    string
	}{
		{"address", []string{"WT_LISTENERS_MACHINE_ADDRESS=9443"}, "listeners.machine.address"},
		{"port", []string{"WT_LISTENERS_OPERATIONS_ADDRESS=127.0.0.1:http"}, "listeners.operations.address"},
		{"TLS version", []string{"WT_TLS_MIN_VERSION=1.1"}, "tls.min_version"},
		{"shutdown too long", []string{"WT_SHUTDOWN_TIMEOUT=10s"}, "shutdown.timeout"},
		{"shutdown zero", []string{"WT_SHUTDOWN_TIMEOUT=0s"}, "shutdown.timeout"},
		{"log level", []string{"WT_LOG_LEVEL=verbose"}, "log.level"},
		{"duration syntax", []string{"WT_SHUTDOWN_TIMEOUT=8"}, "WT_SHUTDOWN_TIMEOUT"},
		{"boolean syntax", []string{"WT_DEV_SELF_SIGNED_TLS=maybe"}, "WT_DEV_SELF_SIGNED_TLS"},
		{"number syntax", []string{"WT_TRACING_SAMPLE_RATIO=half"}, "WT_TRACING_SAMPLE_RATIO"},
		{"sample ratio", []string{"WT_TRACING_SAMPLE_RATIO=1.5"}, "tracing.sample_ratio"},
		{"OTLP over gRPC", []string{"WT_TRACING_OTLP_ENDPOINT=grpc://collector:4317"}, "tracing.otlp.endpoint"},
		{"OTLP without host", []string{"WT_TRACING_OTLP_ENDPOINT=https:///v1"}, "tracing.otlp.endpoint"},
		{"OTLP with a query", []string{"WT_TRACING_OTLP_ENDPOINT=https://collector:4318/?tenant=a"}, "tracing.otlp.endpoint"},
		{"CA file without https", []string{"WT_TRACING_OTLP_ENDPOINT=http://collector:4318", "WT_TRACING_OTLP_CA_FILE=/ca.pem"}, "tracing.otlp.ca_file"},
		{"database scheme", []string{"WT_DATABASE_URL=mysql://app@db/whitetower"}, "database.url"},
		{"database key-value string", []string{"WT_DATABASE_URL=host=db user=app"}, "database.url"},
		{"password in the database URL", []string{"WT_DATABASE_URL=postgres://app:secret@db/whitetower"}, "database.url"},
		{"password parameter", []string{"WT_DATABASE_MIGRATION_URL=postgres://owner@db/whitetower?password=secret"}, "database.migration.url"},
		{"TLS key password parameter", []string{"WT_DATABASE_MIGRATION_URL=postgres://owner@db/whitetower?sslpassword=secret"}, "database.migration.url"},
		{"no connections", []string{"WT_DATABASE_MAX_CONNECTIONS=0"}, "database.max_connections"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load("", append([]string{"WT_DEV_SELF_SIGNED_TLS=true"}, tt.environ...))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want it to name %s", err, tt.want)
			}
		})
	}
}

// A credential in the endpoint must not reach the error, which is printed and
// may be logged.
func TestEndpointErrorsDoNotRepeatTheURL(t *testing.T) {
	for _, endpoint := range []string{
		"https://user:canary-5e3f@collector:4318",
		"https://collector:4318/?api_key=canary-5e3f",
		"https://collector:4318/%zzcanary-5e3f",
	} {
		_, err := Load("", []string{"WT_DEV_SELF_SIGNED_TLS=true", "WT_TRACING_OTLP_ENDPOINT=" + endpoint})
		if err == nil || !strings.Contains(err.Error(), "tracing.otlp.endpoint") {
			t.Fatalf("%s: error %v, want it to name tracing.otlp.endpoint", endpoint, err)
		}
		if strings.Contains(err.Error(), "canary-5e3f") {
			t.Fatalf("the error repeats the endpoint: %v", err)
		}
	}
}

// The same holds for the database URLs, which name roles with privileges.
func TestDatabaseURLErrorsDoNotRepeatTheURL(t *testing.T) {
	for _, env := range []string{
		"WT_DATABASE_URL=postgres://app:canary-5e3f@db/whitetower",
		"WT_DATABASE_URL=postgres://app@db/whitetower?password=canary-5e3f",
		"WT_DATABASE_MIGRATION_URL=postgres://owner@db/whitetower?sslpassword=canary-5e3f",
		"WT_DATABASE_MIGRATION_URL=postgres://owner:canary-5e3f@db/%zz",
	} {
		_, err := Load("", []string{"WT_DEV_SELF_SIGNED_TLS=true", env})
		if err == nil || !strings.Contains(err.Error(), "database.") {
			t.Fatalf("%s: error %v, want it to name the setting", env, err)
		}
		if strings.Contains(err.Error(), "canary-5e3f") {
			t.Fatalf("the error repeats the URL: %v", err)
		}
	}
}

func TestYAMLRoundTrip(t *testing.T) {
	data, err := Defaults().YAML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "sample_ratio: 1\n") {
		t.Errorf("a whole number must print plainly:\n%s", data)
	}

	cfg := Defaults()
	cfg.Listeners.Console.CertFile = "/etc/whitetower/console.crt"
	cfg.Tracing.SampleRatio = 0.25
	cfg.Tracing.OTLP.Endpoint = "https://otel-collector:4318"
	cfg.Dev.SelfSignedTLS = true
	data, err = cfg.YAML()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"timeout: 8s", "sample_ratio: 0.25"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %q:\n%s", want, data)
		}
	}
	var back Config
	if err := decodeYAML(data, &back); err != nil {
		t.Fatalf("the printed configuration does not load back: %v\n%s", err, data)
	}
	if !reflect.DeepEqual(back, cfg) {
		t.Fatalf("round trip changed the configuration:\n got %+v\nwant %+v", back, cfg)
	}
}

func TestEverySettingHasAnEnvironmentVariable(t *testing.T) {
	cfg := Defaults()
	seen := map[string]string{}
	for _, s := range settings(reflect.ValueOf(&cfg).Elem(), nil) {
		if other, ok := seen[s.Env]; ok {
			t.Errorf("%s and %s share the variable %s", s.Key(), other, s.Env)
		}
		seen[s.Env] = s.Key()
		if err := setFromString(s.Value, zeroText(s.Value)); err != nil {
			t.Errorf("%s cannot be set from the environment: %v", s.Key(), err)
		}
	}
}

// zeroText returns a valid textual value for a setting's type.
func zeroText(v reflect.Value) string {
	switch {
	case v.Type() == durationType:
		return "1s"
	case v.Kind() == reflect.Bool:
		return "false"
	case v.Kind() == reflect.Int || v.Kind() == reflect.Int64:
		return "0"
	case v.Kind() == reflect.Float64:
		return "0.5"
	default:
		return "text"
	}
}
