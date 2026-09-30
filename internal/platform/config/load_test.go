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

func TestDefaultsNeedCertificatesOrDevelopmentTLS(t *testing.T) {
	err := Defaults().Validate()
	for _, key := range []string{"listeners.console.cert_file", "listeners.console.key_file", "listeners.machine.cert_file", "listeners.machine.key_file"} {
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("defaults without certificates: error %v, want it to name %s", err, key)
		}
	}
	cfg := Defaults()
	cfg.Dev.SelfSignedTLS = true
	if err := cfg.Validate(); err != nil {
		t.Errorf("defaults with development TLS: %v", err)
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

func TestYAMLRoundTrip(t *testing.T) {
	cfg := Defaults()
	cfg.Listeners.Console.CertFile = "/etc/whitetower/console.crt"
	cfg.Dev.SelfSignedTLS = true
	data, err := cfg.YAML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "timeout: 8s") {
		t.Errorf("durations must print as text:\n%s", data)
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
	default:
		return "text"
	}
}
