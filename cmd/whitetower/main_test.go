package main

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/J466Y/WhiteTower/internal/platform/health"
	"github.com/J466Y/WhiteTower/internal/server"
)

// devEnv is the smallest valid environment: development certificates.
var devEnv = []string{"WT_DEV_SELF_SIGNED_TLS=true"}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, nil, &stdout, &stderr); code != 0 {
			t.Fatalf("%v: exit code %d, stderr %q", args, code, stderr.String())
		}
		if !strings.HasPrefix(stdout.String(), "whitetower dev (commit ") {
			t.Fatalf("%v: output %q", args, stdout.String())
		}
	}
}

func TestUsageErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--no-such-flag"}, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown flag: exit code %d, want 2", code)
	}
	if code := run([]string{"no-such-command"}, nil, &stdout, &stderr); code == 0 {
		t.Fatal("unknown command: exit code 0")
	}
}

func TestConfigPrint(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := append([]string{"WT_LISTENERS_CONSOLE_ADDRESS=:18443"}, devEnv...)
	if code := run([]string{"config", "print"}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, stderr.String())
	}
	for _, want := range []string{`address: :18443`, `self_signed_tls: true`, `timeout: 8s`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q in:\n%s", want, stdout.String())
		}
	}
}

func TestInvalidConfigurationStopsWithTheSettingNamed(t *testing.T) {
	for _, command := range []string{"serve", "healthcheck"} {
		var stdout, stderr bytes.Buffer
		env := append([]string{"WT_SHUTDOWN_TIMEOUT=30s"}, devEnv...)
		if code := run([]string{command}, env, &stdout, &stderr); code != 1 {
			t.Fatalf("%s: exit code %d, want 1", command, code)
		}
		if !strings.Contains(stderr.String(), "shutdown.timeout") {
			t.Fatalf("%s: stderr %q, want it to name shutdown.timeout", command, stderr.String())
		}
	}
}

func TestHealthcheck(t *testing.T) {
	ready := health.NewReadiness(slog.New(slog.DiscardHandler))
	healthy := httptest.NewServer(server.OperationsHandler(server.NewDrain(), ready, http.NotFoundHandler()))
	t.Cleanup(healthy.Close)
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(failing.Close)

	tests := []struct {
		name string
		addr string
		want int
	}{
		{"healthy server", healthy.Listener.Addr().String(), 0},
		{"unhealthy server", failing.Listener.Addr().String(), 1},
		{"nothing listening", unusedAddr(t), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			env := append([]string{"WT_LISTENERS_OPERATIONS_ADDRESS=" + tt.addr}, devEnv...)
			if code := run([]string{"healthcheck"}, env, &stdout, &stderr); code != tt.want {
				t.Fatalf("exit code %d, want %d (stderr %q)", code, tt.want, stderr.String())
			}
		})
	}
}

// unusedAddr returns an address where nothing listens.
func unusedAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}
