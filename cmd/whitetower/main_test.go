package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/J466Y/WhiteTower/internal/server"
)

func TestVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "whitetower dev") {
		t.Fatalf("output %q, want it to start with \"whitetower dev\"", stdout.String())
	}
}

func TestUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-no-such-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}

func TestHealthcheckFlag(t *testing.T) {
	healthy := httptest.NewServer(server.NewHandler())
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
		{name: "healthy server", addr: healthy.Listener.Addr().String(), want: 0},
		{name: "unhealthy server", addr: failing.Listener.Addr().String(), want: 1},
		{name: "nothing listening", addr: unusedAddr(t), want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-healthcheck", "-addr", tt.addr}, &stdout, &stderr); code != tt.want {
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
