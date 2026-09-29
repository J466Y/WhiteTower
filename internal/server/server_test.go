package server_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/J466Y/WhiteTower/internal/server"
	"github.com/J466Y/WhiteTower/internal/webui"
	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

func TestHandler(t *testing.T) {
	srv := httptest.NewServer(server.NewHandler())
	t.Cleanup(srv.Close)

	t.Run("health check", func(t *testing.T) {
		got := get(t, srv.URL+"/healthz")
		if got.status != http.StatusOK || got.body != "ok\n" {
			t.Fatalf("got %d %q, want 200 \"ok\\n\"", got.status, got.body)
		}
	})

	t.Run("public API version", func(t *testing.T) {
		got := get(t, srv.URL+"/api/v1/version")
		if got.status != http.StatusOK {
			t.Fatalf("status %d, want 200", got.status)
		}
		var info struct {
			Version    string `json:"version"`
			Commit     string `json:"commit"`
			APIVersion string `json:"apiVersion"`
		}
		if err := json.Unmarshal([]byte(got.body), &info); err != nil {
			t.Fatalf("decoding %q: %v", got.body, err)
		}
		if info.Version != "dev" || info.APIVersion != "v1" || info.Commit == "" {
			t.Fatalf("got %+v, want version dev, apiVersion v1 and a commit", info)
		}
	})

	t.Run("module API", func(t *testing.T) {
		client := modulev1alpha1connect.NewMetaServiceClient(srv.Client(), srv.URL)
		resp, err := client.GetServerInfo(context.Background(),
			connect.NewRequest(&modulev1alpha1.GetServerInfoRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(resp.Msg.GetContractVersions(), "v1alpha1") {
			t.Fatalf("contract versions %v, want v1alpha1", resp.Msg.GetContractVersions())
		}
	})

	t.Run("console with strict CSP", func(t *testing.T) {
		got := get(t, srv.URL+"/")
		if got.status != http.StatusOK || !strings.Contains(got.body, "White Tower") {
			t.Fatalf("got %d, want 200 with the console page", got.status)
		}
		if csp := got.header.Get("Content-Security-Policy"); csp != webui.ContentSecurityPolicy {
			t.Fatalf("Content-Security-Policy %q", csp)
		}
		if got.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("missing X-Content-Type-Options: nosniff")
		}
	})

	t.Run("client-side route falls back to the console", func(t *testing.T) {
		got := get(t, srv.URL+"/agents/42")
		if got.status != http.StatusOK || !strings.Contains(got.body, "White Tower") {
			t.Fatalf("got %d, want 200 with the console page", got.status)
		}
	})

	t.Run("missing asset is not found", func(t *testing.T) {
		if got := get(t, srv.URL+"/assets/missing.js"); got.status != http.StatusNotFound {
			t.Fatalf("status %d, want 404", got.status)
		}
	})

	t.Run("console rejects other methods", func(t *testing.T) {
		resp, err := srv.Client().Post(srv.URL+"/", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", resp.StatusCode)
		}
	})
}

func TestServeShutsDownWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, listener, server.Config{ShutdownTimeout: 5 * time.Second},
			slog.New(slog.DiscardHandler))
	}()

	if got := get(t, "http://"+listener.Addr().String()+"/healthz"); got.status != http.StatusOK {
		t.Fatalf("status %d, want 200", got.status)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
}

type response struct {
	status int
	header http.Header
	body   string
}

func get(t *testing.T, url string) response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: string(body)}
}
