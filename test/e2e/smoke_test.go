//go:build e2e

// Package e2e holds end-to-end tests that run against a live deployment.
// Run them with `task e2e`. WT_E2E_URL selects the console listener
// (default https://127.0.0.1:8443) and WT_E2E_OPERATIONS_URL the operations
// listener (default http://127.0.0.1:9090). The deployment may serve a
// self-signed development certificate: these tests do not verify it.
package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSmoke(t *testing.T) {
	base := envOr("WT_E2E_URL", "https://127.0.0.1:8443")
	operations := envOr("WT_E2E_OPERATIONS_URL", "http://127.0.0.1:9090")
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	waitUntilHealthy(t, client, operations+"/healthz", 60*time.Second)

	t.Run("readiness", func(t *testing.T) {
		if status, _, body := get(t, client, operations+"/readyz"); status != http.StatusOK {
			t.Fatalf("got %d %q", status, body)
		}
	})

	t.Run("public API", func(t *testing.T) {
		status, header, body := get(t, client, base+"/api/v1/version")
		if status != http.StatusOK || !strings.Contains(body, `"apiVersion":"v1"`) {
			t.Fatalf("got %d %q", status, body)
		}
		if header.Get("X-Request-Id") == "" {
			t.Fatal("missing X-Request-Id")
		}
	})

	t.Run("OpenAPI document", func(t *testing.T) {
		status, _, body := get(t, client, base+"/api/v1/openapi.json")
		if status != http.StatusOK || !strings.Contains(body, `"openapi":"3.1.0"`) {
			t.Fatalf("got %d", status)
		}
	})

	t.Run("protected operation", func(t *testing.T) {
		status, header, body := get(t, client, base+"/api/v1/me")
		if status != http.StatusUnauthorized || header.Get("Content-Type") != "application/problem+json" ||
			!strings.Contains(body, `"code":"unauthenticated"`) {
			t.Fatalf("got %d %s %q, want a 401 problem", status, header.Get("Content-Type"), body)
		}
	})

	t.Run("metrics", func(t *testing.T) {
		status, _, body := get(t, client, operations+"/metrics")
		if status != http.StatusOK {
			t.Fatalf("got %d", status)
		}
		for _, want := range []string{
			"whitetower_build_info{",
			`whitetower_http_requests_total{code="200",listener="console",method="GET",route="/api/v1/version"}`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %s", want)
			}
		}
	})

	t.Run("console", func(t *testing.T) {
		status, header, body := get(t, client, base+"/")
		if status != http.StatusOK || !strings.Contains(body, "<title>White Tower</title>") {
			t.Fatalf("got %d, want 200 with the console", status)
		}
		if csp := header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
			t.Fatalf("missing strict Content-Security-Policy, got %q", csp)
		}
		if hsts := header.Get("Strict-Transport-Security"); !strings.HasPrefix(hsts, "max-age=") {
			t.Fatalf("missing Strict-Transport-Security, got %q", hsts)
		}
	})
}

func envOr(name, fallback string) string {
	if v := strings.TrimRight(os.Getenv(name), "/"); v != "" {
		return v
	}
	return fallback
}

func waitUntilHealthy(t *testing.T, client *http.Client, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not healthy after %s (last error: %v)", url, timeout, err)
		}
		time.Sleep(time.Second)
	}
}

func get(t *testing.T, client *http.Client, url string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(body)
}
