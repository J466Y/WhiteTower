//go:build e2e

// Package e2e holds end-to-end tests that run against a live deployment.
// Run them with `task e2e`; WT_E2E_URL selects the deployment
// (default http://127.0.0.1:8080).
package e2e

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSmoke(t *testing.T) {
	base := strings.TrimRight(os.Getenv("WT_E2E_URL"), "/")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	client := &http.Client{Timeout: 10 * time.Second}
	waitUntilHealthy(t, client, base+"/healthz", 60*time.Second)

	t.Run("public API", func(t *testing.T) {
		status, _, body := get(t, client, base+"/api/v1/version")
		if status != http.StatusOK || !strings.Contains(body, `"apiVersion":"v1"`) {
			t.Fatalf("got %d %q", status, body)
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
	})
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
