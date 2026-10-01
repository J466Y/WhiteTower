package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/version"
)

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestRegistry(t *testing.T) {
	reg := metrics.NewRegistry(version.Info{Version: "1.2.3", Commit: "abc1234"})
	got := scrape(t, metrics.Handler(reg))
	for _, want := range []string{
		`whitetower_build_info{commit="abc1234",go_version="go`,
		`version="1.2.3"} 1`,
		"go_goroutines ",
		"process_",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestHTTP(t *testing.T) {
	reg := metrics.NewRegistry(version.Info{Version: "dev", Commit: "unknown"})
	m := metrics.NewHTTP(reg)

	inFlight := m.InFlight("console")
	inFlight.Inc()
	if v := testutil.ToFloat64(inFlight); v != 1 {
		t.Fatalf("in flight %v, want 1", v)
	}
	inFlight.Dec()

	m.Observe("console", http.MethodGet, "/api/v1/version", http.StatusOK, 20*time.Millisecond)
	m.Observe("console", http.MethodGet, "/api/v1/version", http.StatusOK, 30*time.Millisecond)
	m.Observe("machine", "BREW", "", http.StatusMethodNotAllowed, time.Millisecond)

	got := scrape(t, metrics.Handler(reg))
	for _, want := range []string{
		`whitetower_http_requests_total{code="200",listener="console",method="GET",route="/api/v1/version"} 2`,
		`whitetower_http_requests_total{code="405",listener="machine",method="_OTHER",route=""} 1`,
		`whitetower_http_request_duration_seconds_count{listener="console",method="GET",route="/api/v1/version"} 2`,
		`whitetower_http_requests_in_flight{listener="console"} 0`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "BREW") {
		t.Error("a client-chosen method became a label value")
	}
}
