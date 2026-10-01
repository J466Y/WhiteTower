package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
	"go.yaml.in/yaml/v3"

	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// lines decodes every JSON line written to buf.
func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(buf.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not a JSON line: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func last(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	all := lines(t, buf)
	if len(all) == 0 {
		t.Fatal("nothing logged")
	}
	return all[len(all)-1]
}

func TestTimestampsAreUTCWithMilliseconds(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.New(&buf, "info")
	when := time.Date(2026, 10, 1, 13, 4, 5, 123456789, time.FixedZone("CEST", 2*60*60))
	if err := logger.Handler().Handle(context.Background(), slog.NewRecord(when, slog.LevelInfo, "hello", 0)); err != nil {
		t.Fatal(err)
	}
	if got := last(t, &buf)["time"]; got != "2026-10-01T11:04:05.123Z" {
		t.Fatalf("time %v, want 2026-10-01T11:04:05.123Z", got)
	}

	logger.Info("now")
	got, _ := last(t, &buf)["time"].(string)
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`).MatchString(got) {
		t.Fatalf("time %q, want RFC 3339 in UTC with milliseconds", got)
	}
}

func TestLevels(t *testing.T) {
	for _, tt := range []struct {
		level string
		want  []string
	}{
		{"debug", []string{"debug", "info", "warn", "error"}},
		{"info", []string{"info", "warn", "error"}},
		{"warn", []string{"warn", "error"}},
		{"error", []string{"error"}},
	} {
		var buf bytes.Buffer
		logger := logging.New(&buf, tt.level)
		logger.Debug("debug")
		logger.Info("info")
		logger.Warn("warn")
		logger.Error("error")
		var got []string
		for _, l := range lines(t, &buf) {
			got = append(got, l["msg"].(string))
		}
		if fmt.Sprint(got) != fmt.Sprint(tt.want) {
			t.Errorf("level %s logged %v, want %v", tt.level, got, tt.want)
		}
	}
}

func TestRecordsCarryTheRequestPrincipalAndTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.New(&buf, "info").With("component", "test")

	logger.Info("outside any request")
	for _, key := range []string{"request_id", "principal_id", "trace_id", "span_id"} {
		if _, ok := last(t, &buf)[key]; ok {
			t.Errorf("%s logged outside a request", key)
		}
	}

	ctx := logging.WithRequest(context.Background(), "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59")
	logger.InfoContext(ctx, "before authentication")
	got := last(t, &buf)
	if got["request_id"] != "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59" || got["component"] != "test" {
		t.Fatalf("got %v", got)
	}
	if _, ok := got["principal_id"]; ok {
		t.Fatal("principal_id logged before authentication")
	}

	// Authentication runs further down the chain, on a derived context.
	type key struct{}
	inner := context.WithValue(ctx, key{}, "x")
	logging.SetPrincipal(inner, "user-7")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36},
		SpanID:     trace.SpanID{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7},
		TraceFlags: trace.FlagsSampled,
	})
	logger.InfoContext(trace.ContextWithSpanContext(inner, sc), "after authentication")
	got = last(t, &buf)
	want := map[string]string{
		"request_id":   "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59",
		"principal_id": "user-7",
		"trace_id":     "4bf92f3577b34da6a3ce929d0e0e4736",
		"span_id":      "00f067aa0ba902b7",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %s", k, got[k], v)
		}
	}
	// The outer context sees the principal too: the access log uses it.
	if logging.PrincipalID(ctx) != "user-7" || logging.RequestID(inner) != want["request_id"] {
		t.Fatalf("principal %q, request %q", logging.PrincipalID(ctx), logging.RequestID(inner))
	}
	logging.SetPrincipal(context.Background(), "nobody") // outside a request: no effect
	if logging.PrincipalID(context.Background()) != "" {
		t.Fatal("a principal recorded outside a request")
	}
}

const canary = "canary-7d1a"

func TestSecretNeverShowsItsValue(t *testing.T) {
	s := logging.NewSecret(canary)
	if s.Reveal() != canary || (logging.Secret{}).Reveal() != "" {
		t.Fatal("Reveal must return the value")
	}

	type holder struct {
		Token  Secret `json:"token" yaml:"token"`
		hidden Secret
	}
	h := holder{Token: s, hidden: s}
	var shown []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		shown = append(shown, fmt.Sprintf(verb, s), fmt.Sprintf(verb, h), fmt.Sprintf(verb, &h))
	}
	shown = append(shown, s.String(), fmt.Errorf("token %v refused", s).Error(), errors.New(fmt.Sprint(s)).Error())

	j, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	y, err := yaml.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := logging.New(&buf, "info")
	logger.Info("secrets", "token", s, "holder", h, "pointer", &h)
	shown = append(shown, string(j), string(y), buf.String())

	for _, out := range shown {
		if strings.Contains(out, canary) {
			t.Errorf("the secret shows: %s", out)
		}
	}
	if !strings.Contains(string(j), `"token":"[REDACTED]"`) || !strings.Contains(buf.String(), `"token":"[REDACTED]"`) {
		t.Errorf("want [REDACTED] in place of the secret:\n%s\n%s", j, buf.String())
	}
}

// Secret is the type under test, aliased so that holder reads naturally.
type Secret = logging.Secret

func TestHeaderRedactsCredentials(t *testing.T) {
	h := http.Header{
		"Authorization":        {"Bearer " + canary},
		"Proxy-Authorization":  {"Basic " + canary},
		"Cookie":               {"__Host-session=" + canary},
		"Set-Cookie":           {"__Host-session=" + canary + "; Secure"},
		"X-Api-Key":            {canary},
		"X-Amz-Security-Token": {canary},
		"X-Csrf-Token":         {canary},
		"Content-Type":         {"application/json"},
		"Accept":               {"text/html", "application/json"},
	}
	var buf bytes.Buffer
	logging.New(&buf, "info").Info("request", "headers", logging.Header(h))
	if strings.Contains(buf.String(), canary) {
		t.Fatalf("a credential shows: %s", buf.String())
	}
	got, _ := last(t, &buf)["headers"].(map[string]any)
	if got["Content-Type"] != "application/json" || got["Accept"] != "text/html, application/json" || got["Authorization"] != logging.Redacted {
		t.Fatalf("headers %v", got)
	}
}
