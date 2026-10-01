package tracing

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/version"
)

var testVersion = version.Info{Version: "1.2.3", Commit: "abc1234"}

// collector is a fake OTLP/HTTP receiver. It answers with the given statuses
// in turn, then with 200, and keeps the spans it accepts.
type collector struct {
	*httptest.Server

	mu       sync.Mutex
	statuses []int
	requests int
	header   http.Header
	spans    []*tracepb.Span
	resource map[string]string
}

func newCollector(t *testing.T, statuses ...int) *collector {
	t.Helper()
	c := &collector{statuses: statuses, resource: map[string]string{}}
	c.Server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.Close)
	return c
}

func (c *collector) serve(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	c.header = r.Header.Clone()
	if len(c.statuses) > 0 {
		status := c.statuses[0]
		c.statuses = c.statuses[1:]
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/traces" || r.Header.Get("Content-Encoding") != "gzip" {
		http.Error(w, "unexpected request", http.StatusBadRequest)
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var td tracepb.TracesData
	if err := proto.Unmarshal(data, &td); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, rs := range td.GetResourceSpans() {
		for _, kv := range rs.GetResource().GetAttributes() {
			c.resource[kv.GetKey()] = kv.GetValue().GetStringValue()
		}
		for _, ss := range rs.GetScopeSpans() {
			c.spans = append(c.spans, ss.GetSpans()...)
		}
	}
}

func (c *collector) got() (requests int, spans []*tracepb.Span) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, slices.Clone(c.spans)
}

func sampledParent() trace.SpanContext {
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36},
		SpanID:     trace.SpanID{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
}

// With the default configuration, spans give the logs their IDs and nothing
// leaves the process, whatever the standard OpenTelemetry variables say
// (requirement NFR-14).
func TestDefaultsSendNothing(t *testing.T) {
	c := newCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", c.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", c.URL+"/v1/traces")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_on")

	p, err := New(config.Defaults().Tracing, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	tracer := p.TracerProvider().Tracer("test")
	_, root := tracer.Start(context.Background(), "root")
	_, child := tracer.Start(trace.ContextWithRemoteSpanContext(context.Background(), sampledParent()), "child")
	for _, span := range []trace.Span{root, child} {
		if !span.SpanContext().IsValid() {
			t.Error("a span without IDs: the logs would get no trace ID")
		}
		if span.IsRecording() {
			t.Error("a span is recorded with nowhere to send it")
		}
		span.End()
	}
	if child.SpanContext().TraceID() != sampledParent().TraceID() {
		t.Error("the caller's trace ID was not kept")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests, _ := c.got(); requests != 0 {
		t.Fatalf("%d requests reached the collector, want none", requests)
	}
}

func TestExportsToTheEndpoint(t *testing.T) {
	c := newCollector(t)
	cfg := config.Defaults().Tracing
	cfg.OTLP.Endpoint = c.URL + "/"
	p, err := New(cfg, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	_, span := p.TracerProvider().Tracer("test").Start(context.Background(), "GET /api/v1/version",
		trace.WithAttributes(attribute.String("whitetower.request_id", "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59")))
	span.End()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, spans := c.got()
	if len(spans) != 1 || spans[0].GetName() != "GET /api/v1/version" {
		t.Fatalf("got %v", spans)
	}
	if got := hex.EncodeToString(spans[0].GetTraceId()); got != span.SpanContext().TraceID().String() {
		t.Errorf("trace ID %s, want %s", got, span.SpanContext().TraceID())
	}
	if c.resource["service.name"] != "whitetower" || c.resource["service.version"] != "1.2.3" {
		t.Errorf("resource %v", c.resource)
	}
	if c.header.Get("Content-Type") != "application/x-protobuf" || c.header.Get("User-Agent") != "whitetower/1.2.3" {
		t.Errorf("headers %v", c.header)
	}
}

func TestSamplingFollowsTheCaller(t *testing.T) {
	cfg := config.Defaults().Tracing
	cfg.OTLP.Endpoint = newCollector(t).URL
	cfg.SampleRatio = 0
	p, err := New(cfg, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	tracer := p.TracerProvider().Tracer("test")
	if _, root := tracer.Start(context.Background(), "root"); root.IsRecording() {
		t.Error("a sample ratio of 0 recorded a new trace")
	}
	if _, child := tracer.Start(trace.ContextWithRemoteSpanContext(context.Background(), sampledParent()), "child"); !child.IsRecording() {
		t.Error("the trace of a caller that samples it was not recorded")
	}
}

func TestPropagatorReadsW3CTraceContextOnly(t *testing.T) {
	if got := Propagator().Fields(); !slices.Equal(got, []string{"traceparent", "tracestate"}) {
		t.Fatalf("fields %v", got)
	}
	h := http.Header{}
	h.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.Set("Baggage", "user=someone")
	ctx := Propagator().Extract(context.Background(), propagation.HeaderCarrier(h))
	if sc := trace.SpanContextFromContext(ctx); !sc.IsRemote() || sc.TraceID() != sampledParent().TraceID() {
		t.Fatalf("span context %v", sc)
	}
}

func TestUploadRetries(t *testing.T) {
	retryDelay = time.Millisecond
	t.Cleanup(func() { retryDelay = time.Second })
	for _, tt := range []struct {
		name     string
		statuses []int
		wantErr  bool
		requests int
	}{
		{"recovers after 503, 429 and 502", []int{503, 429, 502}, false, 4},
		{"gives up after five attempts", []int{503, 503, 503, 503, 503, 503}, true, 5},
		{"does not retry a refusal", []int{400}, true, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCollector(t, tt.statuses...)
			client, err := newHTTPClient(config.OTLP{Endpoint: c.URL}, testVersion)
			if err != nil {
				t.Fatal(err)
			}
			err = client.UploadTraces(context.Background(), nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error %v, want an error: %v", err, tt.wantErr)
			}
			if requests, _ := c.got(); requests != tt.requests {
				t.Fatalf("%d requests, want %d", requests, tt.requests)
			}
		})
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	elsewhere := newCollector(t)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/v1/traces", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)
	client, err := newHTTPClient(config.OTLP{Endpoint: redirecting.URL}, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UploadTraces(context.Background(), nil); err == nil {
		t.Fatal("a redirect counted as a success")
	}
	if requests, _ := elsewhere.got(); requests != 0 {
		t.Fatal("the client followed the redirect")
	}
}

func TestCAFile(t *testing.T) {
	retryDelay = time.Millisecond
	t.Cleanup(func() { retryDelay = time.Second })
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	trusted, err := newHTTPClient(config.OTLP{Endpoint: srv.URL, CAFile: caFile}, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := trusted.UploadTraces(context.Background(), nil); err != nil {
		t.Fatalf("with the CA file: %v", err)
	}

	untrusted, err := newHTTPClient(config.OTLP{Endpoint: srv.URL}, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := untrusted.UploadTraces(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("without the CA file: %v, want a certificate error", err)
	}

	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("no certificate here"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newHTTPClient(config.OTLP{Endpoint: srv.URL, CAFile: notPEM}, testVersion); err == nil {
		t.Fatal("a CA file without certificates was accepted")
	}
}

func TestErrorHandlerLogsAtMostOnceAMinute(t *testing.T) {
	var buf bytes.Buffer
	h := ErrorHandler(slog.New(slog.NewJSONHandler(&buf, nil))).(*errorHandler)
	for range 3 {
		h.Handle(errors.New("receiver down"))
	}
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Fatalf("%d lines logged, want 1:\n%s", n, buf.String())
	}
	h.mu.Lock()
	h.last = h.last.Add(-2 * time.Minute)
	h.mu.Unlock()
	h.Handle(errors.New("receiver down"))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var second struct {
		Error      string `json:"error"`
		Suppressed int    `json:"suppressed"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &second); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || second.Suppressed != 2 || second.Error != "receiver down" {
		t.Fatalf("got %d lines, the last %+v", len(lines), second)
	}
}
