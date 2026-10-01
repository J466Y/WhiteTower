package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/J466Y/WhiteTower/internal/platform/config"
)

// syncBuffer collects the server's logs while it runs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// records returns the JSON log records whose message is msg.
func (b *syncBuffer) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for line := range strings.Lines(b.buf.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// collector is a fake OTLP/HTTP receiver that keeps what it receives.
type collector struct {
	*httptest.Server
	mu       sync.Mutex
	requests int
	spans    []*tracepb.Span
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.requests++
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return
		}
		data, _ := io.ReadAll(zr)
		var td tracepb.TracesData
		if proto.Unmarshal(data, &td) == nil {
			for _, rs := range td.GetResourceSpans() {
				for _, ss := range rs.GetScopeSpans() {
					c.spans = append(c.spans, ss.GetSpans()...)
				}
			}
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *collector) got() (int, []*tracepb.Span) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, append([]*tracepb.Span(nil), c.spans...)
}

// serving is a `whitetower serve` started on free local ports.
type serving struct {
	console, machine, operations string
	logs                         *syncBuffer
	stop                         func() error
}

func startServe(t *testing.T, environ ...string) *serving {
	t.Helper()
	console, machine, operations := unusedAddr(t), unusedAddr(t), unusedAddr(t)
	cfg, err := config.Load("", append([]string{
		"WT_DEV_SELF_SIGNED_TLS=true",
		"WT_LISTENERS_CONSOLE_ADDRESS=" + console,
		"WT_LISTENERS_MACHINE_ADDRESS=" + machine,
		"WT_LISTENERS_OPERATIONS_ADDRESS=" + operations,
		"WT_SHUTDOWN_TIMEOUT=2s",
	}, environ...))
	if err != nil {
		t.Fatal(err)
	}
	s := &serving{
		console:    "https://" + console,
		machine:    "https://" + machine,
		operations: "http://" + operations,
		logs:       &syncBuffer{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, s.logs) }()
	var once sync.Once
	var result error
	s.stop = func() error {
		once.Do(func() {
			cancel()
			result = <-done
		})
		return result
	}
	t.Cleanup(func() { _ = s.stop() })

	for deadline := time.Now().Add(10 * time.Second); ; {
		if resp, err := http.Get(s.operations + "/healthz"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not become healthy; it logged:\n%s", s.logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// insecure trusts the development certificate.
var insecure = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

// call makes a request that must succeed, and returns the response's header
// and body.
func call(t *testing.T, method, url, body string, header http.Header) (http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := insecure.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: %s %s", method, url, resp.Status, data)
	}
	return resp.Header, string(data)
}

// With default settings, the server makes no outbound connection, even with
// the standard OpenTelemetry variables pointing somewhere (requirement
// NFR-14; plan P1-01 acceptance criteria).
func TestDefaultsMakeNoOutboundConnection(t *testing.T) {
	c := newCollector(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", c.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", c.URL+"/v1/traces")
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	s := startServe(t)

	call(t, http.MethodGet, s.console+"/api/v1/version", "", nil)
	call(t, http.MethodPost, s.machine+"/whitetower.module.v1alpha1.MetaService/GetServerInfo", "{}",
		http.Header{"Content-Type": {"application/json"}})
	call(t, http.MethodGet, s.operations+"/readyz", "", nil)
	_, body := call(t, http.MethodGet, s.operations+"/metrics", "", nil)
	for _, want := range []string{
		"whitetower_build_info{",
		`whitetower_http_requests_total{code="200",listener="console",method="GET",route="/api/v1/version"} 1`,
		`listener="machine",method="POST",route="/whitetower.module.v1alpha1.MetaService/"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if err := s.stop(); err != nil {
		t.Fatalf("serve returned %v", err)
	}

	if requests, _ := c.got(); requests != 0 {
		t.Fatalf("%d requests left the server for the collector, want none", requests)
	}
	access := s.logs.records(t, "request")
	if len(access) != 2 {
		t.Fatalf("%d access log records, want 2", len(access))
	}
	for _, r := range access {
		if r["request_id"] == nil || r["trace_id"] == nil {
			t.Errorf("access log without its IDs: %v", r)
		}
	}
}

// The criterion of plan P1-01, step 3, through the server binary's own wiring:
// the response, the access log and the exported span share their IDs.
func TestARequestIsFollowedThroughLogsAndExportedTraces(t *testing.T) {
	const callerTrace, callerSpan = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	c := newCollector(t)
	s := startServe(t, "WT_TRACING_OTLP_ENDPOINT="+c.URL)

	header, _ := call(t, http.MethodGet, s.console+"/api/v1/version", "",
		http.Header{"Traceparent": {"00-" + callerTrace + "-" + callerSpan + "-01"}})
	requestID := header.Get("X-Request-Id")
	if err := s.stop(); err != nil { // shutting down sends the last spans
		t.Fatalf("serve returned %v", err)
	}

	_, spans := c.got()
	var exported *tracepb.Span
	for _, span := range spans {
		if hex.EncodeToString(span.GetTraceId()) == callerTrace {
			exported = span
		}
	}
	if exported == nil {
		t.Fatalf("no span of the caller's trace among %d exported", len(spans))
	}
	if hex.EncodeToString(exported.GetParentSpanId()) != callerSpan || exported.GetName() != "GET /api/v1/version" {
		t.Errorf("span %q under %x", exported.GetName(), exported.GetParentSpanId())
	}
	var spanRequestID string
	for _, kv := range exported.GetAttributes() {
		if kv.GetKey() == "whitetower.request_id" {
			spanRequestID = kv.GetValue().GetStringValue()
		}
	}
	if spanRequestID != requestID {
		t.Errorf("span request ID %q, response %q", spanRequestID, requestID)
	}

	access := s.logs.records(t, "request")
	if len(access) != 1 {
		t.Fatalf("%d access log records, want 1", len(access))
	}
	for key, want := range map[string]string{
		"request_id": requestID,
		"trace_id":   callerTrace,
		"span_id":    hex.EncodeToString(exported.GetSpanId()),
	} {
		if access[0][key] != want {
			t.Errorf("access log %s = %v, want %s", key, access[0][key], want)
		}
	}
	if len(s.logs.records(t, "exporting traces")) != 1 {
		t.Error("the server did not log where it exports traces")
	}
}
