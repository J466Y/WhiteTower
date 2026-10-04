package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/internal/server"
	"github.com/J466Y/WhiteTower/internal/version"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

// syncBuffer is a bytes.Buffer that handlers and the test may share.
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

// observed is an observer whose logs, spans and metrics the test reads.
type observed struct {
	*server.Observer
	logs    *syncBuffer
	spans   *tracetest.SpanRecorder
	metrics *metrics.HTTP
	scrape  func() string
}

func newObserved(t *testing.T) *observed {
	t.Helper()
	logs := &syncBuffer{}
	spans := tracetest.NewSpanRecorder()
	registry := metrics.NewRegistry(version.Get())
	m := metrics.NewHTTP(registry)
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return &observed{
		Observer: server.NewObserver(logging.New(logs, "info"), m, tp),
		logs:     logs,
		spans:    spans,
		metrics:  m,
		scrape: func() string {
			rec := httptest.NewRecorder()
			metrics.Handler(registry).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			return rec.Body.String()
		},
	}
}

func (o *observed) span(t *testing.T) sdktrace.ReadOnlySpan {
	t.Helper()
	ended := o.spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("%d spans ended, want 1", len(ended))
	}
	return ended[0]
}

func attr(span sdktrace.ReadOnlySpan, key string) string {
	for _, kv := range span.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.String()
		}
	}
	return ""
}

const (
	callerTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	callerSpan  = "00f067aa0ba902b7"
)

// The criterion of plan P1-01, step 3: a request can be followed through the
// logs and the traces by its IDs.
func TestARequestCanBeFollowedByItsIDs(t *testing.T) {
	o := newObserved(t)
	srv := httptest.NewServer(o.Wrap("console", server.ConsoleHandler(publicAPI())))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/api/v1/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Traceparent", "00-"+callerTrace+"-"+callerSpan+"-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	id := resp.Header.Get(server.RequestIDHeader)
	if u, err := uuid.Parse(id); err != nil || u.Version() != 7 {
		t.Fatalf("request ID %q, want a UUIDv7", id)
	}

	span := o.span(t)
	if span.SpanContext().TraceID().String() != callerTrace || span.Parent().SpanID().String() != callerSpan {
		t.Errorf("span in trace %s under %s, want the caller's trace and span", span.SpanContext().TraceID(), span.Parent().SpanID())
	}
	if span.Name() != "GET /api/v1/version" || span.SpanKind() != trace.SpanKindServer {
		t.Errorf("span %q of kind %s", span.Name(), span.SpanKind())
	}
	for key, want := range map[string]string{
		"whitetower.request_id":     id,
		"http.route":                "/api/v1/version",
		"http.response.status_code": "200",
		"http.request.method":       "GET",
		"url.scheme":                "http",
	} {
		if got := attr(span, key); got != want {
			t.Errorf("span attribute %s = %q, want %q", key, got, want)
		}
	}

	logs := o.logs.records(t, "request")
	if len(logs) != 1 {
		t.Fatalf("%d access log records, want 1", len(logs))
	}
	for key, want := range map[string]any{
		"request_id": id,
		"trace_id":   callerTrace,
		"span_id":    span.SpanContext().SpanID().String(),
		"listener":   "console",
		"method":     "GET",
		"path":       "/api/v1/version",
		"route":      "/api/v1/version",
		"status":     float64(200),
		"level":      "INFO",
	} {
		if logs[0][key] != want {
			t.Errorf("access log %s = %v, want %v", key, logs[0][key], want)
		}
	}

	want := `whitetower_http_requests_total{code="200",listener="console",method="GET",route="/api/v1/version"} 1`
	if !strings.Contains(o.scrape(), want) {
		t.Errorf("metrics lack %s", want)
	}
	if v := testutil.ToFloat64(o.metrics.InFlight("console")); v != 0 {
		t.Errorf("%v requests still in flight", v)
	}
}

// everyone authenticates every request as the same principal.
type everyone struct{}

func (everyone) Authenticate(*http.Request) (*auth.Principal, error) {
	return &auth.Principal{ID: "0192f2c4-0000-7000-8000-000000000007", Kind: auth.Human}, nil
}

// Authentication hands the router a copy of the request; the route it
// matched still reaches the metrics and the access log.
func TestTheRouteSurvivesAuthentication(t *testing.T) {
	o := newObserved(t)
	api := rest.Handler(rest.Options{
		Logger:        slog.New(slog.DiscardHandler),
		Authenticator: everyone{},
		Authorizer:    auth.DenyAll{},
		Limiter:       ratelimit.New(1000, 1000),
	})
	o.Wrap("console", server.ConsoleHandler(api)).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))

	logs := o.logs.records(t, "request")
	if len(logs) != 1 || logs[0]["route"] != "/api/v1/me" || logs[0]["status"] != float64(http.StatusForbidden) ||
		logs[0]["principal_id"] != "0192f2c4-0000-7000-8000-000000000007" {
		t.Fatalf("access log %v", logs)
	}
	if want := `code="403",listener="console",method="GET",route="/api/v1/me"`; !strings.Contains(o.scrape(), want) {
		t.Fatalf("metrics lack %s", want)
	}
}

// A module API call is known by its procedure in the access log, the metrics
// and the span, and by its caller once its token is checked.
func TestModuleAPICallsAreKnownByTheirProcedure(t *testing.T) {
	o := newObserved(t)
	h := o.Wrap("machine", server.MachineHandler(moduleAPI(prometheus.NewRegistry())))
	procedure := modulev1alpha1connect.MetaServiceGetServerInfoProcedure
	for _, token := range []string{"test", ""} {
		r := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
	}

	access := o.logs.records(t, "request")
	if len(access) != 2 ||
		access[0]["route"] != procedure || access[0]["status"] != float64(http.StatusOK) || access[0]["principal_id"] != moduleIdentity ||
		access[1]["route"] != procedure || access[1]["status"] != float64(http.StatusUnauthorized) || access[1]["principal_id"] != nil {
		t.Fatalf("access log %v", access)
	}
	for _, code := range []string{"200", "401"} {
		if want := `code="` + code + `",listener="machine",method="POST",route="` + procedure + `"`; !strings.Contains(o.scrape(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	spans := o.spans.Ended()
	if len(spans) != 2 {
		t.Fatalf("%d spans", len(spans))
	}
	for i, code := range []string{"ok", "unauthenticated"} {
		span := spans[i]
		if span.Name() != "POST "+procedure || attr(span, "rpc.method") != strings.TrimPrefix(procedure, "/") ||
			attr(span, "rpc.response.status_code") != code || span.Status().Code == codes.Error {
			t.Errorf("span %q, attributes %v, status %v", span.Name(), span.Attributes(), span.Status())
		}
	}
}

// Authentication, further down the chain, names the principal; the access log
// and the handler's own records carry it.
func TestThePrincipalReachesTheAccessLog(t *testing.T) {
	o := newObserved(t)
	logger := logging.New(o.logs, "info")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		logging.SetPrincipal(r.Context(), "0192f2c4-0000-7000-8000-000000000007")
		logger.InfoContext(r.Context(), "handled")
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	o.Wrap("console", mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))

	handled := o.logs.records(t, "handled")
	access := o.logs.records(t, "request")
	if len(handled) != 1 || len(access) != 1 {
		t.Fatalf("records: %d handled, %d access", len(handled), len(access))
	}
	for _, r := range []map[string]any{handled[0], access[0]} {
		if r["principal_id"] != "0192f2c4-0000-7000-8000-000000000007" || r["request_id"] != rec.Header().Get(server.RequestIDHeader) {
			t.Errorf("record %v lacks the principal or the request ID", r)
		}
	}
	if access[0]["status"] != float64(http.StatusNoContent) {
		t.Errorf("status %v, want 204", access[0]["status"])
	}
}

func TestFailuresUnmatchedRoutesAndOtherMethods(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /fail", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	t.Run("a server error is logged as an error and fails the span", func(t *testing.T) {
		o := newObserved(t)
		o.Wrap("console", mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/fail", nil))
		if span := o.span(t); span.Status().Code != codes.Error {
			t.Errorf("span status %v, want an error", span.Status())
		}
		if logs := o.logs.records(t, "request"); logs[0]["level"] != "ERROR" || logs[0]["status"] != float64(503) {
			t.Errorf("access log %v", logs[0])
		}
	})

	t.Run("an unmatched path has no route", func(t *testing.T) {
		o := newObserved(t)
		o.Wrap("console", mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/no/such/page", nil))
		if span := o.span(t); span.Name() != "GET" || attr(span, "http.route") != "" {
			t.Errorf("span %q with route %q", span.Name(), attr(span, "http.route"))
		}
		if !strings.Contains(o.scrape(), `code="404",listener="console",method="GET",route=""`) {
			t.Error("the 404 was not counted without a route")
		}
	})

	t.Run("a method the client made up stays out of the labels", func(t *testing.T) {
		o := newObserved(t)
		o.Wrap("console", mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("BREW", "/fail", nil))
		span := o.span(t)
		if span.Name() != "HTTP" || attr(span, "http.request.method") != "_OTHER" || attr(span, "http.request.method_original") != "BREW" {
			t.Errorf("span %q, method %q, original %q", span.Name(), attr(span, "http.request.method"), attr(span, "http.request.method_original"))
		}
		if strings.Contains(o.scrape(), "BREW") {
			t.Error("the made-up method became a label value")
		}
	})

	t.Run("a panic is recorded as a 500 and goes on to net/http", func(t *testing.T) {
		o := newObserved(t)
		func() {
			defer func() {
				if recover() == nil {
					t.Error("the panic was swallowed")
				}
			}()
			o.Wrap("console", mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/panic", nil))
		}()
		if logs := o.logs.records(t, "request"); len(logs) != 1 || logs[0]["status"] != float64(500) {
			t.Errorf("access log %v", logs)
		}
		if v := testutil.ToFloat64(o.metrics.InFlight("console")); v != 0 {
			t.Errorf("%v requests still in flight after the panic", v)
		}
	})
}

// The client chooses the method and the path. Decoded, this path would forge
// a log record and clear a terminal; the logs and the traces get it as the
// client sent it, percent-encoded, and the method escaped.
func TestClientChosenValuesAreSanitized(t *testing.T) {
	o := newObserved(t)
	const path = "/x%0A%7B%22level%22:%22ERROR%22%7D%1B%5B2J"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	// Set directly: net/http refuses such a method on the wire today, and the
	// observer does not rely on it.
	req.Method = "BREW\x1b[2J"
	o.Wrap("console", http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), req)

	const method = `BREW\x1b[2J`
	logs := o.logs.records(t, "request")
	if len(logs) != 1 || logs[0]["path"] != path || logs[0]["method"] != method {
		t.Fatalf("access log %v", logs)
	}
	span := o.span(t)
	if attr(span, "url.path") != path || attr(span, "http.request.method_original") != method {
		t.Errorf("span path %q, method %q", attr(span, "url.path"), attr(span, "http.request.method_original"))
	}
	if raw := o.logs.String(); strings.ContainsAny(raw, "\x1b\r") || strings.Count(raw, "\n") != 1 {
		t.Errorf("a control character reached the log:\n%q", raw)
	}
}

// Streams flush every message through the observer.
func TestStreamsFlowThroughTheObserver(t *testing.T) {
	o := newObserved(t)
	release := make(chan struct{})
	srv := httptest.NewServer(o.Wrap("machine", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello\n")
		w.(http.Flusher).Flush()
		<-release
	})))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	resp, err := http.Get(srv.URL + "/watch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	line := make([]byte, len("hello\n"))
	if _, err := io.ReadFull(resp.Body, line); err != nil || string(line) != "hello\n" {
		t.Fatalf("first message %q, %v: it did not get through before the stream ended", line, err)
	}
	if v := testutil.ToFloat64(o.metrics.InFlight("machine")); v != 1 {
		t.Errorf("in flight %v during the stream, want 1", v)
	}
}

// discardObserver instruments handlers for tests that look elsewhere.
func discardObserver() *server.Observer {
	return server.NewObserver(slog.New(slog.DiscardHandler), metrics.NewHTTP(metrics.NewRegistry(version.Get())),
		sdktrace.NewTracerProvider())
}
