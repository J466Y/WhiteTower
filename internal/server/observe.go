package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/tracing"
)

// RequestIDHeader carries the ID of a request in its response.
const RequestIDHeader = "X-Request-Id"

// Observer instruments the console and machine listeners (requirement
// OPS-05). Every request gets an ID, sent back in X-Request-Id, and a server
// span that continues the caller's W3C trace context; it is counted, timed
// and, once it ends, logged with both IDs, so that it can be followed through
// the logs and the traces.
type Observer struct {
	logger     *slog.Logger
	metrics    *metrics.HTTP
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
}

// NewObserver returns an observer that logs to logger, counts in m and makes
// spans with tp.
func NewObserver(logger *slog.Logger, m *metrics.HTTP, tp trace.TracerProvider) *Observer {
	return &Observer{
		logger:     logger,
		metrics:    m,
		tracer:     tp.Tracer("github.com/J466Y/WhiteTower/internal/server"),
		propagator: tracing.Propagator(),
	}
}

// Wrap instruments the handler of the named listener. The route of a request
// is the ServeMux pattern that matched it, so no handler between Wrap and the
// muxes may replace the request.
func (o *Observer) Wrap(listener string, next http.Handler) http.Handler {
	inFlight := o.metrics.InFlight(listener)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := uuid.Must(uuid.NewV7()).String()
		method := metrics.Method(r.Method)
		attrs := []attribute.KeyValue{
			semconv.HTTPRequestMethodKey.String(method),
			semconv.URLPath(r.URL.Path),
			semconv.URLScheme(scheme(r)),
			semconv.NetworkProtocolVersion(protocolVersion(r)),
			semconv.ClientAddress(clientAddress(r)),
			attribute.String("whitetower.request_id", id),
		}
		spanName := method
		if method != r.Method {
			spanName = "HTTP"
			attrs = append(attrs, semconv.HTTPRequestMethodOriginal(r.Method))
		}
		ctx := logging.WithRequest(r.Context(), id)
		ctx = o.propagator.Extract(ctx, propagation.HeaderCarrier(r.Header))
		ctx, span := o.tracer.Start(ctx, spanName, trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attrs...))
		r = r.WithContext(ctx)
		w.Header().Set(RequestIDHeader, id)
		rec := &recorder{ResponseWriter: w}
		inFlight.Inc()

		defer func() {
			inFlight.Dec()
			status := rec.status
			p := recover()
			switch {
			case p != nil:
				status = http.StatusInternalServerError
			case status == 0:
				status = http.StatusOK // nothing written: net/http sends 200
			}
			route := routeOf(r.Pattern)
			took := time.Since(start)
			o.metrics.Observe(listener, method, route, status, took)
			endSpan(span, spanName, route, status)
			o.log(ctx, listener, r, route, status, rec.bytes, took)
			if p != nil {
				panic(p) // net/http logs it and drops the connection
			}
		}()
		next.ServeHTTP(rec, r)
	})
}

// endSpan names the span after its route, now known, and ends it.
func endSpan(span trace.Span, name, route string, status int) {
	if route != "" {
		span.SetName(name + " " + route)
		span.SetAttributes(semconv.HTTPRoute(route))
	}
	span.SetAttributes(semconv.HTTPResponseStatusCode(status))
	if status >= http.StatusInternalServerError {
		span.SetStatus(codes.Error, http.StatusText(status))
	}
	span.End()
}

// log writes the access log. The request, trace and principal IDs come from
// ctx; the query string is left out, as it can hold credentials.
func (o *Observer) log(ctx context.Context, listener string, r *http.Request, route string, status int, bytes int64, took time.Duration) {
	level := slog.LevelInfo
	if status >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	safePath := strings.ReplaceAll(r.URL.Path, "\n", "")
	safePath = strings.ReplaceAll(safePath, "\r", "")
	o.logger.LogAttrs(ctx, level, "request",
		slog.String("listener", listener),
		slog.String("method", r.Method),
		slog.String("path", safePath),
		slog.String("route", route),
		slog.Int("status", status),
		slog.Int64("bytes", bytes),
		slog.Float64("duration_ms", float64(took.Microseconds())/1000),
		slog.String("protocol", r.Proto),
		slog.String("remote_addr", r.RemoteAddr),
	)
}

// routeOf returns the path of a ServeMux pattern: "GET /api/v1/version"
// gives "/api/v1/version".
func routeOf(pattern string) string {
	if _, path, ok := strings.Cut(pattern, " "); ok {
		return strings.TrimLeft(path, " \t")
	}
	return pattern
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// protocolVersion returns 1.1 for HTTP/1.1 and 2 for HTTP/2.0.
func protocolVersion(r *http.Request) string {
	if r.ProtoMajor >= 2 {
		return "2"
	}
	return "1.1"
}

func clientAddress(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// recorder notes the status and the size of a response. It implements
// http.Flusher, which ConnectRPC requires to stream, and Unwrap, through which
// http.ResponseController reaches the connection.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 && code >= http.StatusOK {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Flush() {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
