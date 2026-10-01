// Package tracing sets up OpenTelemetry tracing (requirement OPS-05): W3C
// Trace Context propagation, and spans exported over OTLP/HTTP only when an
// endpoint is configured (requirement NFR-14). Without one, every request
// still gets trace and span IDs, which reach the logs, but no span is
// recorded and nothing leaves the process.
package tracing

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/version"
)

// Provider makes the server's spans.
type Provider struct {
	tp *sdktrace.TracerProvider
}

// New returns a provider configured by cfg. With an OTLP endpoint, spans are
// sent in batches in the background, and Shutdown sends the last ones.
func New(cfg config.Tracing, v version.Info) (*Provider, error) {
	opts := []sdktrace.TracerProviderOption{sdktrace.WithResource(newResource(v))}
	if cfg.OTLP.Endpoint == "" {
		// IDs for the logs, and nothing recorded.
		opts = append(opts, sdktrace.WithSampler(sdktrace.NeverSample()))
	} else {
		client, err := newHTTPClient(cfg.OTLP, v)
		if err != nil {
			return nil, err
		}
		exporter, err := otlptrace.New(context.Background(), client)
		if err != nil {
			return nil, err
		}
		opts = append(opts,
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
			sdktrace.WithBatcher(exporter))
	}
	return &Provider{tp: sdktrace.NewTracerProvider(opts...)}, nil
}

// TracerProvider returns the OpenTelemetry tracer provider, for
// instrumentation.
func (p *Provider) TracerProvider() trace.TracerProvider { return p.tp }

// Shutdown sends the spans still buffered, within ctx, and stops the
// provider.
func (p *Provider) Shutdown(ctx context.Context) error { return p.tp.Shutdown(ctx) }

func newResource(v version.Info) *resource.Resource {
	attrs := []attribute.KeyValue{semconv.ServiceName("whitetower"), semconv.ServiceVersion(v.Version)}
	if host, err := os.Hostname(); err == nil {
		attrs = append(attrs, semconv.HostName(host))
	}
	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}

// Propagator reads and writes the W3C Trace Context headers, traceparent and
// tracestate. W3C Baggage is left out: the server has no use for it, and it
// would carry whatever callers put in it.
func Propagator() propagation.TextMapPropagator { return propagation.TraceContext{} }

// ErrorHandler returns an OpenTelemetry error handler, to install with
// otel.SetErrorHandler, that logs through logger at most once a minute, so
// that a receiver that is down does not flood the logs.
func ErrorHandler(logger *slog.Logger) otel.ErrorHandler {
	return &errorHandler{logger: logger, every: time.Minute}
}

type errorHandler struct {
	logger *slog.Logger
	every  time.Duration

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (h *errorHandler) Handle(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !h.last.IsZero() && now.Sub(h.last) < h.every {
		h.suppressed++
		return
	}
	h.logger.Warn("tracing failed", "error", err.Error(), "suppressed", h.suppressed)
	h.last, h.suppressed = now, 0
}
