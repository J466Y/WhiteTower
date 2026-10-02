// Package metrics holds the server's Prometheus metrics, served at /metrics
// on the operations listener. White Tower's own metrics are prefixed
// whitetower_; the Go runtime and process metrics keep the go_ and process_
// names that dashboards expect.
package metrics

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/J466Y/WhiteTower/internal/version"
)

// Namespace prefixes White Tower's metrics.
const Namespace = "whitetower"

// NewRegistry returns a registry with the Go runtime and process metrics and
// whitetower_build_info. It is not Prometheus's global registry, so no
// library adds metrics to it unseen.
func NewRegistry(v version.Info) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Name:        "build_info",
			Help:        "Always 1; the labels describe the running build.",
			ConstLabels: prometheus.Labels{"version": v.Version, "commit": v.Commit, "go_version": runtime.Version()},
		}, func() float64 { return 1 }),
	)
	return reg
}

// Handler serves the metrics of reg.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// HTTP holds the request metrics of the HTTP listeners.
type HTTP struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec
	limited  *prometheus.CounterVec
}

// NewHTTP registers the request metrics with reg.
func NewHTTP(reg prometheus.Registerer) *HTTP {
	m := &HTTP{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Requests handled, by listener, method, route and status code.",
		}, []string{"listener", "method", "route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Time spent on requests, by listener, method and route; long-lived streams count when they end.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"listener", "method", "route"}),
		inFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "http",
			Name:      "requests_in_flight",
			Help:      "Requests being handled, open streams included, by listener.",
		}, []string{"listener"}),
		limited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "http",
			Name:      "requests_rate_limited_total",
			Help:      "Requests refused because their client exceeded its rate, by listener.",
		}, []string{"listener"}),
	}
	reg.MustRegister(m.requests, m.duration, m.inFlight, m.limited)
	return m
}

// RateLimited returns the counter of the requests refused on a listener
// because their client exceeded its rate.
func (m *HTTP) RateLimited(listener string) prometheus.Counter {
	return m.limited.WithLabelValues(listener)
}

// InFlight returns the gauge of the requests in flight on a listener.
func (m *HTTP) InFlight(listener string) prometheus.Gauge {
	return m.inFlight.WithLabelValues(listener)
}

// Observe records a request that has ended. The route is the pattern that
// matched it, never its path, so that clients cannot add series at will.
func (m *HTTP) Observe(listener, method, route string, code int, took time.Duration) {
	method = Method(method)
	m.requests.WithLabelValues(listener, method, route, strconv.Itoa(code)).Inc()
	m.duration.WithLabelValues(listener, method, route).Observe(took.Seconds())
}

// Method returns a standard HTTP method as it is, and anything else as
// _OTHER, as the OpenTelemetry conventions do: clients choose the method.
func Method(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "_OTHER"
	}
}
