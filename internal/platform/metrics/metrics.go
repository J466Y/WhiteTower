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

// RPC holds the metrics of the module API's calls. Procedures are those the
// server serves: a call to any other never reaches them.
type RPC struct {
	handled  *prometheus.CounterVec
	duration *prometheus.HistogramVec
	streams  *prometheus.GaugeVec
}

// NewRPC registers the module API's metrics with reg.
func NewRPC(reg prometheus.Registerer) *RPC {
	m := &RPC{
		handled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "rpc",
			Name:      "server_handled_total",
			Help:      "Module API calls that ended, by procedure and code.",
		}, []string{"procedure", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "rpc",
			Name:      "server_duration_seconds",
			Help:      "Time spent on unary module API calls, by procedure.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"procedure"}),
		streams: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "rpc",
			Name:      "server_open_streams",
			Help:      "Module API streams open, such as the Watch streams of connected instances, by procedure.",
		}, []string{"procedure"}),
	}
	reg.MustRegister(m.handled, m.duration, m.streams)
	return m
}

// Refused counts a call refused before its handler ran, such as one without
// a valid token.
func (m *RPC) Refused(procedure, code string) {
	m.handled.WithLabelValues(procedure, code).Inc()
}

// Started counts a call whose handler runs; the returned function records
// its end, with its code.
func (m *RPC) Started(procedure string, stream bool) func(code string) {
	start := time.Now()
	if stream {
		m.streams.WithLabelValues(procedure).Inc()
	}
	return func(code string) {
		m.handled.WithLabelValues(procedure, code).Inc()
		if stream {
			m.streams.WithLabelValues(procedure).Dec()
		} else {
			m.duration.WithLabelValues(procedure).Observe(time.Since(start).Seconds())
		}
	}
}

// Jobs holds the metrics of the background jobs. A replica reports the runs
// of the jobs it leads.
type Jobs struct {
	leader      *prometheus.GaugeVec
	lastRun     *prometheus.GaugeVec
	lastSuccess *prometheus.GaugeVec
	duration    *prometheus.HistogramVec
	failures    *prometheus.CounterVec
}

// NewJobs registers the metrics of the background jobs with reg.
func NewJobs(reg prometheus.Registerer) *Jobs {
	m := &Jobs{
		leader: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "job",
			Name:      "leader",
			Help:      "1 on the replica that leads the job, 0 on the others.",
		}, []string{"job"}),
		lastRun: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "job",
			Name:      "last_run_timestamp_seconds",
			Help:      "When the job's last run on this replica ended, in seconds since the Unix epoch.",
		}, []string{"job"}),
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "job",
			Name:      "last_success_timestamp_seconds",
			Help:      "When the job's last successful run on this replica ended, in seconds since the Unix epoch.",
		}, []string{"job"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "job",
			Name:      "duration_seconds",
			Help:      "Time spent on the job's runs.",
			Buckets:   prometheus.ExponentialBuckets(0.005, 4, 10),
		}, []string{"job"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "job",
			Name:      "failures_total",
			Help:      "Runs of the job that failed.",
		}, []string{"job"}),
	}
	reg.MustRegister(m.leader, m.lastRun, m.lastSuccess, m.duration, m.failures)
	return m
}

// Leading records whether this replica leads the job.
func (m *Jobs) Leading(job string, leading bool) {
	v := 0.0
	if leading {
		v = 1
	}
	m.leader.WithLabelValues(job).Set(v)
}

// Ran records a run of the job that ended at end, after took.
func (m *Jobs) Ran(job string, took time.Duration, end time.Time, succeeded bool) {
	m.duration.WithLabelValues(job).Observe(took.Seconds())
	m.lastRun.WithLabelValues(job).Set(float64(end.UnixMilli()) / 1000)
	if succeeded {
		m.lastSuccess.WithLabelValues(job).Set(float64(end.UnixMilli()) / 1000)
	} else {
		m.failures.WithLabelValues(job).Inc()
	}
}

// Notify holds the metrics of the notifications across replicas.
type Notify struct {
	connected prometheus.Gauge
	received  *prometheus.CounterVec
	resyncs   *prometheus.CounterVec
}

// NewNotify registers the metrics of the notifications with reg.
func NewNotify(reg prometheus.Registerer) *Notify {
	m := &Notify{
		connected: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "notify",
			Name:      "listener_connected",
			Help:      "1 while the replica listens for notifications from the others, 0 while it reconnects.",
		}),
		received: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "notify",
			Name:      "received_total",
			Help:      "Notifications received, by channel.",
		}, []string{"channel"}),
		resyncs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "notify",
			Name:      "resyncs_total",
			Help: "Times a subscriber was told to re-read what it follows, by reason: listening (the replica " +
				"started listening for it, when it subscribed or after a reconnection) or overflow (it fell behind).",
		}, []string{"reason"}),
	}
	reg.MustRegister(m.connected, m.received, m.resyncs)
	return m
}

// Connected records whether the listener is connected.
func (m *Notify) Connected(connected bool) {
	v := 0.0
	if connected {
		v = 1
	}
	m.connected.Set(v)
}

// Received counts a notification received on channel.
func (m *Notify) Received(channel string) { m.received.WithLabelValues(channel).Inc() }

// Resynced counts a subscriber told to re-read what it follows.
func (m *Notify) Resynced(reason string) { m.resyncs.WithLabelValues(reason).Inc() }

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
