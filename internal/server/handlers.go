package server

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/J466Y/WhiteTower/internal/api/moduleapi"
	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/platform/health"
	"github.com/J466Y/WhiteTower/internal/webui"
)

// HSTS is the Strict-Transport-Security header of the console listener,
// which only serves HTTPS: two years, without subdomains, which the core
// does not own.
const HSTS = "max-age=63072000"

// Body size limits of the listeners: a request over them is refused before
// any handler runs (security test ST-05). The module API has no
// client-streaming procedure, so a request body holds one message: the
// machine listener allows a message of the module contracts' size (section
// 4.8) and room for its framing.
const (
	MaxConsoleBody    = 1 << 20
	MaxMachineBody    = moduleapi.MaxMessageBytes + 64<<10
	MaxOperationsBody = 4 << 10
)

// ConsoleHandler serves the console listener: the public REST API, built
// with rest.Handler, and the web console.
func ConsoleHandler(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(rest.BasePath+"/", api)
	mux.Handle("/", webui.Handler())
	limited := LimitBody(MaxConsoleBody,
		problem.Handler(problem.PayloadTooLarge, "the request body is larger than 1 MiB"), mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", HSTS)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		limited.ServeHTTP(w, r)
	})
}

// LimitBody refuses a request whose body is larger than limit bytes: with
// refuse, before next runs, when the request announces its size, and as next
// reads past the limit otherwise.
func LimitBody(limit int64, refuse, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > limit {
			refuse.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// MachineHandler serves the machine listener: the module API, built with
// moduleapi.Handler. A body over the limit is refused as RESOURCE_EXHAUSTED
// in the caller's protocol, as the module API refuses a message over its
// limit, so that clients handle both alike.
func MachineHandler(api http.Handler) http.Handler {
	rpc := connect.NewErrorWriter()
	tooLarge := connect.NewError(connect.CodeResourceExhausted,
		errors.New("the request is larger than a message may be (module contracts, section 4.8)"))
	limited := LimitBody(MaxMachineBody, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rpc.IsSupported(r) {
			plain(w, http.StatusRequestEntityTooLarge, "request body too large\n")
			return
		}
		_ = rpc.Write(w, r, tooLarge)
	}), api)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		limited.ServeHTTP(w, r)
	})
}

// OperationsHandler serves the operations listener. /healthz answers while
// the process runs. /readyz answers "ok" while every readiness check passes
// and the server is not draining, so that load balancers send traffic
// elsewhere otherwise. /metrics serves the Prometheus metrics.
func OperationsHandler(drain *Drain, ready *health.Readiness, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		plain(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-drain.Draining():
			plain(w, http.StatusServiceUnavailable, "draining\n")
			return
		default:
		}
		if failing := ready.Failing(r.Context()); len(failing) > 0 {
			plain(w, http.StatusServiceUnavailable, "not ready: "+strings.Join(failing, ", ")+"\n")
			return
		}
		plain(w, http.StatusOK, "ok\n")
	})
	mux.Handle("GET /metrics", metrics)
	return LimitBody(MaxOperationsBody, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plain(w, http.StatusRequestEntityTooLarge, "request body too large\n")
	}), mux)
}

func plain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
