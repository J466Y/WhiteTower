// Package server assembles the HTTP server of the core.
//
// This is the skeleton of plan P0-01: one plain HTTP listener serving the
// health check, both APIs and the console. Plan P1-01 replaces it with the
// three TLS listeners of the architecture document.
package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/J466Y/WhiteTower/internal/api/moduleapi"
	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/webui"
)

// Config configures the server.
type Config struct {
	// Addr is the TCP address to listen on, for example "127.0.0.1:8080".
	Addr string
	// ShutdownTimeout bounds the graceful shutdown.
	ShutdownTimeout time.Duration
}

// NewHandler returns the root HTTP handler of the core.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle(rest.BasePath+"/", rest.Handler())
	mux.Handle(moduleapi.Handler())
	mux.Handle("/", webui.Handler())
	return withSecurityHeaders(mux)
}

// withSecurityHeaders sets the headers every response must carry.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// Run serves until ctx is canceled, then shuts down gracefully.
func Run(ctx context.Context, cfg Config, logger *slog.Logger) error {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return err
	}
	return Serve(ctx, listener, cfg, logger)
}

// Serve is Run on an existing listener; tests use it with a random port.
func Serve(ctx context.Context, listener net.Listener, cfg Config, logger *slog.Logger) error {
	// HTTP/2 without TLS lets gRPC clients reach the module API during
	// development. TLS arrives with plan P1-01.
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	srv := &http.Server{
		Handler:           NewHandler(),
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(listener) }()
	logger.Info("listening", "addr", listener.Addr().String())

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
