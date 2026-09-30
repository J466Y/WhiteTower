// Package server runs the three listeners of the core (architecture document,
// section 4.1): the console and public API, the machine listener for
// enforcement points and modules, and the operations listener for metrics
// and health checks.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/servertls"
)

// Handlers are what the three listeners serve.
type Handlers struct {
	Console    http.Handler
	Machine    http.Handler
	Operations http.Handler
}

// Listeners are open listeners, for Serve.
type Listeners struct {
	Console, Machine, Operations net.Listener
}

// Drain tells long-lived handlers, such as the module API's watch streams,
// that the server is stopping: they end, and their clients reconnect to
// another replica before their leases run out.
type Drain struct {
	once sync.Once
	ch   chan struct{}
}

// NewDrain returns a drain signal that has not fired.
func NewDrain() *Drain { return &Drain{ch: make(chan struct{})} }

// Draining is closed when the server starts to stop.
func (d *Drain) Draining() <-chan struct{} { return d.ch }

func (d *Drain) start() { d.once.Do(func() { close(d.ch) }) }

// Server runs the listeners.
type Server struct {
	cfg        config.Config
	handlers   Handlers
	drain      *Drain
	logger     *slog.Logger
	consoleTLS *tls.Config
	machineTLS *tls.Config
}

// New prepares the server: it loads the certificates, or generates a
// development certificate when the configuration asks for one.
func New(cfg config.Config, handlers Handlers, drain *Drain, logger *slog.Logger) (*Server, error) {
	minVersion, err := cfg.TLS.Version()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, handlers: handlers, drain: drain, logger: logger}

	var devCert *tls.Certificate
	certificates := func(l config.TLSListener) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
		if cfg.Dev.SelfSignedTLS {
			if devCert == nil {
				hostname, _ := os.Hostname()
				cert, err := servertls.SelfSigned(hostname)
				if err != nil {
					return nil, fmt.Errorf("generating the development certificate: %w", err)
				}
				devCert = &cert
			}
			return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return devCert, nil }, nil
		}
		r, err := servertls.NewReloader(l.CertFile, l.KeyFile, logger)
		if err != nil {
			return nil, err
		}
		return r.GetCertificate, nil
	}
	for _, l := range []struct {
		listener config.TLSListener
		dst      **tls.Config
	}{{cfg.Listeners.Console, &s.consoleTLS}, {cfg.Listeners.Machine, &s.machineTLS}} {
		get, err := certificates(l.listener)
		if err != nil {
			return nil, err
		}
		if *l.dst, err = servertls.Config(minVersion, get); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Run listens on the configured addresses and serves until ctx ends, then
// shuts down.
func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	var opened []net.Listener
	listen := func(name, addr string) (net.Listener, error) {
		l, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			for _, o := range opened {
				_ = o.Close()
			}
			return nil, fmt.Errorf("%s listener on %s: %w", name, addr, err)
		}
		opened = append(opened, l)
		return l, nil
	}
	console, err := listen("console", s.cfg.Listeners.Console.Address)
	if err != nil {
		return err
	}
	machine, err := listen("machine", s.cfg.Listeners.Machine.Address)
	if err != nil {
		return err
	}
	operations, err := listen("operations", s.cfg.Listeners.Operations.Address)
	if err != nil {
		return err
	}
	return s.Serve(ctx, Listeners{Console: console, Machine: machine, Operations: operations})
}

// served is one listener and its HTTP server.
type served struct {
	name     string
	srv      *http.Server
	listener net.Listener
	tls      bool
}

// Serve serves on open listeners until ctx ends, then shuts down within the
// configured timeout. It returns early if a listener fails.
func (s *Server) Serve(ctx context.Context, l Listeners) error {
	console := s.httpServer(s.handlers.Console, s.consoleTLS)
	machine := s.httpServer(s.handlers.Machine, s.machineTLS)
	operations := s.httpServer(s.handlers.Operations, nil)
	all := []served{
		{"console", console, l.Console, true},
		{"machine", machine, l.Machine, true},
		{"operations", operations, l.Operations, false},
	}

	results := make(chan error, len(all))
	for _, sv := range all {
		go func() {
			var err error
			if sv.tls {
				err = sv.srv.ServeTLS(sv.listener, "", "")
			} else {
				err = sv.srv.Serve(sv.listener)
			}
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			} else if err != nil {
				err = fmt.Errorf("%s listener: %w", sv.name, err)
			}
			results <- err
		}()
		s.logger.Info("listening", "listener", sv.name, "addr", sv.listener.Addr().String(), "tls", sv.tls)
	}

	var failed error
	received := 0
	select {
	case <-ctx.Done():
	case failed = <-results:
		received++
		s.logger.Error("a listener stopped; shutting down", "error", failed)
	}
	s.shutdown(all)
	for ; received < len(all); received++ {
		if err := <-results; err != nil && failed == nil {
			failed = err
		}
	}
	return failed
}

// shutdown stops the listeners within the configured timeout. Long-lived
// handlers learn it through the drain signal; whatever is still open at the
// deadline is closed. The operations listener stops last, so health checks
// answer until the end.
func (s *Server) shutdown(all []served) {
	timeout := s.cfg.Shutdown.Timeout
	s.logger.Info("shutting down", "timeout", timeout.String())
	start := time.Now()
	s.drain.start()
	deadline, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stop := func(sv served) {
		if err := sv.srv.Shutdown(deadline); err != nil {
			s.logger.Warn("shutdown deadline reached; closing the remaining connections", "listener", sv.name)
			_ = sv.srv.Close()
		}
	}
	var wg sync.WaitGroup
	for _, sv := range all[:2] {
		wg.Go(func() { stop(sv) })
	}
	wg.Wait()
	stop(all[2])
	s.logger.Info("stopped", "took", time.Since(start).Round(time.Millisecond).String())
}

func (s *Server) httpServer(h http.Handler, tlsConfig *tls.Config) *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	if tlsConfig != nil {
		protocols.SetHTTP2(true)
	}
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsConfig,
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.logger.Handler(), slog.LevelWarn),
	}
}
