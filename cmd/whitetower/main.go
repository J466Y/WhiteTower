// Command whitetower runs the White Tower governance core.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"

	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/health"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/internal/platform/tracing"
	"github.com/J466Y/WhiteTower/internal/server"
	"github.com/J466Y/WhiteTower/internal/version"
	"github.com/J466Y/WhiteTower/internal/webui"
)

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

// usageError marks mistakes on the command line, which exit with status 2.
type usageError struct{ error }

func run(args, environ []string, stdout, stderr io.Writer) int {
	root := newRootCommand(environ, stdout)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.Execute()
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(stderr, "whitetower:", err)
	if errors.As(err, &usageError{}) {
		return 2
	}
	return 1
}

func newRootCommand(environ []string, stdout io.Writer) *cobra.Command {
	v := version.Get()
	root := &cobra.Command{
		Use:           "whitetower",
		Short:         "The White Tower governance core",
		Version:       fmt.Sprintf("%s (commit %s)", v.Version, v.Commit),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("whitetower {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })

	var configPath string
	root.PersistentFlags().StringVar(&configPath, "config", lookup(environ, "WT_CONFIG"),
		"YAML configuration file; environment variables prefixed WT_ override it (env WT_CONFIG)")
	load := func() (config.Config, error) { return config.Load(configPath, environ) }

	root.AddCommand(
		newServeCommand(load, stdout),
		newMigrateCommand(load, stdout),
		newConfigCommand(load),
		newHealthcheckCommand(load),
		&cobra.Command{
			Use:   "version",
			Short: "Print the version",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "whitetower %s (commit %s)\n", v.Version, v.Commit)
				return err
			},
		},
	)
	return root
}

func newServeCommand(load func() (config.Config, error), stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the server until it receives SIGTERM or an interrupt",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			if err := cfg.CheckServe(); err != nil {
				return fmt.Errorf("invalid configuration:\n%w", err)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return serve(ctx, cfg, stdout)
		},
	}
}

func newMigrateCommand(load func() (config.Config, error), stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply the pending database migrations as the migration role, then exit",
		Long: "Apply the pending database migrations as the migration role (database.migration.*), then exit. " +
			"It runs before the server: as an init container on Kubernetes, as a one-off service in Compose. " +
			"Concurrent runs take turns on an advisory lock. The server never reads the migration role's settings.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			if err := cfg.CheckMigrate(); err != nil {
				return fmt.Errorf("invalid configuration:\n%w", err)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return db.Migrate(ctx, cfg.Database.Migration, logging.New(stdout, cfg.Log.Level))
		},
	}
}

// serve runs the server until ctx ends. Every dependency is made here and
// handed to what uses it.
func serve(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	logger := logging.New(stdout, cfg.Log.Level)
	v := version.Get()
	logger.Info("starting whitetower", "version", v.Version, "commit", v.Commit, "console_embedded", webui.Embedded)
	if cfg.Dev.SelfSignedTLS {
		logger.Warn("DEVELOPMENT MODE: the HTTPS listeners serve a self-signed certificate made at startup. Never use this setting in production.")
	}

	// OpenTelemetry reports its own errors through a global handler.
	otel.SetErrorHandler(tracing.ErrorHandler(logger))
	traces, err := tracing.New(cfg.Tracing, v)
	if err != nil {
		return err
	}
	if cfg.Tracing.OTLP.Endpoint != "" {
		logger.Info("exporting traces", "endpoint", cfg.Tracing.OTLP.Endpoint, "sample_ratio", cfg.Tracing.SampleRatio)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), traceFlushTimeout)
		defer cancel()
		if err := traces.Shutdown(ctx); err != nil {
			logger.Warn("sending the last spans", "error", err.Error())
		}
	}()

	// The runtime role only: the migration role's settings stay unread
	// (threat model, DC-3).
	database, err := db.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := checkSchemaAtStart(ctx, database, logger); err != nil {
		return err
	}

	registry := metrics.NewRegistry(v)
	httpMetrics := metrics.NewHTTP(registry)
	observer := server.NewObserver(logger, httpMetrics, traces.TracerProvider())
	api := rest.Handler(rest.Options{
		Logger: logger,
		// Until plan P1-03 brings sessions, API tokens and the permission
		// matrix, nobody is authenticated: only public operations answer.
		Authenticator: auth.Unauthenticated{},
		Authorizer:    auth.DenyAll{},
		Limiter:       ratelimit.New(cfg.API.RateLimit, cfg.API.RateBurst),
		RateLimited:   httpMetrics.RateLimited("console").Inc,
	})
	drain := server.NewDrain()
	ready := health.NewReadiness(logger)
	ready.Add("database", database.Ping)
	ready.Add("schema", database.CheckSchema)
	srv, err := server.New(cfg, server.Handlers{
		Console:    observer.Wrap("console", server.ConsoleHandler(api)),
		Machine:    observer.Wrap("machine", server.MachineHandler()),
		Operations: server.OperationsHandler(drain, ready, metrics.Handler(registry)),
	}, drain, logger)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

// traceFlushTimeout bounds how long the last spans may take to leave after
// the listeners have stopped.
const traceFlushTimeout = 5 * time.Second

// checkSchemaAtStart refuses a database whose schema is newer than the
// binary. A database that does not answer yet, or is not migrated yet, only
// delays readiness: the server starts and waits for it.
func checkSchemaAtStart(ctx context.Context, database *db.DB, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch err := database.CheckSchema(ctx); {
	case errors.Is(err, db.ErrSchemaAhead):
		return err
	case err != nil:
		logger.Warn("the database is not ready; the server waits for it, and for whitetower migrate", "error", err.Error())
	default:
		logger.Info("the database schema is current", "version", db.ExpectedVersion())
	}
	return nil
}

func newConfigCommand(load func() (config.Config, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect the configuration",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Print the effective configuration: the file, the environment and the defaults combined",
		Long: "Print the effective configuration as YAML. It holds no secret: settings ending " +
			"in _file name the files that hold them.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			out, err := cfg.YAML()
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	})
	return cmd
}

// newHealthcheckCommand checks the operations listener of a local server.
// Distroless images have no shell or curl, so container health checks run
// the binary itself, with the server's configuration.
func newHealthcheckCommand(load func() (config.Config, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Check that the local server is healthy, for container health checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			host, port, err := net.SplitHostPort(cfg.Listeners.Operations.Address)
			if err != nil {
				return err
			}
			if host == "" || host == "0.0.0.0" || host == "::" {
				host = "127.0.0.1"
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
			defer cancel()
			url := "http://" + net.JoinHostPort(host, port) + "/healthz"
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("unhealthy: %w", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unhealthy: %s returned %s", url, resp.Status)
			}
			return nil
		},
	}
}

// lookup returns the value of a variable in environ.
func lookup(environ []string, name string) string {
	for _, kv := range environ {
		if n, v, ok := strings.Cut(kv, "="); ok && n == name {
			return v
		}
	}
	return ""
}
