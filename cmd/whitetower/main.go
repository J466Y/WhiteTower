// Command whitetower runs the White Tower governance core.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/J466Y/WhiteTower/internal/server"
	"github.com/J466Y/WhiteTower/internal/version"
	"github.com/J466Y/WhiteTower/internal/webui"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("whitetower", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("addr", envOr("WT_ADDR", "127.0.0.1:8080"), "address to listen on (env WT_ADDR)")
	showVersion := flags.Bool("version", false, "print the version and exit")
	healthcheck := flags.Bool("healthcheck", false,
		"check that the server listening on -addr is healthy, then exit (for container health checks)")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	v := version.Get()
	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "whitetower %s (commit %s)\n", v.Version, v.Commit)
		return 0
	}
	if *healthcheck {
		if err := checkHealth(*addr); err != nil {
			_, _ = fmt.Fprintln(stderr, "unhealthy:", err)
			return 1
		}
		return 0
	}

	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting whitetower", "version", v.Version, "commit", v.Commit, "console_embedded", webui.Embedded)
	cfg := server.Config{Addr: *addr, ShutdownTimeout: 10 * time.Second}
	if err := server.Run(ctx, cfg, logger); err != nil {
		logger.Error("server stopped with an error", "error", err)
		return 1
	}
	return 0
}

// checkHealth calls the health endpoint of a local server. Distroless images
// have no shell or curl, so container health checks run the binary itself.
func checkHealth(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort(host, port) + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return nil
}

func envOr(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return value
	}
	return fallback
}
