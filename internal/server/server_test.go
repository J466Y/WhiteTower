package server_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/health"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/server"
	"github.com/J466Y/WhiteTower/internal/version"
	"github.com/J466Y/WhiteTower/internal/webui"
	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

func TestConsoleHandler(t *testing.T) {
	srv := httptest.NewServer(server.ConsoleHandler())
	t.Cleanup(srv.Close)

	t.Run("public API version", func(t *testing.T) {
		got := get(t, http.DefaultClient, srv.URL+"/api/v1/version")
		if got.status != http.StatusOK {
			t.Fatalf("status %d, want 200", got.status)
		}
		var info struct {
			Version    string `json:"version"`
			Commit     string `json:"commit"`
			APIVersion string `json:"apiVersion"`
		}
		if err := json.Unmarshal([]byte(got.body), &info); err != nil {
			t.Fatalf("decoding %q: %v", got.body, err)
		}
		if info.Version != "dev" || info.APIVersion != "v1" || info.Commit == "" {
			t.Fatalf("got %+v, want version dev, apiVersion v1 and a commit", info)
		}
	})

	t.Run("console with strict CSP and HSTS", func(t *testing.T) {
		got := get(t, http.DefaultClient, srv.URL+"/")
		if got.status != http.StatusOK || !strings.Contains(got.body, "White Tower") {
			t.Fatalf("got %d, want 200 with the console page", got.status)
		}
		if csp := got.header.Get("Content-Security-Policy"); csp != webui.ContentSecurityPolicy {
			t.Fatalf("Content-Security-Policy %q", csp)
		}
		for name, want := range map[string]string{
			"Strict-Transport-Security": server.HSTS,
			"X-Content-Type-Options":    "nosniff",
			"Referrer-Policy":           "no-referrer",
		} {
			if got := got.header.Get(name); got != want {
				t.Errorf("%s: %q, want %q", name, got, want)
			}
		}
	})

	t.Run("client-side route falls back to the console", func(t *testing.T) {
		got := get(t, http.DefaultClient, srv.URL+"/agents/42")
		if got.status != http.StatusOK || !strings.Contains(got.body, "White Tower") {
			t.Fatalf("got %d, want 200 with the console page", got.status)
		}
	})

	t.Run("missing asset is not found", func(t *testing.T) {
		if got := get(t, http.DefaultClient, srv.URL+"/assets/missing.js"); got.status != http.StatusNotFound {
			t.Fatalf("status %d, want 404", got.status)
		}
	})

	t.Run("health checks are not on the console listener", func(t *testing.T) {
		got := get(t, http.DefaultClient, srv.URL+"/healthz")
		if strings.TrimSpace(got.body) == "ok" {
			t.Fatal("/healthz answered on the console listener; it belongs to the operations listener")
		}
	})

	t.Run("console rejects other methods", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/", "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", resp.StatusCode)
		}
	})
}

func TestOperationsHandler(t *testing.T) {
	drain := server.NewDrain()
	ready := health.NewReadiness(slog.New(slog.DiscardHandler))
	registry := metrics.NewRegistry(version.Get())
	srv := httptest.NewServer(server.OperationsHandler(drain, ready, metrics.Handler(registry)))
	t.Cleanup(srv.Close)

	if got := get(t, http.DefaultClient, srv.URL+"/healthz"); got.status != http.StatusOK || got.body != "ok\n" {
		t.Fatalf("healthz: got %d %q", got.status, got.body)
	}
	if got := get(t, http.DefaultClient, srv.URL+"/readyz"); got.status != http.StatusOK || got.body != "ok\n" {
		t.Fatalf("readyz with every check passing: got %d %q", got.status, got.body)
	}
	if got := get(t, http.DefaultClient, srv.URL+"/metrics"); got.status != http.StatusOK || !strings.Contains(got.body, "whitetower_build_info{") {
		t.Fatalf("metrics: got %d %q", got.status, got.body)
	}

	ready.Add("database", func(context.Context) error { return errors.New("connection refused to 10.0.0.5") })
	got := get(t, http.DefaultClient, srv.URL+"/readyz")
	if got.status != http.StatusServiceUnavailable || got.body != "not ready: database\n" {
		t.Fatalf("readyz with a failing check: got %d %q, want 503 naming the check only", got.status, got.body)
	}
}

// running is a server started on random local ports.
type running struct {
	console, machine, operations string
	cancel                       context.CancelFunc
	done                         chan error
}

// start runs a server with a development certificate and the given handlers.
func start(t *testing.T, cfg config.Config, h server.Handlers, drain *server.Drain) *running {
	t.Helper()
	cfg.Dev.SelfSignedTLS = true
	srv, err := server.New(cfg, h, drain, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	listen := func() net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	l := server.Listeners{Console: listen(), Machine: listen(), Operations: listen()}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{
		console:    "https://" + l.Console.Addr().String(),
		machine:    "https://" + l.Machine.Addr().String(),
		operations: "http://" + l.Operations.Addr().String(),
		cancel:     cancel,
		done:       make(chan error, 1),
	}
	go func() { r.done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

// stop cancels the server and returns how long Serve took to return.
func (r *running) stop(t *testing.T) (time.Duration, error) {
	t.Helper()
	begin := time.Now()
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err // for the cleanup
		return time.Since(begin), err
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return")
		return 0, nil
	}
}

// insecureClient trusts the development certificate. HTTP/2 when h2 is set.
func insecureClient(h2 bool) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	var p http.Protocols
	if h2 {
		p.SetHTTP2(true)
	} else {
		p.SetHTTP1(true)
	}
	tr.Protocols = &p
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// defaultHandlers are the handlers of the server binary, instrumented as it
// instruments them.
func defaultHandlers(drain *server.Drain) server.Handlers {
	discard := slog.New(slog.DiscardHandler)
	registry := metrics.NewRegistry(version.Get())
	observer := server.NewObserver(discard, metrics.NewHTTP(registry), noop.NewTracerProvider())
	return server.Handlers{
		Console:    observer.Wrap("console", server.ConsoleHandler()),
		Machine:    observer.Wrap("machine", server.MachineHandler()),
		Operations: server.OperationsHandler(drain, health.NewReadiness(discard), metrics.Handler(registry)),
	}
}

func TestListeners(t *testing.T) {
	drain := server.NewDrain()
	r := start(t, config.Defaults(), defaultHandlers(drain), drain)

	t.Run("console over HTTP/2", func(t *testing.T) {
		got := get(t, insecureClient(true), r.console+"/api/v1/version")
		if got.status != http.StatusOK || got.proto != "HTTP/2.0" {
			t.Fatalf("got %d over %s, want 200 over HTTP/2", got.status, got.proto)
		}
	})

	t.Run("console over HTTP/1.1", func(t *testing.T) {
		if got := get(t, insecureClient(false), r.console+"/api/v1/version"); got.status != http.StatusOK {
			t.Fatalf("status %d", got.status)
		}
	})

	for _, protocol := range []struct {
		name string
		opt  connect.ClientOption
	}{{"gRPC", connect.WithGRPC()}, {"Connect with JSON", connect.WithProtoJSON()}} {
		t.Run("module API over "+protocol.name, func(t *testing.T) {
			client := modulev1alpha1connect.NewMetaServiceClient(insecureClient(true), r.machine, protocol.opt)
			resp, err := client.GetServerInfo(context.Background(), connect.NewRequest(&modulev1alpha1.GetServerInfoRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(resp.Msg.GetContractVersions(), "v1alpha1") {
				t.Fatalf("contract versions %v", resp.Msg.GetContractVersions())
			}
		})
	}

	t.Run("operations over plain HTTP", func(t *testing.T) {
		if got := get(t, http.DefaultClient, r.operations+"/healthz"); got.status != http.StatusOK {
			t.Fatalf("status %d", got.status)
		}
	})

	t.Run("no plain HTTP on the console listener", func(t *testing.T) {
		resp, err := http.Get("http" + strings.TrimPrefix(r.console, "https") + "/")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Fatalf("plain HTTP got %d", resp.StatusCode)
			}
		}
	})
}

func TestTLSVersions(t *testing.T) {
	for _, tt := range []struct {
		name       string
		minVersion string
		client     uint16
		ok         bool
	}{
		{"TLS 1.1 refused", "1.2", tls.VersionTLS11, false},
		{"TLS 1.2 accepted", "1.2", tls.VersionTLS12, true},
		{"TLS 1.3 accepted", "1.2", tls.VersionTLS13, true},
		{"TLS 1.2 refused when 1.3 is required", "1.3", tls.VersionTLS12, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.TLS.MinVersion = tt.minVersion
			drain := server.NewDrain()
			r := start(t, cfg, defaultHandlers(drain), drain)
			for _, addr := range []string{r.console, r.machine} {
				conn, err := tls.Dial("tcp", strings.TrimPrefix(addr, "https://"), &tls.Config{
					InsecureSkipVerify: true, MinVersion: tt.client, MaxVersion: tt.client,
				})
				if err == nil {
					_ = conn.Close()
				}
				if (err == nil) != tt.ok {
					t.Fatalf("%s: handshake error %v, want success %v", addr, err, tt.ok)
				}
			}
		})
	}
}

// streaming writes "hello", then waits: until the drain when it cooperates,
// or until the client goes away otherwise.
func streaming(drain *server.Drain, cooperative bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello\n")
		http.NewResponseController(w).Flush() //nolint:errcheck // the test notices a missing line
		if !cooperative {
			<-r.Context().Done()
			return
		}
		select {
		case <-drain.Draining():
			_, _ = io.WriteString(w, "reconnect elsewhere\n")
		case <-r.Context().Done():
		}
	})
}

func openStream(t *testing.T, url string) *bufio.Reader {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := insecureClient(true)
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	body := bufio.NewReader(resp.Body)
	if line, err := body.ReadString('\n'); err != nil || line != "hello\n" {
		t.Fatalf("first line %q, %v", line, err)
	}
	return body
}

func TestShutdownDrainsOpenStreams(t *testing.T) {
	cfg := config.Defaults()
	cfg.Shutdown.Timeout = 5 * time.Second
	drain := server.NewDrain()
	h := defaultHandlers(drain)
	h.Machine = discardObserver().Wrap("machine", streaming(drain, true))
	r := start(t, cfg, h, drain)

	body := openStream(t, r.machine+"/watch")
	took, err := r.stop(t)
	if err != nil {
		t.Fatalf("Serve returned %v", err)
	}
	if line, _ := body.ReadString('\n'); line != "reconnect elsewhere\n" {
		t.Fatalf("stream ended with %q, want the drain message", line)
	}
	if _, err := body.ReadString('\n'); !errors.Is(err, io.EOF) {
		t.Fatalf("stream after the drain: %v, want EOF", err)
	}
	if took > cfg.Shutdown.Timeout/2 {
		t.Fatalf("a drained stream took %s to shut down", took)
	}
}

func TestShutdownClosesStreamsAtTheDeadline(t *testing.T) {
	cfg := config.Defaults()
	cfg.Shutdown.Timeout = time.Second
	drain := server.NewDrain()
	h := defaultHandlers(drain)
	h.Machine = discardObserver().Wrap("machine", streaming(drain, false))
	r := start(t, cfg, h, drain)

	body := openStream(t, r.machine+"/watch")
	took, err := r.stop(t)
	if err != nil {
		t.Fatalf("Serve returned %v", err)
	}
	if took < cfg.Shutdown.Timeout || took > cfg.Shutdown.Timeout+2*time.Second {
		t.Fatalf("shutdown took %s, want about the %s deadline", took, cfg.Shutdown.Timeout)
	}
	if _, err := body.ReadString('\n'); err == nil {
		t.Fatal("the stream is still open after the deadline")
	}
}

func TestReadinessDropsWhileDraining(t *testing.T) {
	cfg := config.Defaults()
	cfg.Shutdown.Timeout = 3 * time.Second
	drain := server.NewDrain()
	h := defaultHandlers(drain)
	// A stream that ignores the drain keeps the operations listener up.
	h.Machine = streaming(drain, false)
	r := start(t, cfg, h, drain)
	_ = openStream(t, r.machine+"/watch")

	r.cancel()
	<-drain.Draining()
	if got := get(t, http.DefaultClient, r.operations+"/readyz"); got.status != http.StatusServiceUnavailable {
		t.Fatalf("readyz while draining: %d, want 503", got.status)
	}
}

type response struct {
	status int
	proto  string
	header http.Header
	body   string
}

func get(t *testing.T, client *http.Client, url string) response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, proto: resp.Proto, header: resp.Header, body: string(body)}
}
