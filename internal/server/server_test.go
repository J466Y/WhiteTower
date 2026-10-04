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
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/J466Y/WhiteTower/internal/api/moduleapi"
	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/config"
	"github.com/J466Y/WhiteTower/internal/platform/health"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/internal/server"
	"github.com/J466Y/WhiteTower/internal/version"
	"github.com/J466Y/WhiteTower/internal/webui"
	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

func TestConsoleHandler(t *testing.T) {
	srv := httptest.NewServer(server.ConsoleHandler(publicAPI()))
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

func TestLimitBody(t *testing.T) {
	reached := false
	h := server.LimitBody(10,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusRequestEntityTooLarge) }),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			if _, err := io.ReadAll(r.Body); err != nil {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))

	for _, tt := range []struct {
		name    string
		body    io.Reader
		size    int64
		status  int
		reached bool
	}{
		{"within the limit", strings.NewReader("small"), 5, http.StatusOK, true},
		{"announced over the limit: refused before the handler", strings.NewReader(strings.Repeat("x", 11)), 11, http.StatusRequestEntityTooLarge, false},
		{"unannounced over the limit: cut as the handler reads", strings.NewReader(strings.Repeat("x", 11)), -1, http.StatusRequestEntityTooLarge, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reached = false
			r := httptest.NewRequest(http.MethodPost, "/", tt.body)
			r.ContentLength = tt.size
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != tt.status || reached != tt.reached {
				t.Fatalf("status %d, handler reached %v; want %d and %v", rec.Code, reached, tt.status, tt.reached)
			}
		})
	}
}

// Security test ST-05: a request over the size limit of its listener is
// refused before it reaches a handler. The machine listener answers in the
// caller's RPC protocol, as the module API answers a message over its limit.
func TestListenersRefuseLargeBodies(t *testing.T) {
	drain := server.NewDrain()
	r := start(t, config.Defaults(), defaultHandlers(drain), drain)
	post := func(client *http.Client, url, contentType string, size int) (int, http.Header, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(strings.Repeat("x", size)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		// gRPC sends its status in the trailers.
		for k, v := range resp.Trailer {
			resp.Header[k] = v
		}
		return resp.StatusCode, resp.Header, string(body)
	}
	status, header, _ := post(insecureClient(false), r.console+"/api/v1/me", "application/json", server.MaxConsoleBody+1)
	if status != http.StatusRequestEntityTooLarge || header.Get("Content-Type") != "application/problem+json" {
		t.Errorf("console: %d %s, want 413 as a problem", status, header.Get("Content-Type"))
	}
	if status, _, _ := post(http.DefaultClient, r.operations+"/healthz", "text/plain", server.MaxOperationsBody+1); status != http.StatusRequestEntityTooLarge {
		t.Errorf("operations: %d, want 413", status)
	}
	for _, tt := range []struct {
		contentType string
		status      int
		grpcStatus  string
		body        string
	}{
		{"application/proto", http.StatusTooManyRequests, "", `"code":"resource_exhausted"`},
		{"application/grpc", http.StatusOK, "8", ""},
		{"text/plain", http.StatusRequestEntityTooLarge, "", "request body too large\n"},
	} {
		status, header, body := post(insecureClient(true), r.machine+modulev1alpha1connect.MetaServiceGetServerInfoProcedure,
			tt.contentType, server.MaxMachineBody+1)
		if status != tt.status || header.Get("Grpc-Status") != tt.grpcStatus || !strings.Contains(body, tt.body) {
			t.Errorf("machine, %s: %d, grpc-status %q, body %q; want %d, %q, %q",
				tt.contentType, status, header.Get("Grpc-Status"), body, tt.status, tt.grpcStatus, tt.body)
		}
	}
}

func TestListenersRefuseHugeHeaders(t *testing.T) {
	drain := server.NewDrain()
	r := start(t, config.Defaults(), defaultHandlers(drain), drain)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, r.operations+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Padding", strings.Repeat("x", 100<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status %d, want 431", resp.StatusCode)
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

// publicAPI is the public API as the server builds it before plan P1-03:
// nobody is authenticated.
func publicAPI() http.Handler {
	return rest.Handler(rest.Options{
		Logger:        slog.New(slog.DiscardHandler),
		Authenticator: auth.Unauthenticated{},
		Authorizer:    auth.DenyAll{},
		Limiter:       ratelimit.New(1000, 1000),
	})
}

// moduleIdentity is the caller that the test token stands for.
const moduleIdentity = "spiffe://example.org/module/0192f2c4-0000-7000-8000-000000000009"

// moduleTokens accepts the token "test", and nothing else.
type moduleTokens struct{}

func (moduleTokens) Authenticate(_ context.Context, header http.Header) (*moduleapi.Caller, error) {
	if header.Get("Authorization") != "Bearer test" {
		return nil, errors.New("not the test token")
	}
	return &moduleapi.Caller{Identity: moduleIdentity}, nil
}

// moduleAPI is the module API as the server builds it, but for its tokens:
// the server issues none before plan P1-05, and tests use the token "test".
func moduleAPI(reg prometheus.Registerer) http.Handler {
	return moduleapi.Handler(moduleapi.Options{
		Logger:        slog.New(slog.DiscardHandler),
		Authenticator: moduleTokens{},
		Metrics:       metrics.NewRPC(reg),
	})
}

// withToken is a module API request with the test token.
func withToken[T any](msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer test")
	return req
}

// defaultHandlers are the handlers of the server binary, instrumented as it
// instruments them, with the module API of moduleAPI.
func defaultHandlers(drain *server.Drain) server.Handlers {
	discard := slog.New(slog.DiscardHandler)
	registry := metrics.NewRegistry(version.Get())
	observer := server.NewObserver(discard, metrics.NewHTTP(registry), noop.NewTracerProvider())
	return server.Handlers{
		Console:    observer.Wrap("console", server.ConsoleHandler(publicAPI())),
		Machine:    observer.Wrap("machine", server.MachineHandler(moduleAPI(registry))),
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
			resp, err := client.GetServerInfo(context.Background(), withToken(&modulev1alpha1.GetServerInfoRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(resp.Msg.GetContractVersions(), "v1alpha1") {
				t.Fatalf("contract versions %v", resp.Msg.GetContractVersions())
			}
		})
	}

	t.Run("module API without a token", func(t *testing.T) {
		client := modulev1alpha1connect.NewMetaServiceClient(insecureClient(true), r.machine, connect.WithGRPC())
		_, err := client.GetServerInfo(context.Background(), connect.NewRequest(&modulev1alpha1.GetServerInfoRequest{}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("got %v, want UNAUTHENTICATED", err)
		}
	})

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

// A connection that falls silent gets a ping, and is closed when the ping
// goes unanswered: the module API's watch streams do not outlive their peers.
func TestSilentConnectionsArePingedThenClosed(t *testing.T) {
	saved := *server.HTTP2Config
	t.Cleanup(func() { *server.HTTP2Config = saved })
	server.HTTP2Config.SendPingTimeout = 200 * time.Millisecond
	server.HTTP2Config.PingTimeout = 300 * time.Millisecond
	drain := server.NewDrain()
	r := start(t, config.Defaults(), defaultHandlers(drain), drain)

	conn, err := tls.Dial("tcp", strings.TrimPrefix(r.machine, "https://"),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("negotiated %q, want h2", p)
	}
	write := func(b []byte) {
		t.Helper()
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	// An HTTP/2 frame header (RFC 9113, section 4.1): a 24-bit length, the
	// type, the flags and a 31-bit stream identifier.
	const settings, ping, ack = 0x4, 0x6, 0x1
	frame := func(typ, flags byte) []byte { return []byte{0, 0, 0, typ, flags, 0, 0, 0, 0} }
	// The client's preface and empty settings; then nothing but the
	// acknowledgement of the server's settings.
	write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), frame(settings, 0)...))
	began := time.Now()
	_ = conn.SetReadDeadline(began.Add(5 * time.Second))
	var timeout net.Error
	pinged := false
	for header := make([]byte, 9); ; {
		_, err := io.ReadFull(conn, header)
		if err == nil {
			length := int64(header[0])<<16 | int64(header[1])<<8 | int64(header[2])
			_, err = io.CopyN(io.Discard, conn, length)
		}
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("the connection is still open after %s; pinged: %v", time.Since(began), pinged)
		}
		if err != nil {
			break
		}
		switch {
		case header[3] == settings && header[4]&ack == 0:
			write(frame(settings, ack))
		case header[3] == ping && header[4]&ack == 0:
			pinged = true
		}
	}
	if !pinged {
		t.Fatal("the connection was closed without a ping")
	}
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
