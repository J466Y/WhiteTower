package authn_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// logBuffer collects the JSON logs of a service that runs in the background.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// records returns the records whose message is msg.
func (b *logBuffer) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for line := range strings.Lines(b.buf.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// discoveredGauge returns the value of whitetower_oidc_provider_discovered.
func discoveredGauge(t *testing.T, reg *prometheus.Registry) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "whitetower_oidc_provider_discovered" {
			return f.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("no whitetower_oidc_provider_discovered")
	return 0
}

// visit sends a GET request to the service and returns its answer.
func visit(svc *authn.OIDCService, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// checkUnavailable checks the answer of a sign-in route before discovery.
func checkUnavailable(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "10" ||
		rec.Body.String() != "sign-in is unavailable: the server has not reached the identity provider yet; retry later\n" {
		t.Errorf("got %d, Retry-After %q, %q; want 503 with Retry-After and the fixed text", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
}

// Until the service has discovered its provider, the sign-in routes answer
// 503 with Retry-After and the token exchange is unavailable, while a logout
// still signs the browser out of the core. Once discovery succeeds, sign-in
// works, without a new service.
func TestBeforeDiscoverySignInIsUnavailable(t *testing.T) {
	idp := newMockIDP(t)
	idp.discovery = idp.backChannelDocument(frontIssuer)
	clk := clocktest.New(testEpoch)
	opts := backChannelOptions(idp, clk)
	opts.StateKey = newStateKey(t)
	// Nothing reaches the stores before discovery, and a logout without a
	// session cookie revokes nothing.
	opts.Tokens = authn.NewTokenStore(nil, clk, nil)
	svc, err := authn.NewOIDCService(opts, nil, nil, authn.NewSessionStore(nil, clk, authn.SessionOptions{}))
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}

	checkUnavailable(t, visit(svc, "/auth/login"))
	checkUnavailable(t, visit(svc, "/auth/callback?code=a-code&state=a-state"))
	if _, err := svc.ExchangeIDToken(context.Background(), "an ID token"); !errors.Is(err, authn.ErrProviderUnavailable) {
		t.Errorf("exchange: got %v, want ErrProviderUnavailable", err)
	}
	logout := visit(svc, "/auth/logout")
	if logout.Code != http.StatusFound || logout.Header().Get("Location") != "/" {
		t.Errorf("logout: got %d to %q, want a redirect to the console's root", logout.Code, logout.Header().Get("Location"))
	}

	if err := svc.Discover(context.Background()); err != nil {
		t.Fatalf("discovering the provider: %v", err)
	}
	if login := visit(svc, "/auth/login"); login.Code != http.StatusFound ||
		!strings.HasPrefix(login.Header().Get("Location"), frontIssuer+"/protocol/openid-connect/auth?") {
		t.Errorf("login after discovery: got %d to %q, want the issuer's authorization endpoint", login.Code, login.Header().Get("Location"))
	}
}

// Discovery is retried after one second, then after twice as long each time,
// up to a minute, whatever the attempt returned: an error, a closed
// connection, a document that names another issuer, or no document at all.
// Each failure is logged with its reason, and the metric says when sign-in
// becomes available.
func TestDiscoveryBacksOffUntilTheProviderAnswers(t *testing.T) {
	delays := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, time.Minute, time.Minute,
	}
	var requests atomic.Int32
	var provider *httptest.Server
	provider = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		document := map[string]any{
			"issuer":                 frontIssuer,
			"authorization_endpoint": frontIssuer + "/protocol/openid-connect/auth",
			"token_endpoint":         provider.URL + "/token",
			"jwks_uri":               provider.URL + "/jwks",
		}
		switch n := int(requests.Add(1)); {
		case n == 2:
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		case n == 3:
			document["issuer"] = "https://upgrading.example.test/realms/whitetower"
		case n == 4:
			_, _ = w.Write([]byte("<html>Upgrading</html>"))
			return
		case n <= len(delays):
			http.Error(w, "the provider is starting", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(document)
	}))
	// Each attempt opens a connection of its own: Go's client sends a request
	// again when a connection that it reused closes without an answer, which
	// would make two requests of one attempt.
	provider.Config.SetKeepAlivesEnabled(false)
	provider.Start()
	t.Cleanup(provider.Close)

	clk := clocktest.New(testEpoch)
	reg := prometheus.NewRegistry()
	logs := &logBuffer{}
	svc, err := authn.NewOIDCService(authn.OIDCOptions{
		Issuer:       frontIssuer,
		DiscoveryURL: provider.URL,
		ClientID:     "whitetower-console",
		RedirectURL:  "https://127.0.0.1:8443/auth/callback",
		StateKey:     newStateKey(t),
		Clock:        clk,
		Logger:       slog.New(slog.NewJSONHandler(logs, nil)),
		Metrics:      metrics.NewOIDC(reg),
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}
	if v := discoveredGauge(t, reg); v != 0 {
		t.Fatalf("whitetower_oidc_provider_discovered %v before discovery, want 0", v)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Run(ctx)
	}()
	for i, delay := range delays {
		clk.WaitTimers(t, 1)
		if got := int(requests.Load()); got != i+1 {
			t.Fatalf("%d attempts, want %d", got, i+1)
		}
		checkUnavailable(t, visit(svc, "/auth/login"))
		// The service waits for its timer, armed for delay: no attempt
		// happens before it fires.
		clk.Advance(delay - time.Nanosecond)
		clk.WaitTimers(t, 1)
		if got := int(requests.Load()); got != i+1 {
			t.Fatalf("attempt %d came before its delay of %s", got, delay)
		}
		clk.Advance(time.Nanosecond)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return once discovery succeeded")
	}

	if got := int(requests.Load()); got != len(delays)+1 {
		t.Errorf("%d attempts, want %d", got, len(delays)+1)
	}
	if v := discoveredGauge(t, reg); v != 1 {
		t.Errorf("whitetower_oidc_provider_discovered %v after discovery, want 1", v)
	}
	if login := visit(svc, "/auth/login"); login.Code != http.StatusFound {
		t.Errorf("login after discovery: got %d, want 302", login.Code)
	}
	failures := logs.records(t, "sign-in is unavailable: discovering the identity provider failed")
	if len(failures) != len(delays) {
		t.Fatalf("%d failures logged, want %d", len(failures), len(delays))
	}
	document := provider.URL + "/.well-known/openid-configuration"
	for i, r := range failures {
		if r["retry_in"] != delays[i].String() || !strings.Contains(r["error"].(string), document) {
			t.Errorf("failure %d logged as %v, want the retry in %s and an error that names %s", i+1, r, delays[i], document)
		}
	}
	if !strings.Contains(failures[2]["error"].(string), "upgrading.example.test") {
		t.Errorf("the issuer mismatch logged as %q, want the issuer that the document named", failures[2]["error"])
	}
	if len(logs.records(t, "discovered the identity provider: sign-in is available")) != 1 {
		t.Error("the discovery was not logged")
	}
}

// A service that stops retries no more.
func TestDiscoveryStopsWithItsContext(t *testing.T) {
	idp := newMockIDP(t)
	idp.discoveryStatus = http.StatusServiceUnavailable
	clk := clocktest.New(testEpoch)
	opts := backChannelOptions(idp, clk)
	opts.StateKey = newStateKey(t)
	svc, err := authn.NewOIDCService(opts, nil, nil, nil)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Run(ctx)
	}()
	clk.WaitTimers(t, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return once its context ended")
	}
}

// hangingProvider accepts connections and never answers, as a provider that
// is stuck does. It returns its URL and the number of connections it took.
func hangingProvider(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return "http://" + listener.Addr().String() + "/realms/whitetower", &accepted
}

// Each attempt to discover a provider that hangs ends with the timeout of the
// service's HTTP client, and the next attempt follows.
func TestEachDiscoveryAttemptTimesOut(t *testing.T) {
	stuck, accepted := hangingProvider(t)
	clk := clocktest.New(testEpoch)
	svc, err := authn.NewOIDCService(authn.OIDCOptions{
		Issuer:       frontIssuer,
		DiscoveryURL: stuck,
		ClientID:     "whitetower-console",
		RedirectURL:  "https://127.0.0.1:8443/auth/callback",
		StateKey:     newStateKey(t),
		Timeout:      100 * time.Millisecond,
		Clock:        clk,
		Logger:       slog.New(slog.DiscardHandler),
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("creating OIDC service: %v", err)
	}

	// reached waits until the provider has taken n connections, one for each
	// attempt. The provider counts a connection once Accept returns, which
	// can come after the attempt has timed out: the kernel completes the
	// handshake before the provider's goroutine runs.
	reached := func(n int32) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); accepted.Load() < n; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("the provider took %d connections, want %d: each attempt must reach it", accepted.Load(), n)
			}
		}
	}

	attempt := make(chan error, 1)
	go func() { attempt <- svc.Discover(context.Background()) }()
	select {
	case err := <-attempt:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Errorf("got %v, want a timeout", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a discovery attempt against a provider that hangs did not time out")
	}
	reached(1)

	// Run's first attempt ends, and Run waits for its delay; once it has
	// passed, the next attempt reaches the provider, and ends too.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Run(ctx)
	}()
	clk.WaitTimers(t, 1)
	reached(2)
	clk.Advance(time.Second)
	clk.WaitTimers(t, 1)
	reached(3)
	cancel()
	<-done
}

// writeCA writes the certificate of a TLS test server to a PEM file.
func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A provider on an HTTPS back channel, whose certificate the system does not
// trust, is trusted with the CA file: discovery, the token exchange and the
// signing keys all go through the service's client, which trusts it. Without
// the CA file, discovery refuses the provider's certificate.
func TestTheCAFileTrustsTheProvidersBackChannel(t *testing.T) {
	idp := newTLSMockIDP(t)
	idp.discovery = idp.backChannelDocument(frontIssuer)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, tokenStore, database := setupAuthn(t, clk)

	untrusted := backChannelOptions(idp, clk)
	if err := discover(t, untrusted); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("discovery without the CA file: %v, want a certificate error", err)
	}

	opts := backChannelOptions(idp, clk)
	opts.CAFile = writeCA(t, idp.server)
	opts.Tokens = tokenStore
	svc := newService(t, opts, database, principalStore, sessionStore)
	if rec := signInThroughBackChannel(t, svc, idp, clk, frontIssuer); rec.Code != http.StatusFound {
		t.Fatalf("a sign-in through the provider over HTTPS: got %d %q, want 302", rec.Code, rec.Body.String())
	}
	rawToken := idp.signIDToken(map[string]any{"alg": "RS256"}, map[string]any{
		"iss":    frontIssuer,
		"aud":    "wtctl",
		"sub":    "cli-over-https",
		"exp":    clk.Now().Add(time.Hour).Unix(),
		"groups": []string{"wt-owners"},
	})
	if _, err := svc.ExchangeIDToken(context.Background(), rawToken); err != nil {
		t.Fatalf("an exchange through the provider over HTTPS: %v", err)
	}
}

// Replicas, and a replica that restarts, sign the state of a sign-in with the
// same key: a sign-in that starts on one ends on another. A service with
// another key refuses the state.
func TestASignInEndsOnAnyServiceWithTheSameStateKey(t *testing.T) {
	idp := newMockIDP(t)
	idp.discovery = idp.backChannelDocument(frontIssuer)
	clk := clocktest.New(testEpoch)
	sessionStore, principalStore, _, database := setupAuthn(t, clk)
	opts := backChannelOptions(idp, clk)
	opts.StateKey = newStateKey(t)
	first := newService(t, opts, database, principalStore, sessionStore)
	second := newService(t, opts, database, principalStore, sessionStore)
	opts.StateKey = newStateKey(t)
	other := newService(t, opts, database, principalStore, sessionStore)

	// callback ends on svc a sign-in that started on first.
	callback := func(svc *authn.OIDCService) *httptest.ResponseRecorder {
		t.Helper()
		stateCookie, state, nonce := initiateLogin(t, first, "/")
		idp.customToken = idp.signIDToken(map[string]any{"alg": "RS256"}, map[string]any{
			"iss":   frontIssuer,
			"aud":   "whitetower-console",
			"sub":   "usr-replicas",
			"exp":   clk.Now().Add(time.Hour).Unix(),
			"nonce": nonce,
		})
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+url.QueryEscape(state), nil)
		req.AddCookie(stateCookie)
		rec := httptest.NewRecorder()
		svc.ServeHTTP(rec, req)
		return rec
	}
	if rec := callback(second); rec.Code != http.StatusFound {
		t.Errorf("a sign-in that ends on another service with the same key: got %d %q, want 302", rec.Code, rec.Body.String())
	}
	if rec := callback(other); rec.Code != http.StatusBadRequest ||
		rec.Body.String() != "invalid OIDC state cookie: state signature verification failed\n" {
		t.Errorf("a sign-in that ends on a service with another key: got %d %q, want the state refused", rec.Code, rec.Body.String())
	}
}

// The state key's file holds base64, which may wrap, of at least 32 bytes.
// The errors never repeat the file's content.
func TestParseStateKey(t *testing.T) {
	key48 := bytes.Repeat([]byte{0xa5}, 48)
	wrapped := base64.StdEncoding.EncodeToString(key48)
	wrapped = wrapped[:40] + "\n" + wrapped[40:] + "\n"
	for _, tt := range []struct {
		name, text string
		want       []byte
	}{
		{"32 bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)) + "\n", bytes.Repeat([]byte{0x5a}, 32)},
		{"48 bytes on two lines", wrapped, key48},
	} {
		got, err := authn.ParseStateKey([]byte(tt.text))
		if err != nil || !bytes.Equal(got, tt.want) {
			t.Errorf("%s: got %x, %v", tt.name, got, err)
		}
	}
	for _, tt := range []struct{ name, text, want string }{
		{"31 bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 31)), "the key holds 31 bytes: want at least 32"},
		{"a passphrase", "canary-not-a-key-but-a-long-passphrase-of-many-words", "not base64"},
		{"URL-safe base64", strings.Repeat("-_", 22), "not base64"},
		{"empty", "", "the key holds 0 bytes"},
	} {
		_, err := authn.ParseStateKey([]byte(tt.text))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want %q", tt.name, err, tt.want)
		}
		if err != nil && tt.text != "" && strings.Contains(err.Error(), tt.text) {
			t.Errorf("%s: the error repeats the file's content: %v", tt.name, err)
		}
	}
}
