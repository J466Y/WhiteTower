// Package resttest serves the public API in tests, and points its generated
// client at it (plan P1-01, step 10). A test chooses what the operations
// depend on in rest.Options; resttest fills in what it leaves out: a logger
// that discards, an authenticator that takes the principal from As, an
// authorizer that permits everything, and no practical rate limit.
//
// The authenticator trusts a request header, so the server code never
// imports this package: a lint rule keeps test helpers out of it.
package resttest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/J466Y/WhiteTower/internal/api/rest"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/pkg/apiclient"
)

// Server is the public API, served until the test ends.
type Server struct {
	// URL is the base URL of the API, such as http://127.0.0.1:1234/api/v1.
	URL string
	// Client is the API's generated client, pointed at URL.
	Client *apiclient.ClientWithResponses
}

// New serves the public API with opts for the test.
func New(t testing.TB, opts rest.Options) *Server {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Authenticator == nil {
		opts.Authenticator = Authenticator{}
	}
	if opts.Authorizer == nil {
		opts.Authorizer = AllowAll{}
	}
	if opts.Limiter == nil {
		opts.Limiter = ratelimit.New(1e6, 1e6)
	}
	srv := httptest.NewServer(rest.Handler(opts))
	t.Cleanup(srv.Close)
	url := srv.URL + rest.BasePath
	client, err := apiclient.NewClientWithResponses(url, apiclient.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return &Server{URL: url, Client: client}
}

// principalHeader carries the principal that As names, for Authenticator.
const principalHeader = "X-Test-Principal"

// As makes a request act as p: pass it to a client method.
func As(p auth.Principal) apiclient.RequestEditorFn {
	header, err := json.Marshal(p)
	return func(_ context.Context, r *http.Request) error {
		if err != nil {
			return err
		}
		r.Header.Set(principalHeader, string(header))
		return nil
	}
}

// Authenticator authenticates the principal that As named. A request
// without one is anonymous.
type Authenticator struct{}

// Authenticate implements auth.Authenticator.
func (Authenticator) Authenticate(r *http.Request) (*auth.Principal, error) {
	header := r.Header.Get(principalHeader)
	if header == "" {
		return nil, nil
	}
	var p auth.Principal
	if err := json.Unmarshal([]byte(header), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// AllowAll permits every operation to every principal.
type AllowAll struct{}

// Authorize implements auth.Authorizer.
func (AllowAll) Authorize(context.Context, *auth.Principal, string) error { return nil }
