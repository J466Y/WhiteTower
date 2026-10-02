// Package rest implements the public REST API described in api/openapi,
// behind the middleware every request goes through: security headers, panic
// recovery, authentication, rate limiting and, for each operation,
// authorization.
package rest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/internal/version"
)

// BasePath is where the public API is mounted.
const BasePath = "/api/v1"

// Options are what the public API needs from the rest of the server.
type Options struct {
	// Logger receives what clients only see as an internal error.
	Logger *slog.Logger
	// Authenticator identifies the caller of a request.
	Authenticator auth.Authenticator
	// Authorizer decides which operations a principal may call.
	Authorizer auth.Authorizer
	// Limiter limits each principal or, before login, each client address.
	Limiter *ratelimit.Limiter
	// RateLimited, when set, counts the requests that Limiter refuses.
	RateLimited func()
}

// Server implements the operations of the public API.
type Server struct{}

var _ gen.StrictServerInterface = Server{}

// GetVersion returns the version of the running server.
func (Server) GetVersion(context.Context, gen.GetVersionRequestObject) (gen.GetVersionResponseObject, error) {
	v := version.Get()
	return gen.GetVersion200JSONResponse{
		Version:    v.Version,
		Commit:     v.Commit,
		ApiVersion: gen.V1,
	}, nil
}

// GetMe returns the calling principal; the authorization middleware has
// already refused anonymous requests.
func (Server) GetMe(ctx context.Context, _ gen.GetMeRequestObject) (gen.GetMeResponseObject, error) {
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "this operation needs a session or an API token")
	}
	id, err := uuid.Parse(p.ID)
	if err != nil {
		return nil, fmt.Errorf("principal ID %q: %w", p.ID, err)
	}
	return gen.GetMe200JSONResponse{
		Id:          id,
		Kind:        gen.PrincipalKind(p.Kind),
		DisplayName: p.Name,
		Roles:       append([]string{}, p.Roles...),
	}, nil
}

// Handler returns the public API, which expects requests under BasePath: the
// operations of api/openapi, and the document itself at openapi.json.
func Handler(opts Options) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+BasePath+"/openapi.json", documentHandler())
	strict := gen.NewStrictHandlerWithOptions(Server{}, []gen.StrictMiddlewareFunc{authorize(opts.Authorizer)},
		gen.StrictHTTPServerOptions{
			RequestErrorHandlerFunc:  requestError,
			ResponseErrorHandlerFunc: responseError(opts.Logger),
		})
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseURL:          BasePath,
		BaseRouter:       mux,
		ErrorHandlerFunc: parameterError,
	})
	mux.Handle(BasePath+"/", unmatched(mux))
	return chain(routed(mux), opts)
}

// chain puts the middleware around the API's router. From the outside in:
// headers, panics, who calls, how fast; then the operation, which authorize
// guards.
func chain(router http.Handler, opts Options) http.Handler {
	h := limitRate(router, opts)
	h = authenticate(h, opts.Authenticator)
	h = recoverPanics(h, opts.Logger)
	return secure(h)
}

// routed reports the route the mux matched to the observer, which sees only
// the request it handed on.
func routed(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
		logging.SetRoute(r.Context(), r.Pattern)
	})
}
