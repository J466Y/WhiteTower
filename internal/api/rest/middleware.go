package rest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"time"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

// secure sets the headers of every API response: nothing is cached, since
// answers can be personal or sensitive; nothing renders as a page; and other
// origins cannot embed the answers.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// recoverPanics answers a panic in a handler with an internal problem, and
// logs it with its stack; the client learns nothing more (threat model,
// T-10).
func recoverPanics(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if p == http.ErrAbortHandler { //nolint:errorlint // a sentinel panic value, as net/http compares it
				panic(p)
			}
			logger.ErrorContext(r.Context(), "panic serving a request",
				"panic", logging.Sanitize(fmt.Sprint(p)), "stack", string(debug.Stack()))
			problem.Write(w, r, problem.New(problem.Internal, ""))
		}()
		next.ServeHTTP(w, r)
	})
}

// authenticate identifies the caller, and refuses a credential that is not
// accepted. An anonymous request goes on: authorize decides, operation by
// operation, whether it may.
func authenticate(next http.Handler, a auth.Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r)
		if err != nil {
			problem.Write(w, r, problem.New(problem.Unauthenticated, "the credentials of the request were not accepted"))
			return
		}
		if p != nil {
			ctx := auth.WithPrincipal(r.Context(), p)
			logging.SetPrincipal(ctx, p.ID)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// limitRate refuses a caller over its rate: each principal has its own
// bucket and, before login, each client address.
func limitRate(next http.Handler, opts Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := opts.Limiter.Allow(rateKey(r), time.Now()); !ok {
			if opts.RateLimited != nil {
				opts.RateLimited()
			}
			p := problem.New(problem.RateLimited, "slow down, then retry")
			p.RetryAfter = wait
			problem.Write(w, r, p)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateKey returns the bucket of a request: its principal's, or its client
// address's. The address is that of the connection: behind a proxy, the
// proxy's (plan P1-12 adds trusted proxies).
func rateKey(r *http.Request) string {
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		return "principal " + p.ID
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return "address " + ratelimit.AddressKey(ap.Addr())
	}
	return "address " + r.RemoteAddr
}

// authorize lets an operation run only when the document marks it public, or
// when the principal may call it. Every operation goes through it, so none
// can bypass authorization; an operation the document does not mark public
// needs a principal, and one it does not know is refused (fail-closed).
func authorize(az auth.Authorizer) gen.StrictMiddlewareFunc {
	ops := operations()
	return func(next gen.StrictHandlerFunc, name string) gen.StrictHandlerFunc {
		op, known := ops[operationKey(name)]
		if known && op.Public {
			return next
		}
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			p := auth.PrincipalFrom(ctx)
			if p == nil {
				return nil, problem.New(problem.Unauthenticated, "this operation needs a session or an API token")
			}
			if !known || az.Authorize(ctx, p, op.ID) != nil {
				return nil, problem.New(problem.Forbidden, "your roles do not permit this operation")
			}
			return next(ctx, w, r, request)
		}
	}
}

// unmatched answers what matches no operation: a method not allowed, with
// the allowed ones, when the path exists, and not found otherwise.
func unmatched(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var allow []string
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			probe := r.Clone(r.Context())
			probe.Method = method
			if _, pattern := mux.Handler(probe); pattern != BasePath+"/" {
				allow = append(allow, method)
			}
		}
		if len(allow) == 0 {
			problem.Write(w, r, problem.New(problem.NotFound, "no operation of the API has this path"))
			return
		}
		p := problem.New(problem.MethodNotAllowed, "this path does not support the method")
		p.Allow = allow
		problem.Write(w, r, p)
	})
}

// requestError answers a request whose body cannot be read: too large, or
// not JSON.
func requestError(w http.ResponseWriter, r *http.Request, err error) {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		problem.Write(w, r, problem.New(problem.PayloadTooLarge, "the request body is larger than the server accepts"))
		return
	}
	problem.Write(w, r, problem.New(problem.BadRequest, "the request body is not valid JSON"))
}

// parameterError answers a request whose parameters do not fit the
// operation. It names the parameter, never its value.
func parameterError(w http.ResponseWriter, r *http.Request, err error) {
	name := ""
	if e, ok := errors.AsType[*gen.InvalidParamFormatError](err); ok {
		name = e.ParamName
	} else if e, ok := errors.AsType[*gen.RequiredParamError](err); ok {
		name = e.ParamName
	} else if e, ok := errors.AsType[*gen.RequiredHeaderError](err); ok {
		name = e.ParamName
	} else if e, ok := errors.AsType[*gen.UnmarshalingParamError](err); ok {
		name = e.ParamName
	} else if e, ok := errors.AsType[*gen.TooManyValuesForParamError](err); ok {
		name = e.ParamName
	} else if e, ok := errors.AsType[*gen.UnescapedCookieParamError](err); ok {
		name = e.ParamName
	}
	detail := "a parameter of the request is missing or malformed"
	if name != "" {
		detail = fmt.Sprintf("the parameter %q is missing or malformed", logging.Sanitize(name))
	}
	problem.Write(w, r, problem.New(problem.BadRequest, detail))
}

// responseError answers the error an operation returned: a problem as it is,
// and anything else as an internal error, with the details in the log only.
func responseError(logger *slog.Logger) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if p, ok := errors.AsType[*problem.Problem](err); ok {
			problem.Write(w, r, p)
			return
		}
		if r.Context().Err() != nil {
			return // the client went away
		}
		logger.ErrorContext(r.Context(), "operation failed", "error", err.Error())
		problem.Write(w, r, problem.New(problem.Internal, ""))
	}
}
