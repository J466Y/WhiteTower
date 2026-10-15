// Package rest implements the public REST API described in api/openapi,
// behind the middleware every request goes through: security headers, panic
// recovery, authentication, rate limiting and, for each operation,
// authorization.
package rest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/api/rest/gen"
	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/internal/version"
)

// BasePath is where the public API is mounted.
const BasePath = "/api/v1"

// CSRFValidator validates whether a request carries a valid CSRF token.
type CSRFValidator interface {
	ValidateRequestCSRF(r *http.Request) bool
}

// Options are what the public API needs from the rest of the server.
type Options struct {
	// Logger receives what clients only see as an internal error.
	Logger *slog.Logger
	// Authenticator identifies the caller of a request.
	Authenticator auth.Authenticator
	// Authorizer decides which operations a principal may call.
	Authorizer auth.Authorizer
	// CSRF validates CSRF tokens on state-changing requests when sessions are used.
	CSRF CSRFValidator
	// Limiter limits each principal or, before login, each client address.
	Limiter *ratelimit.Limiter
	// RateLimited, when set, counts the requests that Limiter refuses.
	RateLimited func()
	// Tokens manages personal access and service account tokens.
	Tokens *authn.TokenStore
	// Principals manages principal records and service accounts.
	Principals *authn.PrincipalStore
	// Exchanger handles CLI ID token exchange for API tokens.
	Exchanger TokenExchanger
}

// TokenExchanger validates and exchanges an OpenID Connect ID token for an API token.
type TokenExchanger interface {
	ExchangeIDToken(ctx context.Context, rawIDToken string) (*authn.CreatedToken, error)
}

// Server implements the operations of the public API.
type Server struct {
	tokens     *authn.TokenStore
	principals *authn.PrincipalStore
	exchanger  TokenExchanger
}

// NewServer creates a new Server instance.
func NewServer(tokens *authn.TokenStore, principals *authn.PrincipalStore, exchanger TokenExchanger) Server {
	return Server{
		tokens:     tokens,
		principals: principals,
		exchanger:  exchanger,
	}
}

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
	res := gen.GetMe200JSONResponse{
		Id:          id,
		Kind:        gen.PrincipalKind(p.Kind),
		DisplayName: p.Name,
		Roles:       append([]string{}, p.Roles...),
		Permissions: authz.PermissionsList(p.Roles),
	}
	if session := authn.SessionFromContext(ctx); session != nil && session.CSRFToken != "" {
		res.CsrfToken = &session.CSRFToken
	}
	if p.IsBreakglass {
		res.IsBreakglass = &p.IsBreakglass
	}
	return res, nil
}

// ListTokens returns API tokens for the caller or a service account.
func (s Server) ListTokens(ctx context.Context, request gen.ListTokensRequestObject) (gen.ListTokensResponseObject, error) {
	if s.tokens == nil {
		return nil, problem.New(problem.Internal, "tokens store not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}

	targetPrincipalID, err := uuid.Parse(p.ID)
	if err != nil {
		return nil, problem.New(problem.BadRequest, "invalid caller principal ID")
	}

	if request.Params.PrincipalId != nil {
		requestedID := *request.Params.PrincipalId
		if requestedID != targetPrincipalID {
			targetP, err := s.principals.GetByID(ctx, requestedID)
			if err != nil {
				return nil, problem.New(problem.NotFound, "principal not found")
			}
			isResponsible := targetP.ResponsiblePrincipalID != nil && *targetP.ResponsiblePrincipalID == targetPrincipalID
			isAdmin := slices.Contains(p.Roles, "admin")
			if !isResponsible && !isAdmin {
				return nil, problem.New(problem.Forbidden, "cannot list tokens for another principal")
			}
			targetPrincipalID = requestedID
		}
	}

	tokens, err := s.tokens.ListByPrincipal(ctx, targetPrincipalID)
	if err != nil {
		return nil, fmt.Errorf("listing tokens: %w", err)
	}

	res := make(gen.ListTokens200JSONResponse, len(tokens))
	for i, t := range tokens {
		res[i] = gen.ApiTokenMetadata{
			Id:          t.ID,
			PrincipalId: t.PrincipalID,
			Name:        t.Name,
			TokenPrefix: t.TokenPrefix,
			Scopes:      t.Scopes,
			CreatedAt:   t.CreatedAt,
			ExpiresAt:   t.ExpiresAt,
			LastUsedAt:  t.LastUsedAt,
			RevokedAt:   t.RevokedAt,
		}
	}
	return res, nil
}

// CreateToken creates a new API token.
func (s Server) CreateToken(ctx context.Context, request gen.CreateTokenRequestObject) (gen.CreateTokenResponseObject, error) {
	if s.tokens == nil {
		return nil, problem.New(problem.Internal, "tokens store not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}
	if request.Body == nil {
		return nil, problem.New(problem.BadRequest, "request body is required")
	}

	targetPrincipalID, err := uuid.Parse(p.ID)
	if err != nil {
		return nil, problem.New(problem.BadRequest, "invalid caller principal ID")
	}

	var targetRoles []string
	if request.Body.PrincipalId != nil && *request.Body.PrincipalId != targetPrincipalID {
		requestedID := *request.Body.PrincipalId
		targetP, err := s.principals.GetByID(ctx, requestedID)
		if err != nil {
			return nil, problem.New(problem.NotFound, "target principal not found")
		}
		isResponsible := targetP.ResponsiblePrincipalID != nil && *targetP.ResponsiblePrincipalID == targetPrincipalID
		isAdmin := slices.Contains(p.Roles, "admin")
		if !isResponsible && !isAdmin {
			return nil, problem.New(problem.Forbidden, "cannot create token for another principal")
		}
		targetPrincipalID = requestedID
		targetRoles, err = s.principals.GetRoles(ctx, targetPrincipalID)
		if err != nil {
			return nil, fmt.Errorf("resolving target roles: %w", err)
		}
	} else {
		targetRoles = p.Roles
	}

	// Validate scopes are subset of target principal permissions
	allowedPerms := authz.PermissionsList(targetRoles)
	for _, sc := range request.Body.Scopes {
		if !slices.Contains(allowedPerms, sc) {
			return nil, problem.New(problem.BadRequest, fmt.Sprintf("scope %q is not granted by principal's roles", sc))
		}
	}

	expiresInDays := 30
	if request.Body.ExpiresInDays != nil {
		expiresInDays = *request.Body.ExpiresInDays
	}

	created, err := s.tokens.Create(ctx, targetPrincipalID, request.Body.Name, request.Body.Scopes, expiresInDays, *p)
	if err != nil {
		return nil, problem.New(problem.BadRequest, err.Error())
	}

	return gen.CreateToken201JSONResponse{
		Id:          created.ID,
		PrincipalId: created.PrincipalID,
		Name:        created.Name,
		TokenPrefix: created.TokenPrefix,
		Scopes:      created.Scopes,
		Token:       created.Token,
		CreatedAt:   created.CreatedAt,
		ExpiresAt:   created.ExpiresAt,
	}, nil
}

// RevokeToken revokes an API token by ID.
func (s Server) RevokeToken(ctx context.Context, request gen.RevokeTokenRequestObject) (gen.RevokeTokenResponseObject, error) {
	if s.tokens == nil {
		return nil, problem.New(problem.Internal, "tokens store not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}

	reason := "manual revocation"
	if request.Params.Reason != nil && *request.Params.Reason != "" {
		reason = *request.Params.Reason
	}

	if err := s.tokens.Revoke(ctx, request.Id, *p, reason); err != nil {
		if errors.Is(err, authn.ErrTokenNotFound) {
			return nil, problem.New(problem.NotFound, "token not found")
		}
		return nil, fmt.Errorf("revoking token: %w", err)
	}

	return gen.RevokeToken204Response{}, nil
}

// CreateServiceAccount provisions a new service account.
func (s Server) CreateServiceAccount(ctx context.Context, request gen.CreateServiceAccountRequestObject) (gen.CreateServiceAccountResponseObject, error) {
	if s.principals == nil {
		return nil, problem.New(problem.Internal, "principals store not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}
	if request.Body == nil {
		return nil, problem.New(problem.BadRequest, "request body is required")
	}

	callerID, err := uuid.Parse(p.ID)
	if err != nil {
		return nil, problem.New(problem.BadRequest, "invalid caller principal ID")
	}

	var email *string
	if request.Body.Email != nil {
		e := string(*request.Body.Email)
		email = &e
	}

	sa, err := s.principals.CreateServiceAccount(ctx, request.Body.DisplayName, email, callerID, request.Body.Roles, callerID)
	if err != nil {
		return nil, problem.New(problem.BadRequest, err.Error())
	}

	roles, err := s.principals.GetRoles(ctx, sa.ID)
	if err != nil {
		return nil, fmt.Errorf("reading roles for service account: %w", err)
	}

	var respID uuid.UUID
	if sa.ResponsiblePrincipalID != nil {
		respID = *sa.ResponsiblePrincipalID
	}

	return gen.CreateServiceAccount201JSONResponse{
		Id:                     sa.ID,
		DisplayName:            sa.DisplayName,
		Email:                  sa.Email,
		Status:                 gen.ServiceAccountStatus(sa.Status),
		ResponsiblePrincipalId: respID,
		Roles:                  roles,
		CreatedAt:              sa.CreatedAt,
	}, nil
}

// ListServiceAccounts returns service accounts.
func (s Server) ListServiceAccounts(ctx context.Context, _ gen.ListServiceAccountsRequestObject) (gen.ListServiceAccountsResponseObject, error) {
	if s.principals == nil {
		return nil, problem.New(problem.Internal, "principals store not initialized")
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return nil, problem.New(problem.Unauthenticated, "authentication required")
	}

	callerID, err := uuid.Parse(p.ID)
	if err != nil {
		return nil, problem.New(problem.BadRequest, "invalid caller principal ID")
	}

	var filter *uuid.UUID
	if !slices.Contains(p.Roles, "admin") {
		filter = &callerID
	}

	sas, err := s.principals.ListServiceAccounts(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing service accounts: %w", err)
	}

	res := make(gen.ListServiceAccounts200JSONResponse, len(sas))
	for i, sa := range sas {
		roles, _ := s.principals.GetRoles(ctx, sa.ID)
		var respID uuid.UUID
		if sa.ResponsiblePrincipalID != nil {
			respID = *sa.ResponsiblePrincipalID
		}
		res[i] = gen.ServiceAccount{
			Id:                     sa.ID,
			DisplayName:            sa.DisplayName,
			Email:                  sa.Email,
			Status:                 gen.ServiceAccountStatus(sa.Status),
			ResponsiblePrincipalId: respID,
			Roles:                  roles,
			CreatedAt:              sa.CreatedAt,
		}
	}
	return res, nil
}

// ExchangeToken exchanges an IdP ID token from the CLI's login for a short-lived API token.
func (s Server) ExchangeToken(ctx context.Context, request gen.ExchangeTokenRequestObject) (gen.ExchangeTokenResponseObject, error) {
	if s.exchanger == nil {
		return nil, problem.New(problem.Internal, "token exchange is not configured")
	}
	if request.Body == nil || strings.TrimSpace(request.Body.IdToken) == "" {
		return nil, problem.New(problem.BadRequest, "idToken is required")
	}
	created, err := s.exchanger.ExchangeIDToken(ctx, request.Body.IdToken)
	if err != nil {
		if errors.Is(err, authn.ErrPrincipalInactive) {
			return nil, problem.New(problem.Forbidden, "account is deactivated")
		}
		if errors.Is(err, authn.ErrInvalidToken) {
			return nil, problem.New(problem.Unauthenticated, "invalid ID token: "+err.Error())
		}
		return nil, fmt.Errorf("exchanging id token: %w", err)
	}
	return gen.ExchangeToken200JSONResponse{
		Id:          created.ID,
		PrincipalId: created.PrincipalID,
		Name:        created.Name,
		TokenPrefix: created.TokenPrefix,
		Scopes:      append([]string{}, created.Scopes...),
		Token:       created.Token,
		CreatedAt:   created.CreatedAt,
		ExpiresAt:   created.ExpiresAt,
	}, nil
}

// Handler returns the public API, which expects requests under BasePath: the
// operations of api/openapi, and the document itself at openapi.json.
func Handler(opts Options) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET "+BasePath+"/openapi.json", documentHandler())
	strict := gen.NewStrictHandlerWithOptions(NewServer(opts.Tokens, opts.Principals, opts.Exchanger), []gen.StrictMiddlewareFunc{authorize(opts.Authorizer)},
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
	h = csrf(h, opts.CSRF)
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
