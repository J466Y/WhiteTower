// Package auth holds who makes a request, and the two questions every
// request on the public API goes through: who is it (Authenticator), and may
// it do this (Authorizer). Plan P1-03 answers them with sessions, API tokens
// and the permission matrix; until then, nobody is authenticated and only
// public operations can be called.
package auth

import (
	"context"
	"errors"
	"net/http"
)

// Kind is the kind of a principal.
type Kind string

// The kinds of principals.
const (
	Human          Kind = "human"
	ServiceAccount Kind = "service_account"
)

// Principal is the authenticated caller of a request.
type Principal struct {
	// ID is the principal's UUIDv7.
	ID string
	// Kind tells a person from a service account.
	Kind Kind
	// Name is the principal's display name.
	Name string
	// Roles are the roles bound to the principal.
	Roles []string
}

// Authenticator identifies the principal of a request from its credentials.
type Authenticator interface {
	// Authenticate returns the principal, or nil when the request carries no
	// credential. A credential that is not accepted is an error.
	Authenticate(r *http.Request) (*Principal, error)
}

// Authorizer decides whether a principal may call an operation of the API,
// named by its OpenAPI operation ID.
type Authorizer interface {
	// Authorize returns nil when the principal may call the operation, and
	// an error otherwise.
	Authorize(ctx context.Context, p *Principal, operation string) error
}

// ErrDenied is the error of an Authorizer that refuses an operation.
var ErrDenied = errors.New("the principal may not call this operation")

// Unauthenticated accepts no credential: every request is anonymous. It
// stands in for the authentication of plan P1-03.
type Unauthenticated struct{}

// Authenticate implements Authenticator.
func (Unauthenticated) Authenticate(*http.Request) (*Principal, error) { return nil, nil }

// DenyAll refuses every operation. It stands in for the authorization engine
// of plan P1-03.
type DenyAll struct{}

// Authorize implements Authorizer.
func (DenyAll) Authorize(context.Context, *Principal, string) error { return ErrDenied }

type principalKey struct{}

// WithPrincipal returns a context that carries the principal of a request.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal that ctx carries, or nil for an
// anonymous request.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}
