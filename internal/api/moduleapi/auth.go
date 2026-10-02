package moduleapi

import (
	"context"
	"errors"
	"net/http"
)

// Caller is the authenticated caller of the module API: an enforcement point
// acting as its agent, or an instance of another module (contracts, section
// 4.2).
type Caller struct {
	// Identity is the caller's SPIFFE ID:
	// spiffe://<trust domain>/agent/<agent ID> or .../module/<module ID>.
	Identity string
}

// Authenticator verifies the access token that every call carries in its
// Authorization header. Plan P1-05 issues and verifies the tokens; P1-07 adds
// the caller's scope and ends a Watch stream when its token expires (CORE-1).
type Authenticator interface {
	// Authenticate returns the caller, or an error when the call carries no
	// token, or one that is not accepted.
	Authenticate(ctx context.Context, header http.Header) (*Caller, error)
}

// NoTokens accepts no token, since the core issues none until plan P1-05:
// every call is refused as unauthenticated.
type NoTokens struct{}

// Authenticate implements Authenticator.
func (NoTokens) Authenticate(context.Context, http.Header) (*Caller, error) {
	return nil, errors.New("the core issues no access tokens yet")
}

type callerKey struct{}

// CallerFrom returns the caller of the call that ctx belongs to.
func CallerFrom(ctx context.Context) *Caller {
	c, _ := ctx.Value(callerKey{}).(*Caller)
	return c
}
