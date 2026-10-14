// Package authn implements human principal identity management, session lifecycles,
// session fixation prevention, and CSRF protection (plan P1-03, steps 2 and 3; ADR-0009).
package authn

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

// Authenticator validates session cookies on incoming HTTP requests and
// attaches the authenticated principal and session to the request context.
type Authenticator struct {
	sessions   *SessionStore
	principals *PrincipalStore
}

var _ auth.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(sessions *SessionStore, principals *PrincipalStore) *Authenticator {
	return &Authenticator{
		sessions:   sessions,
		principals: principals,
	}
}

// Authenticate reads the session cookie and returns the authenticated Principal.
func (a *Authenticator) Authenticate(r *http.Request) (*auth.Principal, error) {
	cookie, err := r.Cookie(CookieNameSecure)
	if errors.Is(err, http.ErrNoCookie) {
		cookie, err = r.Cookie(CookieNameInsecure)
	}
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading session cookie: %w", err)
	}

	session, err := a.sessions.Get(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}

	p, err := a.principals.GetByID(r.Context(), session.PrincipalID)
	if err != nil {
		return nil, err
	}

	// Mutate request pointer so inner middleware can access session and CSRF token.
	*r = *r.WithContext(ContextWithSession(r.Context(), session))

	return &auth.Principal{
		ID:    p.ID.String(),
		Kind:  auth.Kind(p.Kind),
		Name:  p.DisplayName,
		Roles: append([]string{}, session.Roles...),
	}, nil
}
