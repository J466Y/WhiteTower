// Package authn implements human principal identity management, session lifecycles,
// session fixation prevention, and CSRF protection (plan P1-03, steps 2 and 3; ADR-0009).
package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/J466Y/WhiteTower/internal/platform/auth"
)

// Authenticator validates session cookies and API tokens on incoming HTTP requests and
// attaches the authenticated principal and session to the request context.
type Authenticator struct {
	sessions    *SessionStore
	principals  *PrincipalStore
	tokens      *TokenStore
	roleMapping map[string]string
}

var _ auth.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(
	sessions *SessionStore,
	principals *PrincipalStore,
	tokens *TokenStore,
	roleMapping map[string]string,
) *Authenticator {
	return &Authenticator{
		sessions:    sessions,
		principals:  principals,
		tokens:      tokens,
		roleMapping: roleMapping,
	}
}

// Authenticate reads the Bearer token or session cookie and returns the authenticated Principal.
func (a *Authenticator) Authenticate(r *http.Request) (*auth.Principal, error) {
	// 1. Check Bearer token (API tokens for automation and CLI)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		rawToken := strings.TrimSpace(authHeader[7:])
		if a.tokens == nil {
			return nil, errors.New("api tokens not configured")
		}

		token, p, err := a.tokens.GetByToken(r.Context(), rawToken)
		if err != nil {
			return nil, err
		}

		var roles []string
		dbRoles, err := a.principals.GetRoles(r.Context(), p.ID)
		if err != nil {
			return nil, fmt.Errorf("resolving principal roles: %w", err)
		}
		if p.Kind == "human" {
			roles = ResolveEffectiveRoles(p.IDPGroups, a.roleMapping, dbRoles)
		} else {
			roles, err = a.serviceAccountRoles(r.Context(), p, dbRoles)
			if err != nil {
				return nil, err
			}
		}

		return &auth.Principal{
			ID:     p.ID.String(),
			Kind:   auth.Kind(p.Kind),
			Name:   p.DisplayName,
			Roles:  roles,
			Scopes: append([]string{}, token.Scopes...),
		}, nil
	}

	// 2. Fall back to cookie session
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

	isBreakglass := session.Method == "breakglass"
	var scopes []string
	if isBreakglass {
		scopes = append([]string{}, BreakglassScopes...)
	}

	return &auth.Principal{
		ID:           p.ID.String(),
		Kind:         auth.Kind(p.Kind),
		Name:         p.DisplayName,
		Roles:        append([]string{}, session.Roles...),
		Scopes:       scopes,
		IsBreakglass: isBreakglass,
	}, nil
}

// serviceAccountRoles returns the roles that a service account acts with: those
// bound to it that its responsible human holds now. A service account never
// does more than the person it acts for, and nothing once that person is
// inactive, even with a token issued before (plan P1-03, step 6).
func (a *Authenticator) serviceAccountRoles(ctx context.Context, sa *Principal, bound []string) ([]string, error) {
	if sa.ResponsiblePrincipalID == nil {
		return nil, ErrResponsibleNotHuman
	}
	responsible, err := a.principals.GetByID(ctx, *sa.ResponsiblePrincipalID)
	if err != nil {
		return nil, fmt.Errorf("reading the service account's responsible principal: %w", err)
	}
	if responsible.Kind != "human" {
		return nil, ErrResponsibleNotHuman
	}
	if responsible.Status != "active" {
		return nil, ErrPrincipalInactive
	}
	bindings, err := a.principals.GetRoles(ctx, responsible.ID)
	if err != nil {
		return nil, fmt.Errorf("resolving the responsible principal's roles: %w", err)
	}
	// Sorted, as a human's effective roles are.
	held := ResolveEffectiveRoles(responsible.IDPGroups, a.roleMapping, bindings)
	roles := []string{}
	for _, role := range held {
		if slices.Contains(bound, role) {
			roles = append(roles, role)
		}
	}
	return roles, nil
}
