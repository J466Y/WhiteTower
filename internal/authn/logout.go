package authn

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// LogoutOptions configures the sign-out of a browser.
type LogoutOptions struct {
	// EndSession returns where the browser goes once signed out of the
	// core: the identity provider's end session endpoint, or "" while it is
	// not known (OIDCService.EndSessionURL). Nil without OIDC sign-in. The
	// browser goes to the console's root otherwise, and after a break-glass
	// session.
	EndSession func() string
	Logger     *slog.Logger
}

// LogoutService signs a browser out of the core at /auth/logout, whichever
// way it signed in: through the identity provider or break-glass, so that a
// break-glass session can end before its hour (ST-14). Only a POST that
// carries the CSRF token of the session, as the console sends it, signs out,
// so that another site cannot sign a person out (ADR-0009).
type LogoutService struct {
	sessions *SessionStore
	opts     LogoutOptions
	logger   *slog.Logger
}

// logoutAnswer is the answer to a sign-out. The console signs out with fetch,
// since only fetch sends the CSRF header, and fetch cannot follow a redirect
// to the identity provider's origin: the console navigates to RedirectURL
// itself.
type logoutAnswer struct {
	RedirectURL string `json:"redirect_url"`
}

// NewLogoutService returns the sign-out of the sessions of sessions.
func NewLogoutService(sessions *SessionStore, opts LogoutOptions) *LogoutService {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &LogoutService{sessions: sessions, opts: opts, logger: opts.Logger}
}

// ServeHTTP handles /auth/logout. A POST whose session cookie names an active
// session needs the session's CSRF token in the X-CSRF-Token header; it then
// revokes the session, records the sign-out, and clears the cookie. A cookie
// of no active session is cleared, since there is nothing to protect. A
// request without the cookie clears nothing: a cross-site request never
// carries it, as it is SameSite=Lax, and clearing it would sign the browser
// out. Every sign-out answers where the browser goes next.
func (s *LogoutService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// A link, an image or a prefetch makes a GET, which another site
		// can make too. Redirecting it to the console would leave a person
		// who opened an old link believing that they had signed out.
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a GET signs nobody out: sign out from the console", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	endSession := s.opts.EndSession
	if cookie, err := r.Cookie(CookieName); err == nil && cookie.Value != "" {
		session, err := s.sessions.Get(ctx, cookie.Value)
		switch {
		case err == nil:
			if !s.sessions.ValidateRequestCSRF(r.WithContext(ContextWithSession(ctx, session))) {
				http.Error(w, "the request does not carry the session's CSRF token", http.StatusForbidden)
				return
			}
			// A break-glass session was never signed in at the identity
			// provider, which may well be down.
			if session.Method == "breakglass" {
				endSession = nil
			}
			// A revocation that fails still clears the cookie, so that the
			// browser is signed out.
			if err := s.sessions.SignOut(ctx, cookie.Value); err != nil {
				s.logger.Error("signing out: revoking the session failed", "error", err)
			}
		case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionRevoked),
			errors.Is(err, ErrSessionExpired), errors.Is(err, ErrPrincipalInactive):
			// No active session: nothing to revoke, and nothing that a forged
			// request could end.
		default:
			// Without the session, the CSRF token cannot be checked.
			s.logger.Error("signing out: reading the session failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, s.sessions.ClearCookie())
	}

	next := "/"
	if endSession != nil {
		if u := endSession(); u != "" {
			next = u
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logoutAnswer{RedirectURL: next})
}
