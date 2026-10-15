package authn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

const (
	stateCookieNameSecure   = "__Host-wt_oidc"
	stateCookieNameInsecure = "wt_oidc"
	stateCookieLifetime     = 10 * time.Minute
)

// OIDCOptions holds options for configuring the OpenID Connect backend-for-frontend service.
type OIDCOptions struct {
	Issuer            string
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	Scopes            []string
	GroupsClaim       string
	RoleMapping       map[string]string
	AllowedAlgorithms []string
	SecureCookies     bool
	Clock             clock.Clock
	Logger            *slog.Logger
	Limiter           *ratelimit.Limiter
	HTTPClient        *http.Client
}

type oidcState struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"verifier"`
	ReturnURL    string    `json:"return_url"`
	ExpiresAt    time.Time `json:"exp"`
}

type discoveryClaims struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

type idTokenClaims struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
}

// OIDCService manages the OpenID Connect authorization code flow with PKCE,
// server-side session generation, and RP-initiated logout (plan P1-03, step 1; ADR-0009).
type OIDCService struct {
	opts          OIDCOptions
	provider      *oidc.Provider
	oauthConfig   *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	database      *db.DB
	principals    *PrincipalStore
	sessions      *SessionStore
	stateKey      []byte
	endSessionURL string
	logger        *slog.Logger
}

// NewOIDCService initializes an OIDCService against the configured OpenID Connect provider.
func NewOIDCService(ctx context.Context, opts OIDCOptions, database *db.DB, principals *PrincipalStore, sessions *SessionStore) (*OIDCService, error) {
	if opts.Clock == nil {
		opts.Clock = clock.System
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.GroupsClaim == "" {
		opts.GroupsClaim = "groups"
	}
	if len(opts.Scopes) == 0 {
		opts.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}
	if len(opts.AllowedAlgorithms) == 0 {
		opts.AllowedAlgorithms = []string{oidc.RS256, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256}
	}

	pCtx := ctx
	if opts.HTTPClient != nil {
		pCtx = oidc.ClientContext(ctx, opts.HTTPClient)
	}

	provider, err := oidc.NewProvider(pCtx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering OIDC provider at %s: %w", opts.Issuer, err)
	}

	var disc discoveryClaims
	_ = provider.Claims(&disc)

	verifier := provider.Verifier(&oidc.Config{
		ClientID:             opts.ClientID,
		SupportedSigningAlgs: opts.AllowedAlgorithms,
		Now:                  opts.Clock.Now,
	})

	oauthConfig := &oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  opts.RedirectURL,
		Scopes:       opts.Scopes,
	}

	stateKey := make([]byte, 32)
	if _, err := rand.Read(stateKey); err != nil {
		return nil, fmt.Errorf("generating oidc state key: %w", err)
	}

	return &OIDCService{
		opts:          opts,
		provider:      provider,
		oauthConfig:   oauthConfig,
		verifier:      verifier,
		database:      database,
		principals:    principals,
		sessions:      sessions,
		stateKey:      stateKey,
		endSessionURL: disc.EndSessionEndpoint,
		logger:        opts.Logger,
	}, nil
}

// ServeHTTP handles /auth/* routes: /auth/login, /auth/callback, and /auth/logout.
func (s *OIDCService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/auth")
	switch path {
	case "/login":
		s.handleLogin(w, r)
	case "/callback":
		s.handleCallback(w, r)
	case "/logout":
		s.handleLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleLogin initiates the authorization code flow with PKCE, state, and nonce (ST-15, ST-22).
func (s *OIDCService) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Security test ST-22: Login attempts are rate-limited.
	if s.opts.Limiter != nil {
		ip := clientIP(r)
		if ok, wait := s.opts.Limiter.Allow(ip, s.opts.Clock.Now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+1)))
			http.Error(w, "too many login attempts; slow down and retry", http.StatusTooManyRequests)
			return
		}
	}

	rawReturnURL := r.URL.Query().Get("return_url")
	if rawReturnURL == "" {
		rawReturnURL = r.URL.Query().Get("rd")
	}

	// Security test ST-15: Return URLs outside the console's own paths are refused.
	returnURL, err := ValidateReturnURL(rawReturnURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid return URL: %v", err), http.StatusBadRequest)
		return
	}

	stateToken, err := generateRandomToken(32)
	if err != nil {
		s.logger.Error("generating state token", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	nonce, err := generateRandomToken(32)
	if err != nil {
		s.logger.Error("generating nonce", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		s.logger.Error("generating pkce verifier", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	now := s.opts.Clock.Now()
	state := oidcState{
		State:        stateToken,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		ReturnURL:    returnURL,
		ExpiresAt:    now.Add(stateCookieLifetime),
	}

	cookieValue, err := s.encodeStateCookie(state)
	if err != nil {
		s.logger.Error("encoding state cookie", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	cookieName := stateCookieNameSecure
	if !s.opts.SecureCookies {
		cookieName = stateCookieNameInsecure
	}
	//nolint:gosec // G124: secure flag is dynamic to support non-TLS development
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.opts.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(stateCookieLifetime.Seconds()),
	})

	authURL := s.oauthConfig.AuthCodeURL(
		stateToken,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback validates the authorization code and ID token, provisions the principal,
// resolves effective roles, and issues the session cookie (ST-16).
func (s *OIDCService) handleCallback(w http.ResponseWriter, r *http.Request) {
	cookieName := stateCookieNameSecure
	if !s.opts.SecureCookies {
		cookieName = stateCookieNameInsecure
	}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "missing OIDC state cookie", http.StatusBadRequest)
		return
	}

	state, err := s.decodeStateCookie(cookie.Value)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid OIDC state cookie: %v", err), http.StatusBadRequest)
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(state.State)) != 1 {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	if idpErr := r.URL.Query().Get("error"); idpErr != "" {
		desc := r.URL.Query().Get("error_description")
		s.logger.Warn("IdP returned authentication error", "error", logging.Sanitize(idpErr), "description", logging.Sanitize(desc))
		if desc != "" {
			http.Error(w, fmt.Sprintf("authentication failed: %s (%s)", logging.Sanitize(idpErr), logging.Sanitize(desc)), http.StatusUnauthorized)
		} else {
			http.Error(w, fmt.Sprintf("authentication failed: %s", logging.Sanitize(idpErr)), http.StatusUnauthorized)
		}
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if s.opts.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, s.opts.HTTPClient)
	}

	token, err := s.oauthConfig.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", state.CodeVerifier),
	)
	if err != nil {
		s.logger.Error("exchanging code for token", "error", err)
		http.Error(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "missing id_token in token response", http.StatusBadGateway)
		return
	}

	// Security test ST-16: ID tokens with a wrong issuer or audience, an expired one,
	// a replayed nonce or an unexpected algorithm are refused.
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.logger.Warn("verifying id_token failed", "error", err)
		http.Error(w, fmt.Sprintf("id token verification failed: %v", err), http.StatusBadRequest)
		return
	}

	if idToken.Nonce != state.Nonce {
		s.logger.Warn("nonce mismatch", "expected", state.Nonce, "actual", logging.Sanitize(idToken.Nonce))
		http.Error(w, "id token nonce mismatch", http.StatusBadRequest)
		return
	}

	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "reading id token claims failed", http.StatusBadRequest)
		return
	}

	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		http.Error(w, "reading raw id token claims failed", http.StatusBadRequest)
		return
	}

	var groups []string
	if rawGroups, ok := rawClaims[s.opts.GroupsClaim]; ok {
		switch g := rawGroups.(type) {
		case []any:
			for _, item := range g {
				if str, ok := item.(string); ok {
					groups = append(groups, str)
				}
			}
		case []string:
			groups = append(groups, g...)
		}
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = claims.PreferredUsername
	}
	if displayName == "" {
		displayName = claims.Email
	}
	if displayName == "" {
		displayName = claims.Subject
	}

	var emailPtr *string
	if claims.Email != "" {
		emailPtr = &claims.Email
	}

	principal, err := s.principals.UpsertHuman(ctx, s.opts.Issuer, claims.Subject, displayName, emailPtr, groups)
	if err != nil {
		s.logger.Error("upserting principal", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if principal.Status != "active" {
		http.Error(w, "account is deactivated", http.StatusForbidden)
		return
	}

	var localBindings []string
	if s.database != nil {
		q := authndb.New(s.database)
		var err error
		localBindings, err = q.ListActiveRoleBindings(ctx, principal.ID)
		if err != nil {
			s.logger.Error("fetching local role bindings", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	effectiveRoles := ResolveEffectiveRoles(groups, s.opts.RoleMapping, localBindings)

	session, err := s.sessions.Create(ctx, principal.ID, "oidc", effectiveRoles)
	if err != nil {
		s.logger.Error("creating session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	//nolint:gosec // G124: secure flag is dynamic to support non-TLS development
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.opts.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, s.sessions.Cookie(session.Token, s.opts.SecureCookies))
	http.Redirect(w, r, state.ReturnURL, http.StatusFound)
}

// handleLogout clears the session in PostgreSQL and the browser cookie, then
// redirects to the IdP's end session endpoint if available (plan P1-03, step 1).
func (s *OIDCService) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookieName := CookieNameSecure
	if !s.opts.SecureCookies {
		cookieName = CookieNameInsecure
	}

	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
		_ = s.sessions.Revoke(r.Context(), cookie.Value)
	}

	http.SetCookie(w, s.sessions.ClearCookie(s.opts.SecureCookies))

	if s.endSessionURL != "" {
		postLogout := s.opts.RedirectURL
		if u, err := url.Parse(s.endSessionURL); err == nil {
			q := u.Query()
			q.Set("post_logout_redirect_uri", postLogout)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *OIDCService) encodeStateCookie(state oidcState) (string, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.stateKey)
	mac.Write(data)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *OIDCService) decodeStateCookie(raw string) (*oidcState, error) {
	payload, sig, ok := strings.Cut(raw, ".")
	if !ok {
		return nil, errors.New("malformed state cookie")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("invalid base64 payload")
	}
	expectedSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, errors.New("invalid base64 signature")
	}
	mac := hmac.New(sha256.New, s.stateKey)
	mac.Write(data)
	if subtle.ConstantTimeCompare(mac.Sum(nil), expectedSig) != 1 {
		return nil, errors.New("state signature verification failed")
	}
	var state oidcState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, errors.New("unmarshaling state cookie failed")
	}
	if s.opts.Clock.Now().After(state.ExpiresAt) {
		return nil, errors.New("state cookie expired")
	}
	return &state, nil
}

// ValidateReturnURL verifies that target is a safe relative path within the console (ST-15).
func ValidateReturnURL(target string) (string, error) {
	if target == "" {
		return "/", nil
	}
	if !strings.HasPrefix(target, "/") {
		return "", errors.New("return URL must be a relative path starting with /")
	}
	if strings.HasPrefix(target, "//") {
		return "", errors.New("protocol-relative return URLs are forbidden")
	}
	if strings.Contains(target, "\\") {
		return "", errors.New("return URL cannot contain backslashes")
	}
	if strings.ContainsAny(target, "\r\n\t ") {
		return "", errors.New("return URL contains invalid characters")
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing return URL: %w", err)
	}
	if u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "", errors.New("return URL must not contain host or scheme")
	}
	return target, nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
