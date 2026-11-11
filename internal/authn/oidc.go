package authn

import (
	"bytes"
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
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/authz"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
	"github.com/J466Y/WhiteTower/internal/platform/tlsclient"
)

const (
	// stateCookieName is the name of the cookie that holds a sign-in's state,
	// Secure and with the __Host- prefix, as the session cookie is.
	stateCookieName     = "__Host-wt_oidc"
	stateCookieLifetime = 10 * time.Minute

	// MinStateKeyBytes is the shortest key that may sign the state of a
	// sign-in: the size of an HMAC-SHA256 output, below which RFC 2104
	// (section 3) says that a key weakens the MAC.
	MinStateKeyBytes = 32

	// SignInRetryAfter is how long the sign-in routes and the token exchange
	// ask a client to wait while the identity provider is not discovered.
	SignInRetryAfter = 10 * time.Second

	// providerTimeout bounds each call to the identity provider, unless the
	// options set another timeout.
	providerTimeout = 10 * time.Second

	// signInRefused answers a sign-in whose ID token names the person
	// otherwise than the server expects; the log says why.
	signInRefused = "sign-in refused: the identity provider does not name this person as the server expects; ask an administrator"

	// Discovery is retried firstDiscoveryRetry after the first failure, then
	// after twice the delay each time, up to maxDiscoveryRetry.
	firstDiscoveryRetry = time.Second
	maxDiscoveryRetry   = time.Minute
)

// ErrProviderUnavailable is returned while the service has not discovered its
// identity provider, and so cannot verify ID tokens.
var ErrProviderUnavailable = errors.New("the identity provider is not discovered yet")

// ErrNoExternalID is returned for a verified ID token whose external ID
// claim is missing, is not a string, or is no external ID: the sign-in cannot
// tell which principal is the person's, and no other claim stands in for it,
// since a principal found by another claim would be one that SCIM does not
// reach.
var ErrNoExternalID = errors.New("the ID token carries no external ID in its configured claim")

// OIDCOptions holds options for configuring the OpenID Connect backend-for-frontend service.
type OIDCOptions struct {
	Issuer       string
	DiscoveryURL string // The discovery document's base URL, when not the issuer: a back channel.
	// CAFile is a PEM file with the certificate authorities that sign the
	// provider's certificate on the back channel. Empty: the system's.
	CAFile string
	// Timeout bounds each call to the provider: 10 seconds when zero.
	Timeout      time.Duration
	ClientID     string
	CLIClientID  string
	ClientSecret string
	// StateKey signs the state of a sign-in, at least MinStateKeyBytes long.
	// Every replica takes the same key, so that a sign-in may end on another
	// replica than the one it started on, or after a restart (NFR-06).
	StateKey          []byte
	RedirectURL       string
	Scopes            []string
	GroupsClaim       string
	ExternalIDClaim   string // The claim of the person's external ID, which SCIM sends as externalId: sub when empty.
	RoleMapping       map[string]string
	AllowedAlgorithms []string
	Clock             clock.Clock
	Logger            *slog.Logger
	Limiter           *ratelimit.Limiter
	Metrics           *metrics.OIDC
	// SignIns counts the sign-ins through the callback and the CLI's
	// exchange, by result. None: they are logged, and not counted.
	SignIns *metrics.SignIns
	Tokens  *TokenStore
}

type oidcState struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"verifier"`
	ReturnURL    string    `json:"return_url"`
	ExpiresAt    time.Time `json:"exp"`
}

type discoveryClaims struct {
	Issuer             string `json:"issuer"`
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
	client        *http.Client
	discoveryURL  string
	documentURL   string
	principals    *PrincipalStore
	sessions      *SessionStore
	tokens        *TokenStore
	stateKey      []byte
	postLogoutURL string
	logger        *slog.Logger
	signIns       signIns
	// provider is what discovery found, nil until it succeeds. A request
	// reads it once, so that a discovery that ends meanwhile changes nothing
	// halfway through the request.
	provider atomic.Pointer[discovered]
}

// discovered is what the service uses of a discovered identity provider.
type discovered struct {
	oauthConfig   *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	cliVerifier   *oidc.IDTokenVerifier
	endSessionURL string
}

// NewOIDCService returns the service of the configured identity provider. It
// checks the options and reads the CA file, but does not reach the provider:
// Discover does, and Run retries it until it succeeds. Until then, sign-in and
// the token exchange answer that the provider is unavailable, so that a core
// that starts while the provider is down still serves break-glass and the
// machine listener (KIL-08, HUM-06).
func NewOIDCService(opts OIDCOptions, principals *PrincipalStore, sessions *SessionStore) (*OIDCService, error) {
	// Without an issuer, a discovery document without one would pass the
	// issuer check of Discover.
	if opts.Issuer == "" {
		return nil, errors.New("an OIDC issuer is required")
	}
	// After the identity provider ends its session, it sends the browser back
	// to the console's root, on the origin of the redirect URL: the core's.
	redirect, err := url.Parse(opts.RedirectURL)
	if err != nil || redirect.Scheme == "" || redirect.Host == "" {
		return nil, fmt.Errorf("the OIDC redirect URL %q must be an absolute URL", opts.RedirectURL)
	}
	postLogoutURL := (&url.URL{Scheme: redirect.Scheme, Host: redirect.Host, Path: "/"}).String()
	if len(opts.StateKey) < MinStateKeyBytes {
		return nil, fmt.Errorf("the OIDC state key holds %d bytes: want at least %d", len(opts.StateKey), MinStateKeyBytes)
	}
	tlsConfig, err := tlsclient.Config(opts.CAFile)
	if err != nil {
		return nil, fmt.Errorf("the identity provider's CA file: %w", err)
	}

	if opts.Timeout <= 0 {
		opts.Timeout = providerTimeout
	}
	if opts.Clock == nil {
		opts.Clock = clock.System
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.GroupsClaim == "" {
		opts.GroupsClaim = "groups"
	}
	if opts.ExternalIDClaim == "" {
		opts.ExternalIDClaim = "sub"
	}
	if len(opts.Scopes) == 0 {
		opts.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}
	if len(opts.AllowedAlgorithms) == 0 {
		opts.AllowedAlgorithms = []string{oidc.RS256, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256}
	}

	discoveryURL := opts.Issuer
	if opts.DiscoveryURL != "" {
		discoveryURL = opts.DiscoveryURL
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &OIDCService{
		opts: opts,
		// Every call to the provider goes through this client, whose timeout
		// bounds each of them: discovery; the signing keys, which go-oidc
		// fetches with the client of the context that discovered the
		// provider; and the token exchange, which oauth2 takes from its
		// context.
		client:        &http.Client{Transport: transport, Timeout: opts.Timeout},
		discoveryURL:  discoveryURL,
		documentURL:   strings.TrimSuffix(discoveryURL, "/") + "/.well-known/openid-configuration",
		principals:    principals,
		sessions:      sessions,
		tokens:        opts.Tokens,
		stateKey:      bytes.Clone(opts.StateKey),
		postLogoutURL: postLogoutURL,
		logger:        opts.Logger,
		signIns:       signIns{logger: opts.Logger, metrics: opts.SignIns},
	}, nil
}

// ParseStateKey decodes the key that signs the state of a sign-in, as a file
// holds it: in base64, as `openssl rand -base64 32` writes it, at least
// MinStateKeyBytes once decoded. Whitespace, such as the line breaks that
// openssl writes in a longer key, is left out. Its errors never repeat the
// file's content.
func ParseStateKey(text []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		return nil, errors.New("not base64: want a key as openssl rand -base64 32 writes it")
	}
	if len(key) < MinStateKeyBytes {
		return nil, fmt.Errorf("the key holds %d bytes: want at least %d, as openssl rand -base64 32 writes", len(key), MinStateKeyBytes)
	}
	return key, nil
}

// Discover makes one attempt to discover the identity provider: it fetches
// the discovery document and checks that it names the configured issuer.
// Once an attempt succeeds, the service signs people in and exchanges ID
// tokens. Its error names the document's URL, for the operator who reads the
// log.
func (s *OIDCService) Discover(ctx context.Context) error {
	// Discovery runs at the discovery URL when the server reaches the provider
	// at another address than browsers do, and at the issuer otherwise. go-oidc
	// would compare the document's issuer with the URL it fetched the document
	// from. With the issuer URL context, it skips that comparison and verifies
	// ID tokens against the configured issuer, and the check below compares the
	// document's issuer with the configured one, whichever URL served it, so
	// that one tested path decides (ST-16).
	ctx = oidc.InsecureIssuerURLContext(oidc.ClientContext(ctx, s.client), s.opts.Issuer)
	provider, err := oidc.NewProvider(ctx, s.discoveryURL)
	if err != nil {
		return fmt.Errorf("discovering OIDC provider at %s: %w", s.documentURL, err)
	}

	var disc discoveryClaims
	if err := provider.Claims(&disc); err != nil {
		return fmt.Errorf("discovering OIDC provider at %s: %w", s.documentURL, err)
	}
	if disc.Issuer != s.opts.Issuer {
		return fmt.Errorf("discovering OIDC provider at %s: %w", s.documentURL,
			&oidc.IssuerMismatchError{Provided: s.opts.Issuer, Discovered: disc.Issuer})
	}

	// The console sends browsers to the end session endpoint itself, from its
	// own origin. One that it may not use leaves the sign-out the core's own,
	// as before discovery, and never refuses the provider.
	endSession, err := usableEndSession(disc.EndSessionEndpoint, s.opts.Issuer)
	if err != nil {
		s.logger.Warn("not using the identity provider's end session endpoint: a sign-out ends the core's session only",
			"end_session_endpoint", logging.Sanitize(disc.EndSessionEndpoint), "reason", err.Error())
	}

	cliID := s.opts.CLIClientID
	if cliID == "" {
		cliID = "wtctl"
	}
	s.provider.Store(&discovered{
		oauthConfig: &oauth2.Config{
			ClientID:     s.opts.ClientID,
			ClientSecret: s.opts.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  s.opts.RedirectURL,
			Scopes:       s.opts.Scopes,
		},
		verifier: provider.Verifier(&oidc.Config{
			ClientID:             s.opts.ClientID,
			SupportedSigningAlgs: s.opts.AllowedAlgorithms,
			Now:                  s.opts.Clock.Now,
		}),
		cliVerifier: provider.Verifier(&oidc.Config{
			ClientID:             cliID,
			SupportedSigningAlgs: s.opts.AllowedAlgorithms,
			Now:                  s.opts.Clock.Now,
		}),
		endSessionURL: endSession,
	})
	return nil
}

// usableEndSession returns the end session endpoint of a discovery document
// when browsers may be sent there: an absolute URL with a host, whose scheme
// is https, or http when the issuer's is too, as only development allows
// (T-13). A document without one has none. Any other endpoint, such as a
// javascript: or data: URL, a relative one or plain HTTP for an https issuer,
// is an error that says why, and the endpoint is none.
func usableEndSession(endpoint, issuer string) (string, error) {
	if endpoint == "" {
		return "", nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("it is not a URL")
	}
	iss, issErr := url.Parse(issuer)
	switch {
	case u.Host == "":
		return "", errors.New("it is not an absolute URL with a host")
	case u.Scheme == "https":
		return endpoint, nil
	case u.Scheme == "http" && issErr == nil && iss.Scheme == "http":
		return endpoint, nil
	case u.Scheme == "http":
		return "", errors.New("it is plain HTTP, and the issuer is not")
	default:
		return "", errors.New("its scheme is neither https nor http")
	}
}

// Run discovers the identity provider, and retries until an attempt succeeds
// or ctx ends: a second after the first failure, then twice as long after
// each, up to a minute. It retries whatever an attempt returned, a document
// that names another issuer included: a provider that restarts, or that is
// being upgraded, can refuse connections, answer errors or serve a wrong
// document for a while. Each failure is logged, at most once a minute once
// the delay has grown.
func (s *OIDCService) Run(ctx context.Context) {
	for delay := firstDiscoveryRetry; ; delay = min(2*delay, maxDiscoveryRetry) {
		err := s.Discover(ctx)
		if err == nil {
			if s.opts.Metrics != nil {
				s.opts.Metrics.Discovered()
			}
			s.logger.Info("discovered the identity provider: sign-in is available", "issuer", s.opts.Issuer)
			return
		}
		if ctx.Err() != nil {
			return
		}
		// The error can hold what the provider answered.
		s.logger.Warn("sign-in is unavailable: discovering the identity provider failed",
			"error", logging.Sanitize(err.Error()), "retry_in", delay.String())
		timer := s.opts.Clock.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
	}
}

// ServeHTTP handles /auth/login and /auth/callback. LogoutService handles
// /auth/logout, which break-glass needs too, and sends the browser to
// EndSessionURL.
func (s *OIDCService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	provider := s.provider.Load()
	path := strings.TrimPrefix(r.URL.Path, "/auth")
	switch {
	case (path == "/login" || path == "/callback") && provider == nil:
		if path == "/callback" {
			s.signIns.ended("oidc", resultError)
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(SignInRetryAfter.Seconds())))
		http.Error(w, "sign-in is unavailable: the server has not reached the identity provider yet; retry later", http.StatusServiceUnavailable)
	case path == "/login":
		s.handleLogin(w, r, provider)
	case path == "/callback":
		s.handleCallback(w, r, provider)
	default:
		http.NotFound(w, r)
	}
}

// handleLogin initiates the authorization code flow with PKCE, state, and nonce (ST-15, ST-22).
func (s *OIDCService) handleLogin(w http.ResponseWriter, r *http.Request, provider *discovered) {
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

	stateToken, err := generateRandomToken()
	if err != nil {
		s.logger.Error("generating state token", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	nonce, err := generateRandomToken()
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

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(stateCookieLifetime.Seconds()),
	})

	authURL := provider.oauthConfig.AuthCodeURL(
		stateToken,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback validates the authorization code and ID token, provisions the principal,
// resolves effective roles, and issues the session cookie (ST-16). Each
// refusal logs one line, with its reason, and every end of the sign-in is
// counted by its result.
func (s *OIDCService) handleCallback(w http.ResponseWriter, r *http.Request, provider *discovered) {
	ctx := r.Context()
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		s.signIns.refused(ctx, "oidc", refusedInvalidRequest, nil, "error", "no state cookie")
		http.Error(w, "missing OIDC state cookie", http.StatusBadRequest)
		return
	}

	state, err := s.decodeStateCookie(cookie.Value)
	if err != nil {
		s.signIns.refused(ctx, "oidc", refusedInvalidRequest, nil, "error", err)
		http.Error(w, fmt.Sprintf("invalid OIDC state cookie: %v", err), http.StatusBadRequest)
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState == "" || subtle.ConstantTimeCompare([]byte(queryState), []byte(state.State)) != 1 {
		s.signIns.refused(ctx, "oidc", refusedInvalidRequest, nil, "error", "the state is not the sign-in's")
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	if idpErr := r.URL.Query().Get("error"); idpErr != "" {
		desc := r.URL.Query().Get("error_description")
		s.signIns.refused(ctx, "oidc", refusedByProvider, nil, "error", logging.Sanitize(idpErr), "description", logging.Sanitize(desc))
		if desc != "" {
			http.Error(w, fmt.Sprintf("authentication failed: %s (%s)", logging.Sanitize(idpErr), logging.Sanitize(desc)), http.StatusUnauthorized)
		} else {
			http.Error(w, fmt.Sprintf("authentication failed: %s", logging.Sanitize(idpErr)), http.StatusUnauthorized)
		}
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.signIns.refused(ctx, "oidc", refusedInvalidRequest, nil, "error", "no authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := provider.oauthConfig.Exchange(
		// oauth2 takes its HTTP client from the context: the provider's.
		oidc.ClientContext(ctx, s.client),
		code,
		oauth2.SetAuthURLParam("code_verifier", state.CodeVerifier),
	)
	if err != nil {
		// The error can name the provider's back channel, which browsers
		// must not learn: only the log holds it.
		s.logger.Error("exchanging code for token", "error", err)
		s.signIns.ended("oidc", resultError)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.logger.Error("the identity provider's token response holds no ID token")
		s.signIns.ended("oidc", resultError)
		http.Error(w, "missing id_token in token response", http.StatusBadGateway)
		return
	}

	// Security test ST-16: ID tokens with a wrong issuer or audience, an expired one,
	// a replayed nonce or an unexpected algorithm are refused.
	idToken, err := provider.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		// Fetching the signing keys can fail on the back channel too. The
		// error can quote the token's issuer or audience, which whoever made
		// the token chose.
		s.signIns.refused(ctx, "oidc", refusedInvalidToken, nil, "error", logging.Sanitize(err.Error()))
		http.Error(w, "id token verification failed", http.StatusBadRequest)
		return
	}

	if idToken.Nonce != state.Nonce {
		s.signIns.refused(ctx, "oidc", refusedInvalidToken, nil, "error", "the ID token's nonce is not the sign-in's")
		http.Error(w, "id token nonce mismatch", http.StatusBadRequest)
		return
	}

	id, err := s.identityOf(idToken)
	if errors.Is(err, ErrNoExternalID) {
		s.refuseWithoutExternalID(ctx, "oidc")
		http.Error(w, signInRefused, http.StatusForbidden)
		return
	}
	if err != nil {
		s.signIns.refused(ctx, "oidc", refusedInvalidToken, nil, "error", err)
		http.Error(w, "reading id token claims failed", http.StatusBadRequest)
		return
	}

	// One transaction signs the person in: the principal, its events and the
	// session. Security test ST-14: the session that the browser held is
	// revoked with the new one's creation.
	var session *Session
	_, err = s.principals.SignIn(ctx, "oidc", id, func(ctx context.Context, tx *db.Tx, p *Principal) error {
		localBindings, err := authndb.New(tx).ListActiveRoleBindings(ctx, p.ID)
		if err != nil {
			return fmt.Errorf("fetching local role bindings: %w", err)
		}
		effectiveRoles := ResolveEffectiveRoles(id.Groups, s.opts.RoleMapping, localBindings)
		session, err = s.sessions.ReplaceTx(ctx, tx, heldSessions(r), p.ID, "oidc", effectiveRoles, 0)
		return err
	})
	switch {
	case errors.Is(err, ErrPrincipalInactive):
		s.signIns.refused(ctx, "oidc", refusedInactive, refusedPrincipalID(err))
		http.Error(w, "account is deactivated", http.StatusForbidden)
		return
	case errors.Is(err, ErrExternalIDConflict):
		s.refuseExternalIDConflict(ctx, "oidc", err)
		http.Error(w, signInRefused, http.StatusForbidden)
		return
	case err != nil:
		s.logger.Error("signing in", "error", err)
		s.signIns.ended("oidc", resultError)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.signIns.ended("oidc", resultSuccess)

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, s.sessions.Cookie(session.Token))
	http.Redirect(w, r, state.ReturnURL, http.StatusFound)
}

// EndSessionURL returns where a browser goes once signed out of the core:
// the identity provider's end session endpoint, which ends the person's
// session there too, then sends the browser back to the console (plan P1-03,
// step 1). Before discovery the endpoint is unknown, and a provider may have
// none: the sign-out is then the core's only, and EndSessionURL is "".
func (s *OIDCService) EndSessionURL() string {
	provider := s.provider.Load()
	if provider == nil || provider.endSessionURL == "" {
		return ""
	}
	u, err := url.Parse(provider.endSessionURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	// A provider needs the ID token or the client to accept a post-logout
	// redirect: Keycloak refuses one with neither. The core keeps no ID
	// token, so it names its client, and the provider asks the person to
	// confirm before it ends its session.
	q.Set("client_id", s.opts.ClientID)
	q.Set("post_logout_redirect_uri", s.postLogoutURL)
	u.RawQuery = q.Encode()
	return u.String()
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

// ExchangeIDToken validates an ID token obtained by the CLI, provisions the principal,
// resolves effective roles, and returns a 12-hour API token (plan P1-03, step 7; HUM-06, API-04).
// Each refusal logs one line, with its reason, and every end of the exchange
// is counted by its result.
func (s *OIDCService) ExchangeIDToken(ctx context.Context, rawIDToken string) (*CreatedToken, error) {
	if s.tokens == nil {
		s.signIns.ended("token_exchange", resultError)
		return nil, errors.New("token store not configured")
	}
	provider := s.provider.Load()
	if provider == nil {
		s.signIns.ended("token_exchange", resultError)
		return nil, ErrProviderUnavailable
	}

	rawIDToken = strings.TrimSpace(rawIDToken)
	if rawIDToken == "" {
		s.signIns.refused(ctx, "token_exchange", refusedInvalidRequest, nil, "error", "no ID token")
		return nil, fmt.Errorf("%w: empty id token", ErrInvalidToken)
	}

	// Only an ID token issued for the CLI's client verifies. One issued for
	// the console's confidential client is refused: the exchange does not
	// check the nonce that the callback checks, so such a token, replayed
	// here, would mint an API token (ST-16). The verifier fetches the signing
	// keys with the provider's client.
	idToken, err := provider.cliVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		// Fetching the signing keys can fail on the provider's back channel,
		// whose address no client may learn: only the log holds the cause,
		// sanitized, as it can quote the token's claims.
		s.signIns.refused(ctx, "token_exchange", refusedInvalidToken, nil, "error", logging.Sanitize(err.Error()))
		return nil, fmt.Errorf("%w: the ID token does not verify", ErrInvalidToken)
	}

	id, err := s.identityOf(idToken)
	if errors.Is(err, ErrNoExternalID) {
		s.refuseWithoutExternalID(ctx, "token_exchange")
	} else if err != nil {
		s.signIns.refused(ctx, "token_exchange", refusedInvalidToken, nil, "error", err)
	}
	if err != nil {
		return nil, fmt.Errorf("reading id token claims: %w", err)
	}

	// One transaction signs the person in: the principal, its events and the
	// token, whose whitetower.token.created.v1 records the sign-in.
	var created *CreatedToken
	_, err = s.principals.SignIn(ctx, "token_exchange", id, func(ctx context.Context, tx *db.Tx, p *Principal) error {
		localBindings, err := authndb.New(tx).ListActiveRoleBindings(ctx, p.ID)
		if err != nil {
			return fmt.Errorf("fetching role bindings: %w", err)
		}
		effectiveRoles := ResolveEffectiveRoles(id.Groups, s.opts.RoleMapping, localBindings)
		actor := auth.Principal{
			ID:    p.ID.String(),
			Kind:  auth.Human,
			Name:  p.DisplayName,
			Roles: effectiveRoles,
		}
		// The token's scopes are the permissions of the person's roles that
		// a token may hold (HUM-10). It records the hash of the sign-in
		// configuration that accepted the ID token: the token store's, which
		// main builds from the settings that it gives this service (ST-14).
		scopes := slices.DeleteFunc(authz.PermissionsList(effectiveRoles), func(scope string) bool {
			return !authz.IsTokenScope(authz.Permission(scope))
		})
		created, err = s.tokens.createWithLifetimeTx(ctx, tx, p.ID, "wtctl", scopes, 12*time.Hour, actor,
			s.tokens.signInConfiguration)
		return err
	})
	switch {
	case errors.Is(err, ErrPrincipalInactive):
		s.signIns.refused(ctx, "token_exchange", refusedInactive, refusedPrincipalID(err))
	case errors.Is(err, ErrExternalIDConflict):
		s.refuseExternalIDConflict(ctx, "token_exchange", err)
	case err != nil:
		// The API logs what it answers as an internal error.
		s.signIns.ended("token_exchange", resultError)
	}
	if err != nil {
		return nil, err
	}
	s.signIns.ended("token_exchange", resultSuccess)
	return created, nil
}

// refuseWithoutExternalID logs and counts a sign-in through method whose ID
// token carries no external ID in its configured claim. The log names the
// claim, never its value.
func (s *OIDCService) refuseWithoutExternalID(ctx context.Context, method string) {
	s.signIns.refused(ctx, method, refusedNoExternalID, nil, "claim", s.opts.ExternalIDClaim)
}

// refuseExternalIDConflict logs and counts a sign-in through method that err
// refuses because the principal with its issuer and subject holds another
// external ID, as after the configured claim changed. The log names the
// principal and the claim, and no value of the ID token.
func (s *OIDCService) refuseExternalIDConflict(ctx context.Context, method string, err error) {
	s.signIns.refused(ctx, method, refusedExternalIDConflict, refusedPrincipalID(err), "claim", s.opts.ExternalIDClaim)
}

// identityOf returns what a verified ID token says of the person: the
// configured issuer, the subject, the external ID of the external ID claim, a
// name, the email address and the groups of the groups claim. The name falls
// back to the preferred username, the email address and the subject, in that
// order. An external ID claim that is missing, is not a string or is no
// external ID is ErrNoExternalID.
func (s *OIDCService) identityOf(idToken *oidc.IDToken) (Identity, error) {
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, err
	}
	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		return Identity{}, err
	}

	externalID, ok := rawClaims[s.opts.ExternalIDClaim].(string)
	if !ok || checkExternalID(externalID) != nil {
		return Identity{}, ErrNoExternalID
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

	var email *string
	if claims.Email != "" {
		email = &claims.Email
	}
	return Identity{
		Issuer:      s.opts.Issuer,
		Subject:     claims.Subject,
		ExternalID:  externalID,
		DisplayName: displayName,
		Email:       email,
		Groups:      groups,
	}, nil
}
