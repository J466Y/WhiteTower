package authn

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

const (
	// CookieName is the session cookie's name. Its __Host- prefix makes
	// browsers keep the cookie only when it is Secure, for the core's host
	// alone and the path /, so that neither another host of the domain nor a
	// plain HTTP page can set it (ADR-0009). The console is served over HTTPS
	// only, self-signed certificate included, and browsers treat
	// http://localhost, where the Vite development server runs, as secure:
	// the cookie is always Secure.
	CookieName = "__Host-wt_session"

	// unprefixedCookieName is the session cookie's name without the prefix,
	// which the core gave it when development settings turned Secure off.
	// The core never authenticates with it, but a sign-in revokes the session
	// it names, as one that an older version set or another host planted.
	unprefixedCookieName = "wt_session"

	csrfHMACKey = "whitetower-csrf-token-v1"

	// signInConfigurationForm names the canonical form of a sign-in
	// configuration, which the configuration's hash starts with: a later form
	// would hash every configuration apart from this one's, so that the
	// sessions of this form are refused rather than misread, as are those of
	// the former form, whitetower-role-mapping-v1, which hashed the role
	// mapping alone.
	signInConfigurationForm = "whitetower-sign-in-configuration-v1"

	// cliSignInConfigurationForm names the canonical form of the sign-in
	// configuration with which the CLI's exchange accepts ID tokens, whose
	// hash its API tokens record: the sessions' form with the CLI's client
	// ID. Its own name keeps the two hashes apart even when both clients are
	// one, so that neither ever passes for the other.
	cliSignInConfigurationForm = "whitetower-cli-sign-in-configuration-v1"
)

var (
	// ErrSessionNotFound is returned when a session token does not match any record.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionRevoked is returned when a session has been revoked.
	ErrSessionRevoked = errors.New("session is revoked")

	// ErrSessionExpired is returned when a session has passed its idle or
	// absolute lifetime, or when another sign-in configuration than the
	// store's created it (ST-14).
	ErrSessionExpired = errors.New("session is expired")

	// ErrPrincipalInactive is returned when a session's principal has been deactivated.
	ErrPrincipalInactive = errors.New("principal is inactive")

	// ErrInvalidCSRF is returned when a CSRF token does not match the session's CSRF token hash.
	ErrInvalidCSRF = errors.New("invalid csrf token")
)

// Session represents an active authenticated session.
type Session struct {
	Token             string
	IDHash            []byte
	PrincipalID       uuid.UUID
	Method            string
	Roles             []string
	CSRFToken         string
	CSRFTokenHash     []byte
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}

// SessionOptions configures sessions: their lifetimes, and the sign-in
// configuration that creates them.
type SessionOptions struct {
	IdleTimeout      time.Duration
	AbsoluteLifetime time.Duration
	// SignInConfiguration is the configuration with which the OIDC service
	// accepts ID tokens, finds the person and resolves the roles of the
	// sessions that the server creates. A session records its hash, of every
	// setting but the CLI's client ID, and Get refuses a session that another
	// configuration created, as after a change of one of those settings and a
	// restart, so that no session outlives the configuration that created it
	// (ST-14). Break-glass sessions, whose roles come from none of its
	// settings, are exempt.
	SignInConfiguration SignInConfiguration
}

// SignInConfiguration holds the settings of auth.oidc that decide which ID
// tokens the server accepts, which person a sign-in is and what roles it
// gives. A session records their hash with ClientID, the console's client,
// and an API token of the CLI's exchange with CLIClientID, the CLI's, so that
// a change of either client ends what it signed in and nothing else. The
// settings of transport and routine, such as the discovery URL, the CA file,
// the client secret, the state key, the redirect URL and the scopes, are not
// among them: rotating them must sign no one out.
type SignInConfiguration struct {
	// Issuer is auth.oidc.issuer, the identity provider whose ID tokens the
	// server accepts: empty when OIDC is off, and only break-glass sessions
	// are created.
	Issuer string
	// ClientID is auth.oidc.client_id, the audience of the ID tokens of the
	// console's sign-ins.
	ClientID string
	// CLIClientID is auth.oidc.cli_client_id, the client of the ID tokens that
	// the CLI exchanges for API tokens.
	CLIClientID string
	// AllowedAlgorithms is auth.oidc.allowed_algorithms, the algorithms that
	// may sign them. The verifier reads them as a set.
	AllowedAlgorithms []string
	// ExternalIDClaim is auth.oidc.external_id_claim, the claim that says
	// which person a sign-in is.
	ExternalIDClaim string
	// GroupsClaim is auth.oidc.groups_claim, the claim of the person's
	// groups.
	GroupsClaim string
	// RoleMapping is auth.oidc.role_mapping, which maps those groups to
	// roles.
	RoleMapping map[string]string
}

// SessionStore handles session persistence in PostgreSQL.
type SessionStore struct {
	database *db.DB
	clk      clock.Clock
	writer   *audit.Writer
	opts     SessionOptions
	// signInConfiguration is the hash of opts.SignInConfiguration, which
	// sessions record.
	signInConfiguration []byte
}

// NewSessionStore creates a new SessionStore, which records sign-ins and
// sign-outs with writer.
func NewSessionStore(database *db.DB, clk clock.Clock, writer *audit.Writer, opts SessionOptions) *SessionStore {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	if opts.AbsoluteLifetime <= 0 {
		opts.AbsoluteLifetime = 12 * time.Hour
	}
	c := opts.SignInConfiguration
	return &SessionStore{
		database:            database,
		clk:                 clk,
		writer:              writer,
		opts:                opts,
		signInConfiguration: signInConfigurationSHA256(signInConfigurationForm, c.ClientID, c),
	}
}

// signInConfigurationSHA256 returns the SHA-256 of c in a canonical form: the
// name of the form; the issuer; clientID, which is c.ClientID for sessions and
// c.CLIClientID for the CLI's tokens, c's other client ID being left out; the
// allowed algorithms, in the order of their bytes and each once; the external
// ID claim; the groups claim; then each group of the role mapping, in the
// order of its bytes, followed by its role. Every string is preceded by its
// length, and each list by its number of items, in eight bytes, so that no
// string passes for part of another or of the next setting, whatever it
// holds.
//
// Two configurations thus hash the same in a form exactly when their settings
// are the same, but for what carries no meaning: the order of the algorithms,
// and an algorithm listed twice, since the verifier reads them as a set; the
// order of the groups, which the map has already lost; and nil or empty for a
// list or the mapping. An empty setting hashes apart from any that is set,
// even when the OIDC service gives it a default, such as sub for the external
// ID claim: the configuration writes the defaults, so an empty setting is one
// that was emptied, and the cost is a sign-in, never a role. Likewise,
// ResolveEffectiveRoles looks a group up without its leading slash too, so a
// few mappings that differ in groups that start with slashes resolve the same
// roles for every group, and hash apart all the same.
func signInConfigurationSHA256(form, clientID string, c SignInConfiguration) []byte {
	h := sha256.New()
	writeCount := func(n uint64) { h.Write(binary.BigEndian.AppendUint64(nil, n)) }
	writeString := func(s string) {
		writeCount(uint64(len(s)))
		h.Write([]byte(s))
	}
	writeString(form)
	writeString(c.Issuer)
	writeString(clientID)
	algorithms := slices.Compact(slices.Sorted(slices.Values(c.AllowedAlgorithms)))
	writeCount(uint64(len(algorithms)))
	for _, algorithm := range algorithms {
		writeString(algorithm)
	}
	writeString(c.ExternalIDClaim)
	writeString(c.GroupsClaim)
	writeCount(uint64(len(c.RoleMapping)))
	for _, group := range slices.Sorted(maps.Keys(c.RoleMapping)) {
		writeString(group)
		writeString(c.RoleMapping[group])
	}
	return h.Sum(nil)
}

// signInConfigurationOf returns the hash of the sign-in configuration that a
// session of method records: the store's, and none for break-glass, whose
// roles come from none of its settings.
func (s *SessionStore) signInConfigurationOf(method string) []byte {
	if method == "breakglass" {
		return nil
	}
	return s.signInConfiguration
}

// Create generates and stores a new session for principalID with the given method and roles.
func (s *SessionStore) Create(ctx context.Context, principalID uuid.UUID, method string, roles []string) (*Session, error) {
	return s.CreateWithLifetime(ctx, principalID, method, roles, s.opts.AbsoluteLifetime)
}

// CreateWithLifetime generates and stores a new session with an explicit maximum lifetime.
func (s *SessionStore) CreateWithLifetime(
	ctx context.Context,
	principalID uuid.UUID,
	method string,
	roles []string,
	lifetime time.Duration,
) (*Session, error) {
	token, err := generateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	idHash := hashToken(token)
	csrfToken := deriveCSRFToken(token)
	csrfHash := hashToken(csrfToken)

	now := s.clk.Now().UTC()
	if lifetime <= 0 {
		lifetime = s.opts.AbsoluteLifetime
	}
	absoluteExpiry := now.Add(lifetime)
	idleExpiry := now.Add(s.opts.IdleTimeout)
	if idleExpiry.After(absoluteExpiry) {
		idleExpiry = absoluteExpiry
	}

	q := authndb.New(s.database)
	err = q.CreateSession(ctx, authndb.CreateSessionParams{
		IDHash:                    idHash,
		PrincipalID:               principalID,
		Method:                    method,
		Roles:                     roles,
		CsrfTokenHash:             csrfHash,
		CreatedAt:                 now,
		IdleExpiresAt:             idleExpiry,
		AbsoluteExpiresAt:         absoluteExpiry,
		SignInConfigurationSha256: s.signInConfigurationOf(method),
	})
	if err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return &Session{
		Token:             token,
		IDHash:            idHash,
		PrincipalID:       principalID,
		Method:            method,
		Roles:             append([]string{}, roles...),
		CSRFToken:         csrfToken,
		CSRFTokenHash:     csrfHash,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     idleExpiry,
		AbsoluteExpiresAt: absoluteExpiry,
	}, nil
}

// CreateWithLifetimeTx generates and stores a new session inside the given transaction with an explicit maximum lifetime.
func (s *SessionStore) CreateWithLifetimeTx(
	ctx context.Context,
	tx *db.Tx,
	principalID uuid.UUID,
	method string,
	roles []string,
	lifetime time.Duration,
) (*Session, error) {
	token, err := generateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	idHash := hashToken(token)
	csrfToken := deriveCSRFToken(token)
	csrfHash := hashToken(csrfToken)

	now := s.clk.Now().UTC()
	if lifetime <= 0 {
		lifetime = s.opts.AbsoluteLifetime
	}
	absoluteExpiry := now.Add(lifetime)
	idleExpiry := now.Add(s.opts.IdleTimeout)
	if idleExpiry.After(absoluteExpiry) {
		idleExpiry = absoluteExpiry
	}

	q := authndb.New(tx)
	err = q.CreateSession(ctx, authndb.CreateSessionParams{
		IDHash:                    idHash,
		PrincipalID:               principalID,
		Method:                    method,
		Roles:                     roles,
		CsrfTokenHash:             csrfHash,
		CreatedAt:                 now,
		IdleExpiresAt:             idleExpiry,
		AbsoluteExpiresAt:         absoluteExpiry,
		SignInConfigurationSha256: s.signInConfigurationOf(method),
	})
	if err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return &Session{
		Token:             token,
		IDHash:            idHash,
		PrincipalID:       principalID,
		Method:            method,
		Roles:             append([]string{}, roles...),
		CSRFToken:         csrfToken,
		CSRFTokenHash:     csrfHash,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     idleExpiry,
		AbsoluteExpiresAt: absoluteExpiry,
	}, nil
}

// Get validates and loads an active session by token. It verifies that the principal
// is active and slides the idle expiration. A session that another sign-in
// configuration than the store's created is refused as an expired one, and
// neither revoked nor touched: a replica that still runs that configuration,
// during a rolling restart, accepts it, and so would this one after a return
// to it. A session that recorded no configuration, as those created before
// sessions recorded one, counts as one of another configuration (ST-14).
func (s *SessionStore) Get(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrSessionNotFound
	}
	idHash := hashToken(token)

	q := authndb.New(s.database)
	row, err := q.GetSessionByHash(ctx, idHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("querying session: %w", err)
	}

	now := s.clk.Now().UTC()

	if row.RevokedAt != nil {
		return nil, ErrSessionRevoked
	}
	if now.After(row.AbsoluteExpiresAt) || now.After(row.IdleExpiresAt) {
		return nil, ErrSessionExpired
	}
	if row.Method != "breakglass" && !bytes.Equal(row.SignInConfigurationSha256, s.signInConfiguration) {
		return nil, ErrSessionExpired
	}

	// Verify that the principal is active. If inactive, revoke the session immediately.
	pRow, err := q.GetPrincipalByID(ctx, row.PrincipalID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			_ = s.Revoke(ctx, token)
			return nil, ErrPrincipalInactive
		}
		return nil, fmt.Errorf("checking principal status: %w", err)
	}
	if pRow.Status != "active" {
		_ = s.Revoke(ctx, token)
		return nil, ErrPrincipalInactive
	}

	// Slide idle timeout.
	newIdle := now.Add(s.opts.IdleTimeout)
	if newIdle.After(row.AbsoluteExpiresAt) {
		newIdle = row.AbsoluteExpiresAt
	}
	if err := q.TouchSession(ctx, authndb.TouchSessionParams{
		IDHash:        idHash,
		LastSeenAt:    now,
		IdleExpiresAt: newIdle,
	}); err != nil {
		return nil, fmt.Errorf("sliding session expiry: %w", err)
	}

	csrfToken := deriveCSRFToken(token)

	return &Session{
		Token:             token,
		IDHash:            row.IDHash,
		PrincipalID:       row.PrincipalID,
		Method:            row.Method,
		Roles:             append([]string{}, row.Roles...),
		CSRFToken:         csrfToken,
		CSRFTokenHash:     row.CsrfTokenHash,
		CreatedAt:         row.CreatedAt,
		LastSeenAt:        now,
		IdleExpiresAt:     newIdle,
		AbsoluteExpiresAt: row.AbsoluteExpiresAt,
	}, nil
}

// ReplaceTx creates the session of a sign-in in tx and revokes the sessions
// that held names: those of the session cookies that the browser sent with
// the sign-in, whoever they belong to. A sign-in thus never leaves valid a
// session that the browser held before it, be it the previous user's or one
// that someone planted (ST-14). lifetime bounds the session; zero is the
// store's absolute lifetime.
//
// It records, in tx, each held session that it revoked while neither revoked
// nor expired, as replaced by the principal who signs in, and the sign-in,
// unless it is break-glass's: that sign-in's record is
// whitetower.breakglass.used.v1, which its service writes. A held session of
// another sign-in configuration, which Get refuses, is revoked and recorded
// too, so that neither a replica of that configuration nor a return to it
// accepts it again.
func (s *SessionStore) ReplaceTx(
	ctx context.Context,
	tx *db.Tx,
	held []string,
	principalID uuid.UUID,
	method string,
	roles []string,
	lifetime time.Duration,
) (*Session, error) {
	for _, token := range held {
		if err := s.revokeTx(ctx, tx, token, "replaced", actorOf(method, principalID)); err != nil {
			return nil, fmt.Errorf("revoking the session that the browser held: %w", err)
		}
	}
	session, err := s.CreateWithLifetimeTx(ctx, tx, principalID, method, roles, lifetime)
	if err != nil || method == "breakglass" {
		return session, err
	}
	if err := s.writer.Record(ctx, tx, audit.Event{
		Type:    "whitetower.session.created.v1",
		Subject: principalID.String(),
		Data: map[string]any{
			"principal_id": principalID.String(),
			"actor":        actorOf(method, principalID),
			"method":       method,
			"roles":        append([]string{}, roles...), // an array, never null
			"expires_at":   session.AbsoluteExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		},
	}); err != nil {
		return nil, fmt.Errorf("recording the sign-in: %w", err)
	}
	return session, nil
}

// SignOut revokes the session of token, when it is active, and records in the
// same transaction that its principal signed out. A token of no active
// session, unknown, revoked or expired, changes and records nothing: signing
// out needs no authentication, and must not let a request with a random or
// stale cookie write to the audit log.
func (s *SessionStore) SignOut(ctx context.Context, token string) error {
	return s.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return s.revokeTx(ctx, tx, token, "signed_out", nil)
	})
}

// revokeTx revokes the session of token in tx when it is active, and records
// its revocation for reason, by actor, or by the session's principal when
// actor is nil. A token of no active session changes and records nothing.
func (s *SessionStore) revokeTx(ctx context.Context, tx *db.Tx, token, reason string, actor map[string]any) error {
	now := s.clk.Now().UTC()
	revoked, err := authndb.New(tx).RevokeActiveSession(ctx, authndb.RevokeActiveSessionParams{IDHash: hashToken(token), RevokedAt: &now})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if actor == nil {
		actor = actorOf(revoked.Method, revoked.PrincipalID)
	}
	return s.writer.Record(ctx, tx, audit.Event{
		Type:    "whitetower.session.revoked.v1",
		Subject: revoked.PrincipalID.String(),
		Data: map[string]any{
			"principal_id": revoked.PrincipalID.String(),
			"actor":        actor,
			"method":       revoked.Method,
			"reason":       reason,
		},
	})
}

// heldSessions returns the session tokens that r's cookies name, for ReplaceTx:
// the first under the session cookie's name and the first under the
// unprefixed one, so that a request with many cookies costs no more.
func heldSessions(r *http.Request) []string {
	var held []string
	for _, name := range []string{CookieName, unprefixedCookieName} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			held = append(held, c.Value)
		}
	}
	return held
}

// Revoke marks a single session as revoked.
func (s *SessionStore) Revoke(ctx context.Context, token string) error {
	idHash := hashToken(token)
	now := s.clk.Now().UTC()
	q := authndb.New(s.database)
	return q.RevokeSession(ctx, authndb.RevokeSessionParams{
		IDHash:    idHash,
		RevokedAt: &now,
	})
}

// RevokeAllForPrincipal revokes every active session belonging to principalID.
func (s *SessionStore) RevokeAllForPrincipal(ctx context.Context, principalID uuid.UUID) error {
	now := s.clk.Now().UTC()
	q := authndb.New(s.database)
	return q.RevokeSessionsForPrincipal(ctx, authndb.RevokeSessionsForPrincipalParams{
		PrincipalID: principalID,
		RevokedAt:   &now,
	})
}

// RevokeAllForPrincipalTx revokes every active session belonging to principalID within a transaction.
func (s *SessionStore) RevokeAllForPrincipalTx(ctx context.Context, tx *db.Tx, principalID uuid.UUID) error {
	now := s.clk.Now().UTC()
	q := authndb.New(tx)
	return q.RevokeSessionsForPrincipal(ctx, authndb.RevokeSessionsForPrincipalParams{
		PrincipalID: principalID,
		RevokedAt:   &now,
	})
}

// DeleteExpired permanently removes sessions past their absolute lifetime or idle timeout.
func (s *SessionStore) DeleteExpired(ctx context.Context) (int64, error) {
	now := s.clk.Now().UTC()
	grace := now.Add(-1 * time.Hour)
	q := authndb.New(s.database)
	deleted, err := q.DeleteExpiredSessions(ctx, authndb.DeleteExpiredSessionsParams{
		AbsoluteExpiresAt: now,
		RevokedAt:         &grace,
	})
	if err != nil {
		return 0, fmt.Errorf("deleting expired sessions: %w", err)
	}
	return deleted, nil
}

// ValidateCSRF compares candidate against the session's stored CSRF hash in constant time.
func (s *SessionStore) ValidateCSRF(session *Session, candidate string) bool {
	if session == nil || candidate == "" {
		return false
	}
	candidateHash := hashToken(candidate)
	return subtle.ConstantTimeCompare(candidateHash, session.CSRFTokenHash) == 1
}

// ValidateRequestCSRF checks if an incoming state-changing request carrying a session
// contains a valid CSRF token in the X-CSRF-Token header (ST-13).
func (s *SessionStore) ValidateRequestCSRF(r *http.Request) bool {
	session := SessionFromContext(r.Context())
	if session == nil {
		return true
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.Header.Get("X-WT-CSRF-Token")
	}
	return s.ValidateCSRF(session, token)
}

// Cookie constructs an http.Cookie for sessionToken.
func (s *SessionStore) Cookie(sessionToken string) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.opts.AbsoluteLifetime.Seconds()),
	}
}

// CookieForSession constructs an http.Cookie scaled to the specific session's remaining lifetime.
func (s *SessionStore) CookieForSession(session *Session) *http.Cookie {
	maxAge := int(s.opts.AbsoluteLifetime.Seconds())
	if session != nil && !session.AbsoluteExpiresAt.IsZero() {
		rem := session.AbsoluteExpiresAt.Sub(s.clk.Now().UTC())
		if rem > 0 {
			maxAge = int(rem.Seconds())
		}
	}
	return &http.Cookie{
		Name:     CookieName,
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// ClearCookie returns a cookie configured to delete the session from the client.
func (s *SessionStore) ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

func generateRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func deriveCSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(csrfHMACKey))
	mac.Write([]byte(sessionToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type sessionContextKey struct{}

// ContextWithSession associates session with ctx.
func ContextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// SessionFromContext returns the Session associated with ctx, if any.
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionContextKey{}).(*Session)
	return s
}
