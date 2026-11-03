package authn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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
)

var (
	// ErrSessionNotFound is returned when a session token does not match any record.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionRevoked is returned when a session has been revoked.
	ErrSessionRevoked = errors.New("session is revoked")

	// ErrSessionExpired is returned when a session has passed its idle or absolute lifetime.
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

// SessionOptions configures session lifecycle timeouts.
type SessionOptions struct {
	IdleTimeout      time.Duration
	AbsoluteLifetime time.Duration
}

// SessionStore handles session persistence in PostgreSQL.
type SessionStore struct {
	database *db.DB
	clk      clock.Clock
	writer   *audit.Writer
	opts     SessionOptions
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
	return &SessionStore{
		database: database,
		clk:      clk,
		writer:   writer,
		opts:     opts,
	}
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
		IDHash:            idHash,
		PrincipalID:       principalID,
		Method:            method,
		Roles:             roles,
		CsrfTokenHash:     csrfHash,
		CreatedAt:         now,
		IdleExpiresAt:     idleExpiry,
		AbsoluteExpiresAt: absoluteExpiry,
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
		IDHash:            idHash,
		PrincipalID:       principalID,
		Method:            method,
		Roles:             roles,
		CsrfTokenHash:     csrfHash,
		CreatedAt:         now,
		IdleExpiresAt:     idleExpiry,
		AbsoluteExpiresAt: absoluteExpiry,
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
// is active and slides the idle expiration.
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
// It records, in tx, each held session that it revoked while active, as
// replaced by the principal who signs in, and the sign-in, unless it is
// break-glass's: that sign-in's record is whitetower.breakglass.used.v1, which
// its service writes.
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
