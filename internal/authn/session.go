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

	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

const (
	// CookieNameSecure is the session cookie name with the __Host- prefix (ADR-0009).
	CookieNameSecure = "__Host-wt_session"

	// CookieNameInsecure is the fallback cookie name when TLS is not enabled.
	CookieNameInsecure = "wt_session"

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
	opts     SessionOptions
}

// NewSessionStore creates a new SessionStore.
func NewSessionStore(database *db.DB, clk clock.Clock, opts SessionOptions) *SessionStore {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	if opts.AbsoluteLifetime <= 0 {
		opts.AbsoluteLifetime = 12 * time.Hour
	}
	return &SessionStore{
		database: database,
		clk:      clk,
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

// Rotate implements session fixation prevention by replacing oldToken with a fresh session
// for the same principal, retaining roles and method.
func (s *SessionStore) Rotate(ctx context.Context, oldToken string) (*Session, error) {
	current, err := s.Get(ctx, oldToken)
	if err != nil {
		return nil, fmt.Errorf("validating existing session for rotation: %w", err)
	}

	if err := s.Revoke(ctx, oldToken); err != nil {
		return nil, fmt.Errorf("revoking old session: %w", err)
	}

	return s.Create(ctx, current.PrincipalID, current.Method, current.Roles)
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
func (s *SessionStore) Cookie(sessionToken string, secure bool) *http.Cookie {
	name := CookieNameSecure
	if !secure {
		name = CookieNameInsecure
	}
	//nolint:gosec // G124: secure flag is dynamic to support non-TLS in development
	return &http.Cookie{
		Name:     name,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.opts.AbsoluteLifetime.Seconds()),
	}
}

// CookieForSession constructs an http.Cookie scaled to the specific session's remaining lifetime.
func (s *SessionStore) CookieForSession(session *Session, secure bool) *http.Cookie {
	name := CookieNameSecure
	if !secure {
		name = CookieNameInsecure
	}
	maxAge := int(s.opts.AbsoluteLifetime.Seconds())
	if session != nil && !session.AbsoluteExpiresAt.IsZero() {
		rem := session.AbsoluteExpiresAt.Sub(s.clk.Now().UTC())
		if rem > 0 {
			maxAge = int(rem.Seconds())
		}
	}
	//nolint:gosec // G124: secure flag is dynamic to support non-TLS in development
	return &http.Cookie{
		Name:     name,
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// ClearCookie returns a cookie configured to delete the session from the client.
func (s *SessionStore) ClearCookie(secure bool) *http.Cookie {
	name := CookieNameSecure
	if !secure {
		name = CookieNameInsecure
	}
	//nolint:gosec // G124: secure flag is dynamic to support non-TLS in development
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
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
