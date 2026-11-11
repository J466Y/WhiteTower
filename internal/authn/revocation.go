package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/authn/authndb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// MaxRevocationReason is the longest reason of an emergency revocation, in
// characters, as for the other revocations that the audit log records.
const MaxRevocationReason = 1000

// ErrInvalidReason is returned when the reason of an emergency revocation is
// blank or longer than MaxRevocationReason characters.
var ErrInvalidReason = fmt.Errorf("the reason is required, and holds at most %d characters", MaxRevocationReason)

// Revocation is what an emergency revocation ended.
type Revocation struct {
	// Sessions and Tokens count the sessions and the API tokens that it
	// revoked: those that were not revoked before, expired ones included.
	Sessions, Tokens int64
	// At is when it revoked them.
	At time.Time
	// SignedOut tells that the caller's own session was among them, so that
	// the answer clears its cookie, as a sign-out does.
	SignedOut bool
}

// EmergencyRevocation ends every session and every API token at once (plan
// P1-03, step 14; HUM-10): the platform administrator, or the break-glass
// custodian, runs it after a compromise of the identity provider, which no
// setting of the server tells apart from its normal work.
type EmergencyRevocation struct {
	sessions *SessionStore
	logger   *slog.Logger
}

// NewEmergencyRevocation returns the emergency revocation of the sessions of
// sessions and of every API token, through the store's database, clock and
// audit writer. It raises its security alerts in logger.
func NewEmergencyRevocation(sessions *SessionStore, logger *slog.Logger) *EmergencyRevocation {
	return &EmergencyRevocation{sessions: sessions, logger: logger}
}

// Revoke ends every session and every API token, of people and of service
// accounts, whatever sign-in configuration they record, for reason, in one
// transaction that records whitetower.access.revoked_all.v1 with the
// principal of caller, the session of whoever runs it: a session alone runs
// it, never an API token. The only session that stays is caller, when it is
// a break-glass session: the custodian goes on halting while everyone signs
// in again. A caller of any other method ends, since the session that asks
// could come from the compromised identity provider. Principals and their
// role bindings stay. Once it commits, it raises a security alert, as a
// break-glass use does, whoever ran it.
//
// It revokes every session and token that is not revoked yet, as the
// deactivation of a principal does, expired ones included: one that has
// expired on this replica's clock may not have on another's, and a request
// that read a session there just before would slide its idle expiry once
// this commits.
//
// The transaction first locks the sessions and the API tokens against
// inserts and updates (LockSessionsAndAPITokens), so that no session or token
// that another replica creates while it runs survives it once its creation
// commits first: a creation that committed before the lock is granted is
// revoked, and one that waits for the lock commits after the revocation. It
// adds nothing to the request path: a request reads its session or token
// without waiting, and only the writes of last use wait for the commit.
func (e *EmergencyRevocation) Revoke(ctx context.Context, caller *Session, reason string) (Revocation, error) {
	if caller == nil {
		return Revocation{}, errors.New("an emergency revocation needs the session of whoever runs it")
	}
	if strings.TrimSpace(reason) == "" || utf8.RuneCountInString(reason) > MaxRevocationReason {
		return Revocation{}, ErrInvalidReason
	}
	var keep []byte
	if caller.Method == "breakglass" {
		keep = caller.IDHash
	}
	s := e.sessions
	var revoked Revocation
	err := s.database.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := authndb.New(tx)
		if err := q.LockSessionsAndAPITokens(ctx); err != nil {
			return fmt.Errorf("locking the sessions and the API tokens: %w", err)
		}
		// Read once the lock is granted: no session or token is created
		// from then until the commit.
		now := s.clk.Now().UTC()
		sessions, err := q.RevokeAllSessions(ctx, authndb.RevokeAllSessionsParams{RevokedAt: &now, Keep: keep})
		if err != nil {
			return fmt.Errorf("revoking every session: %w", err)
		}
		tokens, err := q.RevokeAllAPITokens(ctx, &now)
		if err != nil {
			return fmt.Errorf("revoking every API token: %w", err)
		}
		revoked = Revocation{Sessions: sessions, Tokens: tokens, At: now, SignedOut: keep == nil}
		if err := s.writer.Record(ctx, tx, audit.Event{
			Type: "whitetower.access.revoked_all.v1",
			Data: map[string]any{
				"actor":    actorOf(caller.Method, caller.PrincipalID),
				"reason":   reason,
				"sessions": sessions,
				"tokens":   tokens,
			},
		}); err != nil {
			return fmt.Errorf("recording the emergency revocation: %w", err)
		}
		tx.AfterCommit(func(ctx context.Context) {
			e.logger.ErrorContext(ctx, "SECURITY ALERT: emergency revocation ended every session and API token",
				"principal_id", caller.PrincipalID.String(),
				"method", caller.Method,
				"sessions", sessions,
				"tokens", tokens,
				"reason", logging.Sanitize(reason),
			)
		})
		return nil
	})
	if err != nil {
		return Revocation{}, err
	}
	return revoked, nil
}

// ClearCookie returns the cookie that signs the caller's browser out once
// its session ended.
func (e *EmergencyRevocation) ClearCookie() *http.Cookie {
	return e.sessions.ClearCookie()
}
