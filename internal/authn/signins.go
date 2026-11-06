package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// How a sign-in ended, as the log and whitetower_auth_sign_ins_total name it:
// success, error, or the reason of a refusal. A refused sign-in changes
// nothing, so it writes no audit event: the log and the metric are its only
// trace (the maintainer's decision 3 of 2026-11-05, plan P1-03).
const (
	resultSuccess = "success"
	// resultError: the server or the identity provider failed, and the log
	// says how.
	resultError = "error"

	// refusedInvalidRequest: the request ends no sign-in that the server
	// began, or lacks what a sign-in needs: no state, or a state of no
	// sign-in, no authorization code, no ID token, no credential.
	refusedInvalidRequest = "invalid_request"
	// refusedByProvider: the identity provider sent the browser back with an
	// error, such as access_denied.
	refusedByProvider = "provider_error"
	// refusedInvalidToken: the ID token does not verify, or is not the
	// sign-in's.
	refusedInvalidToken = "invalid_token"
	// refusedNoExternalID: the ID token carries no external ID in its
	// configured claim.
	refusedNoExternalID = "no_external_id"
	// refusedExternalIDConflict: the principal with the sign-in's issuer and
	// subject holds another external ID.
	refusedExternalIDConflict = "external_id_conflict"
	// refusedInactive: the principal is deactivated.
	refusedInactive = "inactive"
	// refusedInvalidCredential: the break-glass credential does not verify.
	refusedInvalidCredential = "invalid_credential" //nolint:gosec // G101: the name of a refusal's reason, which holds no credential
	// refusedRateLimited: the client made too many break-glass attempts.
	refusedRateLimited = "rate_limited"
)

// signIns records how sign-ins end: a line in the log for each refusal, and a
// count of each sign-in by method and result.
type signIns struct {
	logger  *slog.Logger
	metrics *metrics.SignIns // none in tests that do not count
}

// refused logs one line for a sign-in through method that the server refused
// for reason, with the ID of the principal that the refusal found, when there
// is one, and attrs, and counts it. Its callers pass no value of a credential
// or an ID token, and sanitize what a client chose.
func (s signIns) refused(ctx context.Context, method, reason string, principalID *uuid.UUID, attrs ...any) {
	args := []any{"method", method, "reason", reason}
	if principalID != nil {
		args = append(args, "principal_id", principalID.String())
	}
	s.logger.WarnContext(ctx, "refusing a sign-in", append(args, attrs...)...)
	s.ended(method, reason)
}

// ended counts a sign-in through method that ended with result.
func (s signIns) ended(method, result string) {
	if s.metrics != nil {
		s.metrics.Ended(method, result)
	}
}

// refusedPrincipal is the error of a sign-in that the store refuses for the
// principal it found: an inactive one, or one that holds another external
// ID. It wraps the reason, ErrPrincipalInactive or ErrExternalIDConflict.
type refusedPrincipal struct {
	id  uuid.UUID
	err error
}

func (e *refusedPrincipal) Error() string { return fmt.Sprintf("%v: principal %s", e.err, e.id) }
func (e *refusedPrincipal) Unwrap() error { return e.err }

// refusedPrincipalID returns the ID of the principal whose sign-in err
// refuses, or nil when err names none.
func refusedPrincipalID(err error) *uuid.UUID {
	if r, ok := errors.AsType[*refusedPrincipal](err); ok {
		return &r.id
	}
	return nil
}
