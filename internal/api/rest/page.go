package rest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/J466Y/WhiteTower/internal/api/rest/problem"
)

// List pages: every list operation takes a limit and a cursor, and returns at
// most MaxPageSize items, so that no request can ask the core for an
// unbounded amount of work (requirement API-03; threat model, T-72).
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
	maxCursorLength = 1024
)

// PageSize returns the size of the page a list asks for: limit, or
// DefaultPageSize when the request names none, and never more than
// MaxPageSize.
func PageSize(limit *int) (int, error) {
	switch {
	case limit == nil:
		return DefaultPageSize, nil
	case *limit < 1:
		return 0, problem.New(problem.BadRequest, "limit must be at least 1")
	default:
		return min(*limit, MaxPageSize), nil
	}
}

// EncodeCursor turns the position after the last item of a page, such as its
// sort key and ID, into the opaque cursor of the next page.
func EncodeCursor(position any) (string, error) {
	b, err := json.Marshal(position)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeCursor reads into position a cursor that EncodeCursor made for the
// same kind of position. Anything else is an invalid_cursor problem: clients
// pass cursors back as they got them.
func DecodeCursor(cursor string, position any) error {
	invalid := problem.New(problem.InvalidCursor, "pass back the cursor of the previous page as it came")
	if len(cursor) > maxCursorLength {
		return invalid
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return invalid
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(position); err != nil || dec.More() {
		return invalid
	}
	return nil
}

// ETag returns the strong entity tag of a resource at a version: its row's
// version column (requirement API-03).
func ETag(version int64) string { return fmt.Sprintf(`"%d"`, version) }

// IfMatch reads the version that an update's If-Match header names. An
// update must name one, so that two people cannot silently overwrite each
// other's changes (threat model, T-08): a missing header is a
// precondition_required problem, and "*", which would skip the check, or a
// malformed one, a bad_request problem.
func IfMatch(header string) (int64, error) {
	if header == "" {
		return 0, problem.New(problem.PreconditionRequired, "send If-Match with the ETag of the version you read")
	}
	var version int64
	if _, err := fmt.Sscanf(header, `"%d"`, &version); err != nil || ETag(version) != header {
		return 0, problem.New(problem.BadRequest, "If-Match must hold one ETag, as the resource was read")
	}
	return version, nil
}

// Stale returns the precondition_failed problem of an update whose version
// is no longer the current one.
func Stale() *problem.Problem {
	return problem.New(problem.PreconditionFailed, "the resource changed since you read it: read it again, then retry")
}
