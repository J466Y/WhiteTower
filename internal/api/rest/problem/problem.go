// Package problem writes the errors of the public API as RFC 9457 problem
// details (requirement API-03). Each error has a stable code, which the
// console translates; the English title and detail never carry internals
// (threat model, T-10). docs/reference/api-errors.md lists the codes.
package problem

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// Code is a stable error code.
type Code string

// The error codes. Add a code here, to codes below and to
// docs/reference/api-errors.md together; a test keeps them in step.
const (
	BadRequest           Code = "bad_request"
	InvalidCursor        Code = "invalid_cursor"
	Unauthenticated      Code = "unauthenticated"
	Forbidden            Code = "forbidden"
	NotFound             Code = "not_found"
	MethodNotAllowed     Code = "method_not_allowed"
	PreconditionFailed   Code = "precondition_failed"
	PayloadTooLarge      Code = "payload_too_large"
	PreconditionRequired Code = "precondition_required"
	RateLimited          Code = "rate_limited"
	Internal             Code = "internal"
)

// Codes maps every code to its HTTP status and title.
var Codes = map[Code]struct {
	Status int
	Title  string
}{
	BadRequest:           {http.StatusBadRequest, "The request is malformed"},
	InvalidCursor:        {http.StatusBadRequest, "The page cursor is not valid"},
	Unauthenticated:      {http.StatusUnauthorized, "Authentication is needed"},
	Forbidden:            {http.StatusForbidden, "The operation is not permitted"},
	NotFound:             {http.StatusNotFound, "Not found"},
	MethodNotAllowed:     {http.StatusMethodNotAllowed, "The method is not allowed"},
	PreconditionFailed:   {http.StatusPreconditionFailed, "The resource has changed"},
	PayloadTooLarge:      {http.StatusRequestEntityTooLarge, "The request body is too large"},
	PreconditionRequired: {http.StatusPreconditionRequired, "The request must name the version it changes"},
	RateLimited:          {http.StatusTooManyRequests, "Too many requests"},
	Internal:             {http.StatusInternalServerError, "Internal error"},
}

// TypeBase starts the type URI of every problem: it ends with the code, and
// leads to the code's documentation.
const TypeBase = "https://github.com/J466Y/WhiteTower/blob/main/docs/reference/api-errors.md#"

// Problem is an error of the public API. It is an error, so that handlers can
// return it.
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Code     Code   `json:"code"`

	// RetryAfter, when set, is sent as the Retry-After header.
	RetryAfter time.Duration `json:"-"`
	// Allow, when set, is sent as the Allow header.
	Allow []string `json:"-"`
}

// New returns the problem of a code, with a detail that explains this
// occurrence to a person, in English and without internals.
func New(code Code, detail string) *Problem {
	c, ok := Codes[code]
	if !ok {
		c = Codes[Internal]
		code = Internal
	}
	return &Problem{Type: TypeBase + string(code), Title: c.Title, Status: c.Status, Detail: detail, Code: code}
}

func (p *Problem) Error() string { return string(p.Code) + ": " + p.Detail }

// Write sends p as the response. Its instance is the request ID, which ties
// the client's error to the server's logs.
func Write(w http.ResponseWriter, r *http.Request, p *Problem) {
	if id := logging.RequestID(r.Context()); id != "" {
		p.Instance = "urn:uuid:" + id
	}
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	if p.RetryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(int(math.Ceil(p.RetryAfter.Seconds()))))
	}
	if len(p.Allow) > 0 {
		h.Set("Allow", strings.Join(p.Allow, ", "))
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// Handler returns a handler that sends a problem of code: for example the
// answer to a body over the size limit, on a listener's middleware.
func Handler(code Code, detail string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Write(w, r, New(code, detail))
	})
}
