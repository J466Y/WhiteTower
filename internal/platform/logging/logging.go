// Package logging sets up the server's logs: JSON lines with UTC timestamps
// in milliseconds (requirement NFR-19). A record logged with a request's
// context carries the request, trace and principal IDs, so that a request can
// be followed through the logs and the traces. The redaction helpers keep
// tokens, keys and cookies out of the logs (requirement NFR-12).
package logging

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"
)

// TimeFormat is the layout of the time field: RFC 3339 in UTC, with
// milliseconds.
const TimeFormat = "2006-01-02T15:04:05.000Z07:00"

// New returns a logger that writes JSON lines to w and drops records below
// level: debug, info, warn or error (anything else means info).
func New(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level)) // the configuration validates the level
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: l,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(TimeFormat))
			}
			return a
		},
	})
	return slog.New(contextHandler{h})
}

type requestKey struct{}

// request holds the identifiers of one request. Authentication learns the
// principal, and the innermost router the route, after the request has
// started, so they are set in place.
type request struct {
	id        string
	principal atomic.Pointer[string]
	route     atomic.Pointer[string]
}

func requestFrom(ctx context.Context) *request {
	r, _ := ctx.Value(requestKey{}).(*request)
	return r
}

// WithRequest returns a context for the request with the given ID. Records
// logged with it, or with a context derived from it, carry the ID.
func WithRequest(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestKey{}, &request{id: id})
}

// RequestID returns the ID of the request that ctx belongs to, or "".
func RequestID(ctx context.Context) string {
	if r := requestFrom(ctx); r != nil {
		return r.id
	}
	return ""
}

// SetPrincipal records who made the request that ctx belongs to; the
// authentication middleware (plan P1-03) calls it. The records logged from
// then on, the request's access log among them, carry the principal ID.
func SetPrincipal(ctx context.Context, id string) {
	if r := requestFrom(ctx); r != nil {
		r.principal.Store(&id)
	}
}

// PrincipalID returns the principal recorded for the request that ctx
// belongs to, or "".
func PrincipalID(ctx context.Context) string {
	if r := requestFrom(ctx); r != nil {
		if p := r.principal.Load(); p != nil {
			return *p
		}
	}
	return ""
}

// SetRoute records the pattern of the innermost router that matched the
// request that ctx belongs to. Middleware that hands on a copy of the request
// hides the router's match from the outer layers, which read it here.
func SetRoute(ctx context.Context, pattern string) {
	if r := requestFrom(ctx); r != nil && pattern != "" {
		r.route.Store(&pattern)
	}
}

// Route returns the pattern recorded with SetRoute, or "".
func Route(ctx context.Context) string {
	if r := requestFrom(ctx); r != nil {
		if p := r.route.Load(); p != nil {
			return *p
		}
	}
	return ""
}

// contextHandler adds the request, principal and trace IDs found in a
// record's context. In a logger with groups, they land in the innermost one.
type contextHandler struct{ slog.Handler }

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	var attrs []slog.Attr
	if req := requestFrom(ctx); req != nil {
		attrs = append(attrs, slog.String("request_id", req.id))
		if p := req.principal.Load(); p != nil {
			attrs = append(attrs, slog.String("principal_id", *p))
		}
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		attrs = append(attrs,
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()))
	}
	if len(attrs) > 0 {
		// The record may be shared with the caller: add to a copy.
		r = r.Clone()
		r.AddAttrs(attrs...)
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}
