package moduleapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
)

// calls is the middleware of every call to the module API, in two parts.
//
// Its gate runs once the request headers have arrived, before connect reads
// the request message, so that a caller without a valid token costs no
// decoding. It reports the procedure as the route, for the access log and
// the HTTP metrics; puts the contract version in the context; and
// authenticates the caller (contracts, section 4.2).
//
// Its interceptor wraps the calls that pass the gate. It counts them in the
// RPC metrics, marks the span of those the server failed, and keeps the
// cause of an internal error from the caller (threat model, T-10): the cause
// goes to the log. A unary call whose message cannot be read ends before the
// interceptor, and shows only in the HTTP metrics and the access log.
type calls struct {
	auth    Authenticator
	metrics *metrics.RPC
	logger  *slog.Logger
}

// errInternal is all that a caller learns of an internal error. An error
// that wraps it has been logged already.
var errInternal = errors.New("internal error")

var errUnauthenticated = errors.New("the call needs a valid access token (module contracts, section 4.2)")

// codeOK names the outcome of a call that succeeded, in the metrics and the
// spans.
const codeOK = "ok"

// gate is the connect.RequestGateFunc of every procedure.
func (c *calls) gate(ctx context.Context, spec connect.Spec, _ connect.Peer, header http.Header) (context.Context, error) {
	logging.SetRoute(ctx, spec.Procedure)
	version := procedureVersion(spec.Procedure)
	trace.SpanFromContext(ctx).SetAttributes(
		semconv.RPCSystemNameConnectrpc,
		semconv.RPCMethod(strings.TrimPrefix(spec.Procedure, "/")),
		attribute.String("whitetower.contract_version", version),
	)
	ctx = context.WithValue(ctx, versionKeyType{}, version)
	caller, err := c.authenticate(ctx, spec, header)
	if err != nil {
		c.metrics.Refused(spec.Procedure, outcome(ctx, err))
		return nil, err
	}
	logging.SetPrincipal(ctx, caller.Identity)
	return context.WithValue(ctx, callerKey{}, caller), nil
}

// authenticate returns the caller. A panic in the authenticator fails the
// call as a panic in a handler does, since connect.WithRecover does not
// cover gates.
func (c *calls) authenticate(ctx context.Context, spec connect.Spec, header http.Header) (caller *Caller, err error) {
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler { //nolint:errorlint // net/http compares it so.
				panic(p)
			}
			caller, err = nil, c.recovered(ctx, spec, header, p)
		}
	}()
	caller, err = c.auth.Authenticate(ctx, header)
	if err != nil || caller == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errUnauthenticated)
	}
	return caller, nil
}

// WrapUnary implements connect.Interceptor.
func (c *calls) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		done := c.metrics.Started(req.Spec().Procedure, false)
		resp, err := next(ctx, req)
		if err == nil {
			err = checkSize(req.Spec(), isJSON(req.HTTPMethod(), req.Header(), req.Peer().Query), resp.Any())
		}
		if err = c.end(ctx, req.Spec(), err, done); err != nil {
			return nil, err
		}
		return resp, nil
	}
}

// WrapStreamingClient implements connect.Interceptor. The core calls no
// module API.
func (c *calls) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (c *calls) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		done := c.metrics.Started(conn.Spec().Procedure, true)
		return c.end(ctx, conn.Spec(), next(ctx, sizedConn{conn}), done)
	}
}

// sizedConn checks the size of each message that its handler sends.
type sizedConn struct{ connect.StreamingHandlerConn }

func (c sizedConn) Send(msg any) error {
	// Streams always come in POST requests.
	if err := checkSize(c.Spec(), isJSON(http.MethodPost, c.RequestHeader(), nil), msg); err != nil {
		return err
	}
	return c.StreamingHandlerConn.Send(msg)
}

// sendLimit returns the size of the largest message that the core may send
// on a procedure (contracts, section 4.8).
func sendLimit(procedure string) int {
	if procedure == modulev1alpha1connect.GovernanceServiceWatchProcedure {
		return MaxWatchMessageBytes
	}
	return MaxMessageBytes
}

// checkSize fails a message over the limit of its procedure, measured in the
// encoding of the call: the protocols and their encodings are equivalent
// (contracts, section 4.1), so the limit holds in each. connect's
// WithSendMaxBytes does not do: it measures the message as sent, compressed
// when the caller accepts it, while the caller limits the message it decodes.
// The core splits whatever can grow, so a message over the limit is a bug of
// the core's, and fails the call as an internal error. The caller would
// refuse it anyway, and could not do otherwise next time.
func checkSize(spec connect.Spec, json bool, msg any) error {
	m, ok := msg.(proto.Message)
	if !ok {
		return nil
	}
	var size int
	if json {
		b, err := protojson.Marshal(m)
		if err != nil {
			return connect.NewError(connect.CodeInternal, fmt.Errorf("encoding a message as JSON: %w", err))
		}
		size = len(b)
	} else {
		size = proto.Size(m)
	}
	if limit := sendLimit(spec.Procedure); size > limit {
		return connect.NewError(connect.CodeInternal,
			fmt.Errorf("a %d-byte message exceeds the %d-byte limit of the module contracts (section 4.8)", size, limit))
	}
	return nil
}

// isJSON reports whether a call is encoded as JSON. A Connect GET request
// says so in its encoding parameter; any other request in its content type:
// application/json, or a protocol's type with the +json suffix.
func isJSON(method string, header http.Header, query url.Values) bool {
	if method == http.MethodGet {
		return query.Get("encoding") == "json"
	}
	mediaType, _, _ := strings.Cut(header.Get("Content-Type"), ";")
	return strings.HasSuffix(strings.TrimSpace(mediaType), "json")
}

// end records how a call ended, and returns the error for the caller.
func (c *calls) end(ctx context.Context, spec connect.Spec, err error, done func(code string)) error {
	if code := codeOf(err); err != nil && hidden(code) {
		if !errors.Is(err, errInternal) {
			c.logger.ErrorContext(ctx, "module API call failed", "procedure", spec.Procedure, "code", code.String(),
				"error", logging.Sanitize(err.Error()))
		}
		err = connect.NewError(code, errInternal)
	}
	done(outcome(ctx, err))
	return err
}

// recovered answers a panic in a handler with INTERNAL, and logs it with its
// stack.
func (c *calls) recovered(ctx context.Context, spec connect.Spec, _ http.Header, p any) error {
	c.logger.ErrorContext(ctx, "panic serving a module API call", "procedure", spec.Procedure,
		"panic", logging.Sanitize(fmt.Sprint(p)), "stack", string(debug.Stack()))
	return connect.NewError(connect.CodeInternal, errInternal)
}

// outcome reports how a call ended on its span, and returns the name of its
// code. As the OpenTelemetry conventions have it for gRPC servers, the span
// of a call that the server failed is an error; one that the caller got
// wrong is not.
func outcome(ctx context.Context, err error) string {
	if err == nil {
		trace.SpanFromContext(ctx).SetAttributes(semconv.RPCResponseStatusCode(codeOK))
		return codeOK
	}
	code := codeOf(err)
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(semconv.RPCResponseStatusCode(code.String()))
	switch code {
	case connect.CodeUnknown, connect.CodeDeadlineExceeded, connect.CodeUnimplemented,
		connect.CodeInternal, connect.CodeUnavailable, connect.CodeDataLoss:
		span.SetStatus(codes.Error, code.String())
	}
	return code.String()
}

// codeOf returns the code that connect sends for err: a handler may return
// the error of its context, which connect sends as CANCELED or
// DEADLINE_EXCEEDED, and any other error that is not a connect error as
// UNKNOWN.
func codeOf(err error) connect.Code {
	var connectErr *connect.Error
	switch {
	case errors.As(err, &connectErr):
		return connectErr.Code()
	case errors.Is(err, context.Canceled):
		return connect.CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return connect.CodeDeadlineExceeded
	default:
		return connect.CodeUnknown
	}
}

// hidden reports whether the message of an error with this code stays in the
// server's log: those are the codes of internal errors.
func hidden(code connect.Code) bool {
	return code == connect.CodeUnknown || code == connect.CodeInternal || code == connect.CodeDataLoss
}
