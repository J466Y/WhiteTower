// Package audit is White Tower's tamper-evident audit log (plan P1-02;
// ADR-0006): the evidence of every change of the core, and of what modules
// report, sealed into a Merkle tree under signed checkpoints.
//
// Events are CloudEvents of the event catalog (contracts, section 8). Each is
// stored as its canonical JSON (RFC 8785), the exact bytes that the tree
// hashes and that verification recomputes from; the columns beside them are
// read from those bytes, for queries. Every event enters the queue of events
// to seal in its own transaction.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.opentelemetry.io/otel/trace"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// Event is an event of the core: a change of state, recorded in the
// transaction that makes it (AUD-01).
type Event struct {
	// Type is a type of the event catalog that the core emits.
	Type string
	// Subject is the ID of the agent that the change is about, when the
	// type has one.
	Subject string
	// Data marshals to the event's data, which its type's schema checks. It
	// names people only by their pseudonymous principal IDs, never by name
	// or email address (NFR-20), and holds no secret.
	Data any
}

// envelope is a CloudEvent in the JSON format (contracts, section 8.2).
type envelope struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Time            string          `json:"time"`
	Subject         string          `json:"subject,omitempty"`
	DataContentType string          `json:"datacontenttype"`
	Data            json.RawMessage `json:"data"`
	TraceParent     string          `json:"traceparent,omitempty"`
	TraceState      string          `json:"tracestate,omitempty"`
	RequestID       string          `json:"wtrequestid,omitempty"`
}

// timeLayout writes times as the contracts do: in UTC, to the millisecond.
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// Writer records the core's events. Every change of state records its event
// in its own transaction, so that a change whose event cannot be recorded
// does not happen (AUD-01).
type Writer struct {
	catalog *Catalog
	clock   clock.Clock
}

// NewWriter returns a writer that checks events against catalog, and dates
// them by clk.
func NewWriter(catalog *Catalog, clk clock.Clock) *Writer {
	return &Writer{catalog: catalog, clock: clk}
}

// Record records e in tx, and queues it for the sealer. Its source is the
// core, its time now, and it carries the request ID and the trace of ctx. It
// fails when e is not a valid event of the core, or cannot be stored: the
// caller returns the error, and InTx rolls the whole change back.
func (w *Writer) Record(ctx context.Context, tx *db.Tx, e Event) error {
	if t, ok := w.catalog.types[e.Type]; ok && !slices.Contains(t.emitters, "core") {
		return fmt.Errorf("audit: %s: the core does not emit this type", e.Type)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	data, err := json.Marshal(e.Data)
	if err != nil {
		return fmt.Errorf("audit: %s: encoding the data: %w", e.Type, err)
	}
	at := w.clock.Now().UTC().Truncate(time.Millisecond)
	env := envelope{
		SpecVersion: "1.0", ID: id.String(), Source: "/core", Type: e.Type, Time: at.Format(timeLayout),
		Subject: e.Subject, DataContentType: "application/json", Data: data, RequestID: logging.RequestID(ctx),
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		env.TraceParent = fmt.Sprintf("00-%s-%s-%s", sc.TraceID(), sc.SpanID(), sc.TraceFlags())
		env.TraceState = sc.TraceState().String()
	}
	canonical, decoded, err := canonicalize(env)
	if err != nil {
		return fmt.Errorf("audit: %s: %w", e.Type, err)
	}
	t, err := w.catalog.check(decoded)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	f, err := factsOf(t, decoded)
	if err != nil {
		return fmt.Errorf("audit: %s: %w", e.Type, err)
	}
	params := auditdb.RecordEventParams{
		ID: id, Source: env.Source, EventID: env.ID, Type: e.Type, EventTime: at, Canonical: canonical,
		ActorType: f.actorType, ActorID: optional(f.actorID), Action: f.action, Outcome: optional(f.outcome),
		Reason: optional(f.reason), RequestID: optional(env.RequestID),
	}
	if e.Subject != "" {
		subject, err := uuid.Parse(e.Subject)
		if err != nil {
			return fmt.Errorf("audit: %s: the subject: %w", e.Type, err)
		}
		params.SubjectAgentID = &subject
	}
	if env.TraceParent != "" {
		traceID := env.TraceParent[3:35]
		params.TraceID = &traceID
	}
	if err := auditdb.New(tx).RecordEvent(ctx, params); err != nil {
		return fmt.Errorf("audit: %s: storing the event: %w", e.Type, err)
	}
	return nil
}

// canonicalize returns an event's canonical JSON (RFC 8785), and the event
// decoded from those bytes as jsonschema.UnmarshalJSON decodes it.
func canonicalize(v any) (canonical []byte, decoded map[string]any, err error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	if canonical, err = jcs.Transform(raw); err != nil {
		return nil, nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(canonical))
	if err != nil {
		return nil, nil, err
	}
	decoded, ok := doc.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("not a JSON object")
	}
	return canonical, decoded, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
