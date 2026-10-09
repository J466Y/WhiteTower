package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
	"go.opentelemetry.io/otel/trace"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

const (
	agent     = "0192f1c2-7a3b-7c4d-8e5f-000000000001"
	olivia    = "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"
	requestID = "0192f2c4-8d1e-7c3a-9b2f-5e1d2c3b4a59"
)

var epoch = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// created is an event of the core, as the inventory will record it.
func created() audit.Event {
	return audit.Event{Type: "whitetower.agent.created.v1", Subject: agent, Data: map[string]any{
		"slug": "invoice-triage", "kind": "in_house", "risk_tier": "high",
		"use_case_id": "0192f1c2-7a3b-7c4d-8e5f-000000000010", "primary_owner": olivia,
		"actor": map[string]any{"type": "human", "id": olivia}, "state_version": 812,
	}}
}

func setup(t *testing.T) (*dbtest.Database, *db.DB, *audit.Writer) {
	t.Helper()
	d := dbtest.New(t)
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	return d, d.Open(t), audit.NewWriter(catalog, clocktest.New(epoch.Add(345*time.Millisecond+678*time.Microsecond)))
}

// record records e in a transaction of its own.
func record(ctx context.Context, pool *db.DB, w *audit.Writer, e audit.Event) error {
	return pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error { return w.Record(ctx, tx, e) })
}

func TestRecordStoresTheCanonicalEvent(t *testing.T) {
	d, pool, w := setup(t)
	span := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36},
		SpanID:  trace.SpanID{0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7}, TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(logging.WithRequest(context.Background(), requestID), span)
	if err := record(ctx, pool, w, created()); err != nil {
		t.Fatal(err)
	}

	var (
		id                                            uuid.UUID
		source, eventID, typ, actorType, actorID, act string
		subject                                       uuid.UUID
		outcome, reason, request, traceID             *string
		eventTime                                     time.Time
		canonical                                     []byte
	)
	if err := d.Superuser(t).QueryRow(context.Background(), `
		SELECT id, source, event_id, type, event_time, subject_agent_id, actor_type, actor_id, action, outcome,
		       reason, request_id, trace_id, canonical
		FROM whitetower.audit_events`).Scan(&id, &source, &eventID, &typ, &eventTime, &subject, &actorType, &actorID,
		&act, &outcome, &reason, &request, &traceID, &canonical); err != nil {
		t.Fatal(err)
	}
	if id.Version() != 7 || eventID != id.String() || source != "/core" || typ != "whitetower.agent.created.v1" ||
		!eventTime.Equal(epoch.Add(345*time.Millisecond)) || subject.String() != agent || actorType != "human" ||
		actorID != olivia || act != "agent.created" || outcome != nil || reason != nil ||
		request == nil || *request != requestID || traceID == nil || *traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("columns: %v %s %s %s %v %s %s %s %s %v %v %v %v", id, source, eventID, typ, eventTime, subject,
			actorType, actorID, act, outcome, reason, request, traceID)
	}

	// The stored bytes are the event's canonical JSON, which says what the
	// columns say.
	if again, err := jcs.Transform(canonical); err != nil || !bytes.Equal(again, canonical) {
		t.Fatalf("not canonical JSON (RFC 8785): %s", canonical)
	}
	var event map[string]any
	if err := json.Unmarshal(canonical, &event); err != nil {
		t.Fatal(err)
	}
	for member, want := range map[string]any{
		"specversion": "1.0", "id": id.String(), "source": "/core", "type": "whitetower.agent.created.v1",
		"time": "2026-10-09T12:00:00.345Z", "subject": agent, "datacontenttype": "application/json",
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "wtrequestid": requestID,
	} {
		if event[member] != want {
			t.Errorf("%s: %v, want %v", member, event[member], want)
		}
	}
	if data, _ := json.Marshal(event["data"]); !strings.Contains(string(data), `"actor":{"id":"`+olivia+`","type":"human"}`) {
		t.Errorf("data %s", data)
	}

	// It waits for the sealer.
	var queued uuid.UUID
	if err := d.Superuser(t).QueryRow(context.Background(), "SELECT audit_id FROM whitetower.audit_unsealed").Scan(&queued); err != nil || queued != id {
		t.Fatalf("queue: %v %v", queued, err)
	}
}

// Security test ST-09: a domain operation whose audit write fails is rolled
// back entirely, whether the event is invalid or the database refuses it.
func TestAFailedAuditWriteRollsTheChangeBack(t *testing.T) {
	d, pool, w := setup(t)
	ctx := context.Background()
	refused := created()
	refused.Data.(map[string]any)["email"] = "olivia@example.org"
	change := func(name string, e audit.Event) error {
		return pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			if _, err := tx.Exec(ctx, "INSERT INTO whitetower.job_state (name) VALUES ($1)", name); err != nil {
				return err
			}
			return w.Record(ctx, tx, e)
		})
	}

	if err := change("invalid-event", refused); err == nil || !strings.Contains(err.Error(), "invalid data") {
		t.Fatalf("an invalid event: %v", err)
	}
	superuser := d.Superuser(t)
	for _, stmt := range []string{
		`CREATE FUNCTION whitetower.refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		 BEGIN RAISE EXCEPTION 'the audit log is unavailable'; END $$`,
		`CREATE TRIGGER refuse_audit BEFORE INSERT ON whitetower.audit_events
		 FOR EACH ROW EXECUTE FUNCTION whitetower.refuse_audit()`,
	} {
		if _, err := superuser.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := change("refused-event", created()); err == nil || !strings.Contains(err.Error(), "the audit log is unavailable") {
		t.Fatalf("an event the database refuses: %v", err)
	}

	var changes, stored, queued int
	if err := superuser.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM whitetower.job_state), (SELECT count(*) FROM whitetower.audit_events),
		(SELECT count(*) FROM whitetower.audit_unsealed)`).Scan(&changes, &stored, &queued); err != nil {
		t.Fatal(err)
	}
	if changes != 0 || stored != 0 || queued != 0 {
		t.Fatalf("%d changes, %d events and %d queued survived their failed transactions", changes, stored, queued)
	}
}

func TestRecordRefusesWhatTheCoreDoesNotEmit(t *testing.T) {
	_, pool, w := setup(t)
	ctx := context.Background()
	noSubject := created()
	noSubject.Subject = ""
	decision := audit.Event{Type: "whitetower.decision.made.v1", Subject: agent, Data: map[string]any{
		"decision": "allow", "reason": "policy.permit", "action": "tool.invoke",
		"resource": map[string]any{"type": "tool", "id": "send_email"}, "environment": "production",
		"policies": []string{"0192f1c2-7a3b-7c4d-8e5f-000000000101"}, "bundle_version": 42, "state_version": 918,
		"evaluation_us": 310,
	}}
	for _, tt := range []struct {
		name  string
		event audit.Event
		want  string
	}{
		{"an enforcement point's event", decision, "the core does not emit this type"},
		{"a type outside the catalog", audit.Event{Type: "whitetower.agent.renamed.v1", Data: map[string]any{}}, "not a type of the event catalog"},
		{"no subject where it is required", noSubject, "the subject, its agent, is required"},
		{"data that does not encode", audit.Event{Type: "whitetower.agent.created.v1", Subject: agent, Data: func() {}}, "encoding the data"},
	} {
		if err := record(ctx, pool, w, tt.event); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want %q", tt.name, err, tt.want)
		}
	}
}

// The runtime role only adds events: it cannot change or remove one, and the
// sealer takes events off the queue without changing them.
func TestTheRuntimeRoleOnlyAddsEvents(t *testing.T) {
	_, pool, w := setup(t)
	ctx := context.Background()
	if err := record(ctx, pool, w, created()); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE whitetower.audit_events SET action = 'nothing'",
		"DELETE FROM whitetower.audit_events",
		"TRUNCATE whitetower.audit_events",
		"UPDATE whitetower.audit_unsealed SET ingested_at = now()",
	} {
		if _, err := pool.Exec(ctx, stmt); err == nil {
			t.Errorf("the runtime role could run %q", stmt)
		}
	}
	if tag, err := pool.Exec(ctx, "DELETE FROM whitetower.audit_unsealed"); err != nil || tag.RowsAffected() != 1 {
		t.Errorf("taking the event off the queue: %v %v", tag, err)
	}
}

// The criterion of plan P1-02, step 2: partitions exist three months ahead.
func TestThePartitionsJobKeepsThreeMonthsAhead(t *testing.T) {
	d, pool, _ := setup(t)
	ctx := context.Background()
	superuser := d.Superuser(t)
	month := time.Now().UTC()
	month = time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	last := month.AddDate(0, audit.MonthsAhead, 0).Format("2006_01")
	for _, table := range []string{"audit_events_" + last, "audit_event_ids_" + last} {
		if _, err := superuser.Exec(ctx, "DROP TABLE whitetower."+table); err != nil {
			t.Fatal(err)
		}
	}
	if err := audit.PartitionsJob(pool).Run(ctx); err != nil {
		t.Fatal(err)
	}
	for i := range audit.MonthsAhead + 1 {
		suffix := month.AddDate(0, i, 0).Format("2006_01")
		for _, table := range []string{"audit_events_" + suffix, "audit_event_ids_" + suffix} {
			var exists bool
			if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", "whitetower."+table).Scan(&exists); err != nil || !exists {
				t.Errorf("partition %s: %v %v", table, exists, err)
			}
		}
	}
}
