package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// memorySink records batches in memory for testing.
type memorySink struct {
	mu       sync.Mutex
	name     string
	batches  [][]auditdb.ExportLeavesRow
	failWith error
}

func newMemorySink(name string) *memorySink {
	return &memorySink{name: name}
}

func (m *memorySink) Name() string { return m.name }

func (m *memorySink) Export(_ context.Context, batch []auditdb.ExportLeavesRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWith != nil {
		return m.failWith
	}
	cpy := make([]auditdb.ExportLeavesRow, len(batch))
	copy(cpy, batch)
	m.batches = append(m.batches, cpy)
	return nil
}

func (m *memorySink) Close() error { return nil }

func (m *memorySink) events() []auditdb.ExportLeavesRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []auditdb.ExportLeavesRow
	for _, b := range m.batches {
		all = append(all, b...)
	}
	return all
}

func gatherLabeled(t *testing.T, reg *prometheus.Registry, name, label, value string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name {
			for _, m := range f.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == label && lp.GetValue() == value {
						return m.GetGauge().GetValue() + m.GetCounter().GetValue()
					}
				}
			}
		}
	}
	return -1
}

func sealAll(t *testing.T, s *Sealer) {
	t.Helper()
	if err := s.round(context.Background()); err != nil {
		t.Fatalf("sealer round failed: %v", err)
	}
}

func TestExporterShipsInIndexOrderAndPersistsCursor(t *testing.T) {
	pool := dbtest.New(t).Open(t)
	clk := clocktest.New(time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC))
	key := newKey(t)
	sealer := newTestSealer(t, pool, key, clk)

	// Record and seal 10 events.
	record(t, pool, sealer.writer, 10)
	sealAll(t, sealer.Sealer)

	sink := newMemorySink("test-sink")
	reg := prometheus.NewRegistry()
	auditMetrics := metrics.NewAudit(reg)

	exporter := NewExporter(ExporterOptions{
		DB:           pool,
		Sinks:        []Sink{sink},
		PollInterval: 100 * time.Millisecond,
		BatchSize:    4, // Batches of 4 to test multi-batch progression
		Clock:        clk,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics:      auditMetrics,
	})

	// Run exporter rounds until all are exported.
	ctx := context.Background()
	for {
		hasMore, err := exporter.round(ctx)
		if err != nil {
			t.Fatalf("round failed: %v", err)
		}
		if !hasMore {
			break
		}
	}

	exported := sink.events()
	if len(exported) != 10 {
		t.Fatalf("exported %d events, want 10", len(exported))
	}

	// Verify strict index order from 0 to 9.
	for i, ev := range exported {
		if ev.LeafIndex != int64(i) {
			t.Errorf("event at index %d has LeafIndex %d, want %d", i, ev.LeafIndex, i)
		}
	}

	// Verify persistent cursor in database.
	err := pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		c, err := auditdb.New(tx).GetExportCursor(ctx, "test-sink")
		if err != nil {
			return err
		}
		if c.LastLeafIndex != 9 {
			t.Errorf("cursor in db is %d, want 9", c.LastLeafIndex)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("check cursor in db: %v", err)
	}

	// Verify metrics.
	if v := gatherLabeled(t, reg, "whitetower_audit_exported_total", "sink", "test-sink"); v != 10 {
		t.Errorf("exported_total metric is %v, want 10", v)
	}
	if v := gatherLabeled(t, reg, "whitetower_audit_export_cursor_leaf_index", "sink", "test-sink"); v != 9 {
		t.Errorf("export_cursor_leaf_index metric is %v, want 9", v)
	}
	if v := gatherLabeled(t, reg, "whitetower_audit_export_lag", "sink", "test-sink"); v != 0 {
		t.Errorf("export_lag metric is %v, want 0", v)
	}
}

// TestExporterCoreRestartRecoveryNoSkippedEvents tests the acceptance criterion:
// "after a core restart, the collector has every event exactly once or more, and none is missing".
func TestExporterCoreRestartRecoveryNoSkippedEvents(t *testing.T) {
	pool := dbtest.New(t).Open(t)
	clk := clocktest.New(time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC))
	key := newKey(t)
	sealer := newTestSealer(t, pool, key, clk)

	// Step 1: Record and seal 5 events.
	record(t, pool, sealer.writer, 5)
	sealAll(t, sealer.Sealer)

	sink := newMemorySink("persistent-collector")
	reg1 := prometheus.NewRegistry()
	exporter1 := NewExporter(ExporterOptions{
		DB:           pool,
		Sinks:        []Sink{sink},
		PollInterval: 100 * time.Millisecond,
		BatchSize:    10,
		Clock:        clk,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics:      metrics.NewAudit(reg1),
	})

	ctx := context.Background()
	if _, err := exporter1.round(ctx); err != nil {
		t.Fatalf("exporter1 round failed: %v", err)
	}

	if len(sink.events()) != 5 {
		t.Fatalf("first run exported %d events, want 5", len(sink.events()))
	}

	// Step 2: Simulate core restart / crash. Exporter 1 stops.
	_ = exporter1.opts.Sinks[0].Close()

	// More events are ingested and sealed while exporter is stopped.
	record(t, pool, sealer.writer, 5)
	sealAll(t, sealer.Sealer)

	// Step 3: Core restarts. Fresh exporter connects to the same database.
	reg2 := prometheus.NewRegistry()
	exporter2 := NewExporter(ExporterOptions{
		DB:           pool,
		Sinks:        []Sink{sink}, // Collector continues receiving
		PollInterval: 100 * time.Millisecond,
		BatchSize:    10,
		Clock:        clk,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics:      metrics.NewAudit(reg2),
	})

	if _, err := exporter2.round(ctx); err != nil {
		t.Fatalf("exporter2 round failed: %v", err)
	}

	allExported := sink.events()
	var treeSize int64
	_ = pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		treeSize, err = auditdb.New(tx).TreeSize(ctx)
		return err
	})
	if len(allExported) != int(treeSize) {
		t.Fatalf("after restart total exported events is %d, want tree size %d", len(allExported), treeSize)
	}

	// Check that every event from 0 to treeSize-1 was received, with no missing events.
	seen := make(map[int64]int)
	for _, ev := range allExported {
		seen[ev.LeafIndex]++
	}
	for i := int64(0); i < treeSize; i++ {
		if seen[i] < 1 {
			t.Errorf("missing event at leaf index %d after core restart", i)
		}
	}
}

func TestExporterAtLeastOnceOnSinkFailure(t *testing.T) {
	pool := dbtest.New(t).Open(t)
	clk := clocktest.New(time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC))
	key := newKey(t)
	sealer := newTestSealer(t, pool, key, clk)

	record(t, pool, sealer.writer, 3)
	sealAll(t, sealer.Sealer)

	sink := newMemorySink("flaky-sink")
	sink.failWith = errors.New("network connection refused")

	reg := prometheus.NewRegistry()
	m := metrics.NewAudit(reg)
	exporter := NewExporter(ExporterOptions{
		DB:           pool,
		Sinks:        []Sink{sink},
		PollInterval: 100 * time.Millisecond,
		BatchSize:    10,
		Clock:        clk,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics:      m,
	})

	ctx := context.Background()
	_, err := exporter.round(ctx)
	if err == nil {
		t.Fatal("expected exporter round to fail when sink fails")
	}

	// Verify cursor was NOT advanced in database.
	err = pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := auditdb.New(tx).GetExportCursor(ctx, "flaky-sink")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("cursor should not exist or be advanced on failure, got %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Heal the sink.
	sink.failWith = nil

	_, err = exporter.round(ctx)
	if err != nil {
		t.Fatalf("expected round to succeed after healing sink, got %v", err)
	}

	if len(sink.events()) != 3 {
		t.Fatalf("exported %d events after healing, want 3", len(sink.events()))
	}
}

func TestOTLPSinkExportProtobuf(t *testing.T) {
	pool := dbtest.New(t).Open(t)
	clk := clocktest.New(time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC))
	key := newKey(t)
	sealer := newTestSealer(t, pool, key, clk)

	// Record events and force a checkpoint.
	record(t, pool, sealer.writer, 5)
	sealAll(t, sealer.Sealer)

	// Advance clock past checkpoint interval to trigger checkpoint creation.
	clk.Advance(2 * time.Minute)
	record(t, pool, sealer.writer, 1)
	sealAll(t, sealer.Sealer)

	var receivedReqs []*collogspb.ExportLogsServiceRequest
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			http.Error(w, "want application/x-protobuf", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var req collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		receivedReqs = append(receivedReqs, &req)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	otlpSink, err := NewOTLPSink(OTLPSinkOptions{
		Endpoint: srv.URL,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new otlp sink: %v", err)
	}

	reg := prometheus.NewRegistry()
	exporter := NewExporter(ExporterOptions{
		DB:           pool,
		Sinks:        []Sink{otlpSink},
		PollInterval: 100 * time.Millisecond,
		BatchSize:    20,
		Clock:        clk,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics:      metrics.NewAudit(reg),
	})

	if _, err := exporter.round(context.Background()); err != nil {
		t.Fatalf("export round: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedReqs) == 0 {
		t.Fatal("no requests received by collector")
	}

	var totalRecords int
	foundCheckpoint := false
	for _, req := range receivedReqs {
		for _, rl := range req.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, rec := range sl.LogRecords {
					totalRecords++
					if rec.EventName == "whitetower.audit.checkpoint.v1" {
						foundCheckpoint = true
					}
					if rec.Body == nil || rec.Body.GetStringValue() == "" {
						t.Error("log record has empty body")
					}
					if len(rec.Attributes) == 0 {
						t.Error("log record has no attributes")
					}
				}
			}
		}
	}

	if totalRecords < 6 {
		t.Errorf("total log records %d, want at least 6", totalRecords)
	}
	if !foundCheckpoint {
		t.Error("expected checkpoint event to be exported as an ordinary event (AUD-06)")
	}
}

func TestJSONLSinkWithRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Create sink with tiny max size to force rotation.
	sink, err := NewJSONLSink(logPath, 1, 3) // 1 MB max size, 3 backups
	if err != nil {
		t.Fatalf("new jsonl sink: %v", err)
	}
	defer sink.Close()

	// Artificially set maxBytes to 200 bytes on rotatingWriter for testing rotation.
	sink.writer.maxBytes = 200

	batch1 := []auditdb.ExportLeavesRow{
		{
			LeafIndex: 0,
			Canonical: []byte(`{"id":"01","type":"whitetower.agent.created.v1","time":"2026-10-14T10:00:00Z"}`),
		},
		{
			LeafIndex: 1,
			Canonical: []byte(`{"id":"02","type":"whitetower.agent.created.v1","time":"2026-10-14T10:00:01Z"}`),
		},
	}

	if err := sink.Export(context.Background(), batch1); err != nil {
		t.Fatalf("export batch 1: %v", err)
	}

	batch2 := []auditdb.ExportLeavesRow{
		{
			LeafIndex: 2,
			Canonical: []byte(`{"id":"03","type":"whitetower.agent.created.v1","time":"2026-10-14T10:00:02Z"}`),
		},
		{
			LeafIndex: 3,
			Canonical: []byte(`{"id":"04","type":"whitetower.agent.created.v1","time":"2026-10-14T10:00:03Z"}`),
		},
	}

	if err := sink.Export(context.Background(), batch2); err != nil {
		t.Fatalf("export batch 2: %v", err)
	}

	// Verify rotated backup file exists.
	rotatedPath := logPath + ".1"
	if _, err := os.Stat(rotatedPath); err != nil {
		t.Errorf("expected rotated file %s to exist: %v", rotatedPath, err)
	}

	// Verify current file has valid JSON Lines.
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read current log: %v", err)
	}
	if len(content) == 0 {
		t.Error("current log file is empty")
	}
}

func TestPseudonymizationNFR20(t *testing.T) {
	key := []byte("secret-salt-123456789012345678901234")
	p := NewPseudonymizer(key)

	originalPrincipal := "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"
	pseudo1 := p.Pseudonymize(originalPrincipal)
	pseudo2 := p.Pseudonymize(originalPrincipal)

	// Deterministic
	if pseudo1 != pseudo2 {
		t.Fatalf("pseudonymize is not deterministic: %q != %q", pseudo1, pseudo2)
	}
	// Different from original
	if pseudo1 == originalPrincipal {
		t.Fatalf("pseudonymize did not change the principal ID")
	}
	// Must be a valid UUID
	if _, err := uuid.Parse(pseudo1); err != nil {
		t.Fatalf("pseudonym is not a valid UUID: %v", err)
	}

	// Different key produces different pseudonymous ID
	otherP := NewPseudonymizer([]byte("different-key-1234567890123456789"))
	if otherP.Pseudonymize(originalPrincipal) == pseudo1 {
		t.Fatal("different key produced the same pseudonymous ID")
	}

	// Event canonical JSON replacement
	eventJSON := []byte(`{
		"specversion": "1.0",
		"id": "0192f1c2-7a3b-7c4d-8e5f-111111111111",
		"source": "/core",
		"type": "whitetower.agent.created.v1",
		"time": "2026-10-14T10:00:00Z",
		"data": {
			"slug": "test-agent",
			"actor": {
				"type": "human",
				"id": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"
			}
		}
	}`)

	canon, err := p.PseudonymizeCanonical(eventJSON)
	if err != nil {
		t.Fatalf("pseudonymize canonical: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(canon, &parsed); err != nil {
		t.Fatalf("unmarshal pseudonymized canonical: %v", err)
	}

	data := parsed["data"].(map[string]any)
	actor := data["actor"].(map[string]any)
	if actor["id"] != pseudo1 {
		t.Errorf("actor id is %v, want %v", actor["id"], pseudo1)
	}
	if actor["type"] != "human" {
		t.Errorf("actor type changed to %v", actor["type"])
	}
}

func TestExporterPseudonymizationOnExport(t *testing.T) {
	pool := dbtest.New(t).Open(t)
	clk := clocktest.New(time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC))
	key := newKey(t)
	sealer := newTestSealer(t, pool, key, clk)

	// Record an agent creation event with human actor.
	originalHumanID := "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"
	err := pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		return sealer.writer.Record(ctx, tx, Event{
			Type:    "whitetower.agent.created.v1",
			Subject: "0192f1c2-7a3b-7c4d-8e5f-111111111111",
			Data: map[string]any{
				"slug":          "my-agent",
				"kind":          "in_house",
				"risk_tier":     "low",
				"use_case_id":   "0192f1c2-7a3b-7c4d-8e5f-000000000010",
				"primary_owner": originalHumanID,
				"actor": map[string]any{
					"type": "human",
					"id":   originalHumanID,
				},
				"state_version": 1,
			},
		})
	})
	if err != nil {
		t.Fatalf("record event: %v", err)
	}
	sealAll(t, sealer.Sealer)

	sink := newMemorySink("pseudo-sink")
	reg := prometheus.NewRegistry()
	secretKey := []byte("salt-for-export-testing-123456789")

	exporter := NewExporter(ExporterOptions{
		DB:           pool,
		Sinks:        []Sink{sink},
		PollInterval: 100 * time.Millisecond,
		BatchSize:    10,
		PseudonymKey: secretKey,
		Clock:        clk,
		Logger:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics:      metrics.NewAudit(reg),
	})

	if _, err := exporter.round(context.Background()); err != nil {
		t.Fatalf("export round: %v", err)
	}

	exported := sink.events()
	if len(exported) != 1 {
		t.Fatalf("exported %d events, want 1", len(exported))
	}

	ev := exported[0]
	// 1. Exported metadata actor ID is pseudonymized.
	if ev.ActorID == nil || *ev.ActorID == originalHumanID {
		t.Fatalf("exported ActorID was not pseudonymized: %v", ev.ActorID)
	}
	if _, err := uuid.Parse(*ev.ActorID); err != nil {
		t.Fatalf("pseudonymized ActorID is not a valid UUID: %v", err)
	}

	// 2. Exported canonical JSON has pseudonymized actor ID.
	var parsed map[string]any
	if err := json.Unmarshal(ev.Canonical, &parsed); err != nil {
		t.Fatalf("unmarshal canonical: %v", err)
	}
	data := parsed["data"].(map[string]any)
	actor := data["actor"].(map[string]any)
	if actor["id"] != *ev.ActorID {
		t.Errorf("actor id in canonical %v != exported ActorID %v", actor["id"], *ev.ActorID)
	}

	// 3. Database retains genuine unpseudonymized actor ID.
	err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		var dbActorID *string
		err := tx.QueryRow(ctx, "SELECT actor_id FROM whitetower.audit_events WHERE id = $1", ev.ID).Scan(&dbActorID)
		if err != nil {
			return err
		}
		if dbActorID == nil || *dbActorID != originalHumanID {
			t.Errorf("database actor_id %v, want genuine %v", dbActorID, originalHumanID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("query db: %v", err)
	}
}
