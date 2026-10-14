package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

func ensurePartition(t *testing.T, superuser *pgx.Conn, year, month int) {
	t.Helper()
	start := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	suffix := fmt.Sprintf("%04d_%02d", year, month)

	sqlEvents := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS whitetower.audit_events_%s
		PARTITION OF whitetower.audit_events
		FOR VALUES FROM ('%s') TO ('%s')`,
		suffix, start.Format(time.RFC3339), end.Format(time.RFC3339))
	if _, err := superuser.Exec(context.Background(), sqlEvents); err != nil {
		t.Fatalf("ensure events partition %s: %v", suffix, err)
	}

	sqlIDs := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS whitetower.audit_event_ids_%s
		PARTITION OF whitetower.audit_event_ids
		FOR VALUES FROM ('%s') TO ('%s')`,
		suffix, start.Format("2006-01-02"), end.Format("2006-01-02"))
	if _, err := superuser.Exec(context.Background(), sqlIDs); err != nil {
		t.Fatalf("ensure ids partition %s: %v", suffix, err)
	}
}

func recordInMonth(t *testing.T, pool *db.DB, w *Writer, n int) {
	t.Helper()
	for range n {
		agentID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			return w.Record(ctx, tx, Event{
				Type:    "whitetower.agent.created.v1",
				Subject: agentID.String(),
				Data: map[string]any{
					"slug":          "retention-test-agent",
					"kind":          "in_house",
					"risk_tier":     "high",
					"use_case_id":   "0192f1c2-7a3b-7c4d-8e5f-000000000010",
					"primary_owner": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
					"actor":         map[string]any{"type": "human", "id": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"},
					"state_version": 1,
				},
			})
		})
		if err != nil {
			t.Fatalf("record event: %v", err)
		}
	}
}

func recordInPastMonth(t *testing.T, superuser *pgx.Conn, at time.Time, n int) {
	t.Helper()
	cat, err := LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for range n {
		agentID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		id, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(map[string]any{
			"slug":          "retention-test-agent",
			"kind":          "in_house",
			"risk_tier":     "high",
			"use_case_id":   "0192f1c2-7a3b-7c4d-8e5f-000000000010",
			"primary_owner": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
			"actor":         map[string]any{"type": "human", "id": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"},
			"state_version": 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		env := envelope{
			SpecVersion:     "1.0",
			ID:              id.String(),
			Source:          "/core",
			Type:            "whitetower.agent.created.v1",
			Time:            at.Format(timeLayout),
			Subject:         agentID.String(),
			DataContentType: "application/json",
			Data:            data,
		}
		canonical, decoded, err := canonicalize(env)
		if err != nil {
			t.Fatal(err)
		}
		typ, err := cat.check(decoded)
		if err != nil {
			t.Fatal(err)
		}
		f, err := factsOf(typ, decoded)
		if err != nil {
			t.Fatal(err)
		}
		sql := `WITH stored AS (
			INSERT INTO whitetower.audit_events (
				id, ingested_at, source, event_id, type, event_time, subject_agent_id,
				actor_type, actor_id, action, outcome, reason, canonical
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
			) RETURNING id, ingested_at
		)
		INSERT INTO whitetower.audit_unsealed (audit_id, ingested_at)
		SELECT id, ingested_at FROM stored;`
		subject, _ := uuid.Parse(agentID.String())
		_, err = superuser.Exec(ctx, sql,
			id, at, env.Source, env.ID, env.Type, at, subject,
			f.actorType, optional(f.actorID), f.action, optional(f.outcome), optional(f.reason), canonical,
		)
		if err != nil {
			t.Fatalf("insert past event: %v", err)
		}
	}
}

func TestRetentionDropsExpiredPartitionAndRecordsRange(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)

	// 1. Ingest events into audit_events_2025_01.
	past := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	clk := clocktest.New(past)
	ensurePartition(t, superuser, 2025, 1)

	key := newKey(t)
	sealer := newTestSealer(t, pool, key, clk)
	eventCount := 5
	recordInPastMonth(t, superuser, past, eventCount)

	// Seal events into Merkle tree.
	sealAll(t, sealer.Sealer)

	// 2. Advance clock to Oct 2026 (> 180 days after Jan 2025).
	clk.Advance(600 * 24 * time.Hour)
	now := clk.Now().UTC()
	ensurePartition(t, superuser, now.Year(), int(now.Month()))

	reg := prometheus.NewRegistry()
	met := metrics.NewAudit(reg)

	// Run retention to drop partitions older than 180 days.
	dropped, err := DropExpiredPartitions(context.Background(), RetentionOptions{
		DB:      pool,
		Writer:  sealer.writer,
		Days:    180,
		Clock:   clk,
		Logger:  slog.Default(),
		Metrics: met,
	})
	if err != nil {
		t.Fatalf("DropExpiredPartitions: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("expected 1 partition dropped, got %d", dropped)
	}

	// 3. Verify partition table was dropped.
	var exists bool
	err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, "SELECT to_regclass('whitetower.audit_events_2025_01') IS NOT NULL").Scan(&exists)
	})
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("partition table whitetower.audit_events_2025_01 still exists after retention drop")
	}

	// 4. Verify audit_pruned_ranges recorded the range [0, eventCount).
	log := NewLog(pool)
	var ranges [][2]int64
	err = log.Pruned(context.Background(), func(from, to int64) error {
		ranges = append(ranges, [2]int64{from, to})
		return nil
	})
	if err != nil {
		t.Fatalf("log.Pruned: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected 1 pruned range, got %d: %v", len(ranges), ranges)
	}
	if ranges[0][0] != 0 || ranges[0][1] != int64(eventCount) {
		t.Fatalf("expected pruned range [0, %d), got [%d, %d)", eventCount, ranges[0][0], ranges[0][1])
	}

	// 5. Verify leaves and tree hashes remain in the database.
	var leafCount int
	err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_leaves").Scan(&leafCount)
	})
	if err != nil {
		t.Fatal(err)
	}
	if leafCount != eventCount {
		t.Fatalf("expected %d leaves in audit_leaves, got %d", eventCount, leafCount)
	}

	// 6. Verify whitetower.audit.partition_dropped.v1 event was recorded.
	var dropEventCount int
	err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_events WHERE type = 'whitetower.audit.partition_dropped.v1'").Scan(&dropEventCount)
	})
	if err != nil {
		t.Fatal(err)
	}
	if dropEventCount != 1 {
		t.Fatalf("expected 1 partition_dropped event in audit_events, got %d", dropEventCount)
	}

	// 7. Seal the partition_dropped event and ensure log continues to seal cleanly.
	sealAll(t, sealer.Sealer)
}

func TestRetentionRetainsActivePartitions(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	clk := clocktest.New(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	ensurePartition(t, superuser, 2026, 10)

	key := newKey(t)
	sealer := newTestSealer(t, pool, key, clk)
	recordInMonth(t, pool, sealer.writer, 3)

	dropped, err := DropExpiredPartitions(context.Background(), RetentionOptions{
		DB:     pool,
		Writer: sealer.writer,
		Days:   180,
		Clock:  clk,
		Logger: slog.Default(),
	})
	if err != nil {
		t.Fatalf("DropExpiredPartitions: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("expected 0 partitions dropped, got %d", dropped)
	}

	var exists bool
	err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, "SELECT to_regclass('whitetower.audit_events_2026_10') IS NOT NULL").Scan(&exists)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("active partition table was incorrectly dropped")
	}
}

func TestRetentionJobConfigured(t *testing.T) {
	job := RetentionJob(RetentionOptions{
		Days: 180,
	})
	if job.Name != "audit-retention" {
		t.Fatalf("expected job name 'audit-retention', got %q", job.Name)
	}
	if job.Schedule == nil {
		t.Fatal("expected non-nil schedule")
	}
}
