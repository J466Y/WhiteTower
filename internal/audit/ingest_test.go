package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
)

func setupIngester(t *testing.T, clk *clocktest.Fake) (*db.DB, *audit.Ingester) {
	t.Helper()
	d := dbtest.New(t)
	pool := d.Open(t)
	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	w := audit.NewWriter(cat, clk)
	ing := audit.NewIngester(audit.IngesterOptions{
		DB:            pool,
		Catalog:       cat,
		Writer:        w,
		Clock:         clk,
		RateLimit:     1000,
		RateBurst:     1000,
		MaxSealingLag: 5 * time.Second,
	})
	return pool, ing
}

func decisionEvent(source, eventID string, seq int64, agentID, decision, reason string) []byte {
	m := map[string]any{
		"specversion":     "1.0",
		"id":              eventID,
		"source":          source,
		"type":            "whitetower.decision.made.v1",
		"time":            "2026-10-14T10:00:00.000Z",
		"subject":         agentID,
		"datacontenttype": "application/json",
		"wtseq":           fmt.Sprint(seq),
		"traceparent":     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"data": map[string]any{
			"decision":       decision,
			"reason":         reason,
			"action":         "tool.invoke",
			"resource":       map[string]any{"type": "tool", "id": "read_invoice"},
			"environment":    "production",
			"policies":       []string{"0192f1c2-7a3b-7c4d-8e5f-000000000202"},
			"bundle_version": 1,
			"state_version":  1,
			"evaluation_us":  100,
		},
	}
	b, _ := json.Marshal(m)
	return b
}

func instanceStartedEvent(source, eventID string, seq int64, instanceID string) []byte {
	m := map[string]any{
		"specversion":     "1.0",
		"id":              eventID,
		"source":          source,
		"type":            "whitetower.instance.started.v1",
		"time":            "2026-10-14T10:00:00.000Z",
		"datacontenttype": "application/json",
		"wtseq":           fmt.Sprint(seq),
		"data": map[string]any{
			"instance_id":      instanceID,
			"module_id":        "mod-01",
			"version":          "1.0.0",
			"contract_version": "v1alpha1",
			"capabilities":     []string{"enforcement-point"},
		},
	}
	b, _ := json.Marshal(m)
	return b
}

// Security test ST-10: Ingestion refuses event types and sources outside the instance's own;
// per-instance rate limits and backpressure keep one flooding instance from slowing the others
func TestST10IngestionSecurityAndIsolation(t *testing.T) {
	clk := clocktest.New(epoch)
	_, ing := setupIngester(t, clk)
	ctx := context.Background()

	agentUUID := uuid.MustParse(agent)
	caller := audit.IngestCaller{
		InstanceID:    "inst-01",
		AllowedAgents: []uuid.UUID{agentUUID},
		AllowedTypes:  []string{"whitetower.decision.made.v1"},
	}

	validSource := fmt.Sprintf("/agents/%s/ep/ep-01", agent)

	t.Run("RefusesUndeclaredEventType", func(t *testing.T) {
		ev := instanceStartedEvent(validSource, "ev-01", 1, "inst-01")
		res, err := ing.Ingest(ctx, caller, [][]byte{ev})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Status != audit.StatusRejected {
			t.Fatalf("expected StatusRejected, got %+v", res)
		}
	})

	t.Run("RefusesCoreOnlyEventType", func(t *testing.T) {
		callerWithCore := caller
		callerWithCore.AllowedTypes = []string{"whitetower.agent.created.v1"}
		coreEv := created()
		dataJSON, _ := json.Marshal(coreEv.Data)
		raw, _ := json.Marshal(map[string]any{
			"specversion":     "1.0",
			"id":              "ev-core-01",
			"source":          validSource,
			"type":            "whitetower.agent.created.v1",
			"time":            "2026-10-14T10:00:00.000Z",
			"subject":         agent,
			"datacontenttype": "application/json",
			"wtseq":           "1",
			"data":            json.RawMessage(dataJSON),
		})
		res, err := ing.Ingest(ctx, callerWithCore, [][]byte{raw})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Status != audit.StatusRejected {
			t.Fatalf("expected StatusRejected for core type, got %+v", res)
		}
	})

	t.Run("RefusesSourceOutsideAllowedAgents", func(t *testing.T) {
		otherAgent := "0192f1c2-7a3b-7c4d-8e5f-000000000099"
		otherSource := fmt.Sprintf("/agents/%s/ep/ep-01", otherAgent)
		ev := decisionEvent(otherSource, "ev-02", 1, otherAgent, "allow", "policy.permit")
		res, err := ing.Ingest(ctx, caller, [][]byte{ev})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Status != audit.StatusRejected {
			t.Fatalf("expected StatusRejected for unauthorized agent source, got %+v", res)
		}
	})

	t.Run("RefusesSubjectMismatch", func(t *testing.T) {
		otherAgent := "0192f1c2-7a3b-7c4d-8e5f-000000000099"
		ev := decisionEvent(validSource, "ev-03", 1, otherAgent, "allow", "policy.permit")
		res, err := ing.Ingest(ctx, caller, [][]byte{ev})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Status != audit.StatusRejected {
			t.Fatalf("expected StatusRejected for subject mismatch, got %+v", res)
		}
	})

	t.Run("RefusesModuleSourceOutsideInstanceID", func(t *testing.T) {
		callerMod := audit.IngestCaller{
			InstanceID:    "inst-01",
			AllowedAgents: []uuid.UUID{},
			AllowedTypes:  []string{"whitetower.instance.started.v1"},
		}
		foreignSource := "/modules/mod-01/inst-99"
		ev := instanceStartedEvent(foreignSource, "ev-04", 1, "inst-99")
		res, err := ing.Ingest(ctx, callerMod, [][]byte{ev})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Status != audit.StatusRejected {
			t.Fatalf("expected StatusRejected for wrong module instance source, got %+v", res)
		}
	})

	t.Run("RefusesCoreSource", func(t *testing.T) {
		ev := decisionEvent("/core", "ev-05", 1, agent, "allow", "policy.permit")
		res, err := ing.Ingest(ctx, caller, [][]byte{ev})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Status != audit.StatusRejected {
			t.Fatalf("expected StatusRejected for /core source, got %+v", res)
		}
	})

	t.Run("PerInstanceRateLimiting", func(t *testing.T) {
		d := dbtest.New(t)
		pool := d.Open(t)
		cat, _ := audit.LoadCatalog(events.Files)
		w := audit.NewWriter(cat, clk)
		rateLimitedIng := audit.NewIngester(audit.IngesterOptions{
			DB:        pool,
			Catalog:   cat,
			Writer:    w,
			Clock:     clk,
			RateLimit: 1, // 1 per second
			RateBurst: 1,
		})

		ev := decisionEvent(validSource, "ev-rl-1", 1, agent, "allow", "policy.permit")
		res, err := rateLimitedIng.Ingest(ctx, caller, [][]byte{ev})
		if err != nil {
			t.Fatalf("first call failed: %v", err)
		}
		if res[0].Status != audit.StatusAccepted {
			t.Fatalf("expected accepted, got %v", res[0].Status)
		}

		// Second call immediately from same instance should be rate-limited.
		ev2 := decisionEvent(validSource, "ev-rl-2", 2, agent, "allow", "policy.permit")
		_, err = rateLimitedIng.Ingest(ctx, caller, [][]byte{ev2})
		if err == nil {
			t.Fatal("expected ErrRateLimited, got nil")
		}
		var rlErr *audit.ErrRateLimited
		if !errors.As(err, &rlErr) {
			t.Fatalf("expected ErrRateLimited, got %T: %v", err, err)
		}

		// Another instance is not affected (isolation).
		caller2 := caller
		caller2.InstanceID = "inst-02"
		caller2Source := fmt.Sprintf("/agents/%s/ep/ep-02", agent)
		evOther := decisionEvent(caller2Source, "ev-rl-other", 1, agent, "allow", "policy.permit")
		resOther, err := rateLimitedIng.Ingest(ctx, caller2, [][]byte{evOther})
		if err != nil {
			t.Fatalf("other instance should not be rate-limited: %v", err)
		}
		if resOther[0].Status != audit.StatusAccepted {
			t.Fatalf("expected other instance accepted, got %v", resOther[0].Status)
		}
	})

	t.Run("BackpressureOnSealingLag", func(t *testing.T) {
		d := dbtest.New(t)
		pool := d.Open(t)
		cat, _ := audit.LoadCatalog(events.Files)
		w := audit.NewWriter(cat, clk)
		bpIng := audit.NewIngester(audit.IngesterOptions{
			DB:            pool,
			Catalog:       cat,
			Writer:        w,
			Clock:         clk,
			RateLimit:     1000,
			RateBurst:     1000,
			MaxSealingLag: 2 * time.Second,
		})

		// First, insert an unsealed event with timestamp in the past (> 2s ago).
		oldTime := clk.Now().Add(-5 * time.Second)
		oldAuditID, _ := uuid.NewV7()
		if err := pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO whitetower.audit_unsealed (audit_id, ingested_at) VALUES ($1, $2)`, oldAuditID, oldTime)
			return err
		}); err != nil {
			t.Fatal(err)
		}

		ev := decisionEvent(validSource, "ev-bp-1", 1, agent, "allow", "policy.permit")
		_, err := bpIng.Ingest(ctx, caller, [][]byte{ev})
		if err == nil {
			t.Fatal("expected ErrResourceExhausted under lag backpressure, got nil")
		}
		var resExErr *audit.ErrResourceExhausted
		if !errors.As(err, &resExErr) {
			t.Fatalf("expected ErrResourceExhausted, got %T: %v", err, err)
		}
	})
}

func TestIngestBatchProcessing(t *testing.T) {
	clk := clocktest.New(epoch)
	pool, ing := setupIngester(t, clk)
	ctx := context.Background()

	agentUUID := uuid.MustParse(agent)
	caller := audit.IngestCaller{
		InstanceID:    "inst-01",
		AllowedAgents: []uuid.UUID{agentUUID},
		AllowedTypes:  []string{"whitetower.decision.made.v1"},
	}
	src := fmt.Sprintf("/agents/%s/ep/ep-01", agent)

	t.Run("AcceptsValidEventsAndDetectsGaps", func(t *testing.T) {
		// Event with seq 1 (expected 1, no gap)
		ev1 := decisionEvent(src, "ev-seq-1", 1, agent, "allow", "policy.permit")
		// Event with seq 4 (gap: expected 2, received 4, gap_size 2)
		ev4 := decisionEvent(src, "ev-seq-4", 4, agent, "deny", "policy.forbid")

		res, err := ing.Ingest(ctx, caller, [][]byte{ev1, ev4})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].Status != audit.StatusAccepted || res[1].Status != audit.StatusAccepted {
			t.Fatalf("expected both accepted, got %+v", res)
		}

		// Verify gap event was recorded in audit_events.
		var gapCount int
		var gapSource string
		var gapExpected, gapReceived, gapSize int64
		err = pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			row := tx.QueryRow(ctx, `SELECT count(*),
			  (convert_from(canonical, 'UTF-8')::jsonb->'data'->>'source'),
			  (convert_from(canonical, 'UTF-8')::jsonb->'data'->>'expected_seq')::bigint,
			  (convert_from(canonical, 'UTF-8')::jsonb->'data'->>'received_seq')::bigint,
			  (convert_from(canonical, 'UTF-8')::jsonb->'data'->>'gap_size')::bigint
			  FROM whitetower.audit_events
			  WHERE type = 'whitetower.audit.gap_detected.v1'
			  GROUP BY canonical`)
			return row.Scan(&gapCount, &gapSource, &gapExpected, &gapReceived, &gapSize)
		})
		if err != nil {
			t.Fatalf("querying gap event: %v", err)
		}
		if gapSource != src || gapExpected != 2 || gapReceived != 4 || gapSize != 2 {
			t.Fatalf("unexpected gap event content: src=%s expected=%d received=%d size=%d",
				gapSource, gapExpected, gapReceived, gapSize)
		}
	})

	t.Run("HandlesDuplicates", func(t *testing.T) {
		// Resend ev-seq-1: should be duplicate.
		ev1 := decisionEvent(src, "ev-seq-1", 1, agent, "allow", "policy.permit")
		// In-batch duplicate: two identical events in the same batch.
		evNewA := decisionEvent(src, "ev-seq-5", 5, agent, "allow", "policy.permit")
		evNewB := decisionEvent(src, "ev-seq-5", 5, agent, "allow", "policy.permit")

		res, err := ing.Ingest(ctx, caller, [][]byte{ev1, evNewA, evNewB})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 3 {
			t.Fatalf("expected 3 results, got %d", len(res))
		}
		if res[0].Status != audit.StatusDuplicate {
			t.Errorf("expected res[0] duplicate, got %v", res[0].Status)
		}
		if res[1].Status != audit.StatusAccepted {
			t.Errorf("expected res[1] accepted, got %v", res[1].Status)
		}
		if res[2].Status != audit.StatusDuplicate {
			t.Errorf("expected res[2] duplicate, got %v", res[2].Status)
		}
	})

	t.Run("HandlesOutOfOrderDelivery", func(t *testing.T) {
		// Current max sequence seen is 5.
		// Event with seq 3 arrives (out of order, was part of earlier gap).
		ev3 := decisionEvent(src, "ev-seq-3", 3, agent, "allow", "policy.permit")
		res, err := ing.Ingest(ctx, caller, [][]byte{ev3})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Status != audit.StatusAccepted {
			t.Fatalf("expected accepted for out of order event, got %+v", res)
		}

		// Sequence in DB should still be at least 5.
		var lastSeq int64
		err = pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			return tx.QueryRow(ctx, `SELECT last_seq FROM whitetower.audit_source_sequences WHERE source = $1`, src).Scan(&lastSeq)
		})
		if err != nil {
			t.Fatal(err)
		}
		if lastSeq != 5 {
			t.Fatalf("expected lastSeq 5, got %d", lastSeq)
		}
	})

	t.Run("ConcurrentBatchesDoNotDeadlock", func(t *testing.T) {
		srcA := fmt.Sprintf("/agents/%s/ep/ep-a", agent)
		srcB := fmt.Sprintf("/agents/%s/ep/ep-b", agent)

		var wg sync.WaitGroup
		const callers = 8
		errs := make([]error, callers)

		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				// Odd goroutines send B then A; even goroutines send A then B.
				var batch [][]byte
				if idx%2 == 0 {
					batch = [][]byte{
						decisionEvent(srcA, fmt.Sprintf("ev-conc-a-%d", idx), int64(idx+1), agent, "allow", "policy.permit"),
						decisionEvent(srcB, fmt.Sprintf("ev-conc-b-%d", idx), int64(idx+1), agent, "allow", "policy.permit"),
					}
				} else {
					batch = [][]byte{
						decisionEvent(srcB, fmt.Sprintf("ev-conc-b-%d", idx), int64(idx+1), agent, "allow", "policy.permit"),
						decisionEvent(srcA, fmt.Sprintf("ev-conc-a-%d", idx), int64(idx+1), agent, "allow", "policy.permit"),
					}
				}
				_, errs[idx] = ing.Ingest(ctx, caller, batch)
			}(i)
		}
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("caller %d failed with error (possible deadlock/failure): %v", i, err)
			}
		}
	})
}
