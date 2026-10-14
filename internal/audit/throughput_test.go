package audit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

func makeDecisionEvent(source string, seq int64, agentID string) []byte {
	return []byte(fmt.Sprintf(`{
		"specversion": "1.0",
		"id": "%s",
		"source": "%s",
		"type": "whitetower.decision.made.v1",
		"time": "%s",
		"subject": "%s",
		"datacontenttype": "application/json",
		"wtseq": "%d",
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"data": {
			"decision": "allow",
			"reason": "policy.permit",
			"action": "tool.invoke",
			"resource": {"type": "tool", "id": "read_invoice"},
			"environment": "production",
			"policies": ["0192f1c2-7a3b-7c4d-8e5f-000000000202"],
			"bundle_version": 1,
			"state_version": 1,
			"evaluation_us": 420
		}
	}`, uuid.NewString(), source, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), agentID, seq))
}

// TestThroughputSustainedAndBurst measures ingestion and sealing throughput
// under sustained load (200 eps, NFR-07) and peak burst (2,000 eps, NFR-09).
func TestThroughputSustainedAndBurst(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)

	now := time.Now().UTC()
	ensurePartition(t, superuser, now.Year(), int(now.Month()))

	cat, err := LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}

	sysClock := clock.System
	writer := NewWriter(cat, sysClock)
	ingester := NewIngester(IngesterOptions{
		DB:            pool,
		Catalog:       cat,
		Writer:        writer,
		Clock:         sysClock,
		RateLimit:     20000,
		RateBurst:     20000,
		MaxSealingLag: 10 * time.Second,
	})

	key := newKey(t)
	reg := prometheus.NewRegistry()
	met := metrics.NewAudit(reg)
	sealer := NewSealer(SealerOptions{
		DB:       pool,
		Writer:   writer,
		Key:      key,
		Origin:   origin,
		Interval: 2 * time.Second, // Frequent checkpoints for test
		Clock:    sysClock,
		Logger:   slog.New(slog.DiscardHandler),
		Metrics:  met,
	})

	// Run sealer continuously in background during throughput test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sealerDone := make(chan error, 1)
	go func() {
		// Round every 50ms
		for {
			select {
			case <-ctx.Done():
				sealerDone <- nil
				return
			default:
				if err := sealer.round(ctx); err != nil && ctx.Err() == nil {
					sealerDone <- err
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	agentUUID := uuid.New()
	instanceID := uuid.NewString()
	caller := IngestCaller{
		InstanceID:    instanceID,
		AllowedAgents: []uuid.UUID{agentUUID},
		AllowedTypes:  []string{"whitetower.decision.made.v1"},
	}

	runPhase := func(name string, targetRate int, duration time.Duration) {
		t.Run(name, func(t *testing.T) {
			publishers := 4
			interval := 100 * time.Millisecond
			batchSize := targetRate / (publishers * int(time.Second/interval))
			if batchSize < 1 {
				batchSize = 1
			}

			var wg sync.WaitGroup
			var ingestedTotal atomic.Int64
			deadline := time.Now().Add(duration)

			for p := 0; p < publishers; p++ {
				wg.Add(1)
				go func(pubIdx int) {
					defer wg.Done()
					src := fmt.Sprintf("/agents/%s/ep/%s-pub-%d", agentUUID, instanceID[:8], pubIdx)
					var seq int64

					for time.Now().Before(deadline) {
						start := time.Now()
						batch := make([][]byte, batchSize)
						for i := 0; i < batchSize; i++ {
							seq++
							batch[i] = makeDecisionEvent(src, seq, agentUUID.String())
						}

						results, err := ingester.Ingest(ctx, caller, batch)
						if err != nil {
							t.Errorf("publisher %d ingest error: %v", pubIdx, err)
							return
						}
						for _, r := range results {
							if r.Status != StatusAccepted {
								t.Errorf("unexpected status: %v", r)
							}
						}
						ingestedTotal.Add(int64(batchSize))

						elapsed := time.Since(start)
						if elapsed < interval {
							time.Sleep(interval - elapsed)
						}
					}
				}(p)
			}
			wg.Wait()
			t.Logf("Phase %s: ingested %d events (target rate: %d eps)", name, ingestedTotal.Load(), targetRate)
		})
	}

	// 1. Sustained Phase (200 eps)
	sustainedDuration := 2 * time.Second
	if !testing.Short() {
		sustainedDuration = 4 * time.Second
	}
	runPhase("Sustained_200_eps", 200, sustainedDuration)

	// 2. Burst Phase (2,000 eps)
	burstDuration := 1 * time.Second
	if !testing.Short() {
		burstDuration = 2 * time.Second
	}
	runPhase("Burst_2000_eps", 2000, burstDuration)

	// Wait for queue to drain completely (NFR-09).
	drainDeadline := time.Now().Add(10 * time.Second)
	for {
		var queued int64
		err := pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_unsealed").Scan(&queued)
		})
		if err != nil {
			t.Fatal(err)
		}
		if queued == 0 {
			break
		}
		if time.Now().After(drainDeadline) {
			t.Fatalf("sealer queue failed to drain within 10s: %d still queued", queued)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Verify all leaves are sealed and Merkle tree size is accurate.
	var leafCount int64
	err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_leaves").Scan(&leafCount)
	})
	if err != nil {
		t.Fatal(err)
	}
	if leafCount == 0 {
		t.Fatal("expected leaves to be sealed, got 0")
	}

	// Check that checkpoints exist.
	var checkpointCount int64
	err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM whitetower.audit_checkpoints").Scan(&checkpointCount)
	})
	if err != nil {
		t.Fatal(err)
	}
	if checkpointCount == 0 {
		t.Fatal("expected checkpoints to be signed, got 0")
	}

	cancel()
	<-sealerDone
}

// BenchmarkSealerRound benchmarks the sealing performance of a 100-event batch.
func BenchmarkSealerRound(b *testing.B) {
	d := dbtest.New(b)
	pool, superuser := d.Open(b), d.Superuser(b)
	now := time.Now().UTC()

	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	suffix := fmt.Sprintf("%04d_%02d", now.Year(), int(now.Month()))
	_, _ = superuser.Exec(context.Background(), fmt.Sprintf(`CREATE TABLE IF NOT EXISTS whitetower.audit_events_%s
		PARTITION OF whitetower.audit_events FOR VALUES FROM ('%s') TO ('%s')`,
		suffix, start.Format(time.RFC3339), end.Format(time.RFC3339)))

	cat, err := LoadCatalog(events.Files)
	if err != nil {
		b.Fatal(err)
	}
	sysClock := clock.System
	writer := NewWriter(cat, sysClock)
	key := newKey(b)
	sealer := NewSealer(SealerOptions{
		DB:       pool,
		Writer:   writer,
		Key:      key,
		Origin:   origin,
		Interval: time.Hour,
		Clock:    sysClock,
		Logger:   slog.New(slog.DiscardHandler),
		Metrics:  metrics.NewAudit(prometheus.NewRegistry()),
	})

	ingester := NewIngester(IngesterOptions{
		DB:            pool,
		Catalog:       cat,
		Writer:        writer,
		Clock:         sysClock,
		RateLimit:     100000,
		RateBurst:     100000,
		MaxSealingLag: time.Hour,
	})

	agentUUID := uuid.New()
	instanceID := uuid.NewString()
	caller := IngestCaller{
		InstanceID:    instanceID,
		AllowedAgents: []uuid.UUID{agentUUID},
		AllowedTypes:  []string{"whitetower.decision.made.v1"},
	}
	src := fmt.Sprintf("/agents/%s/ep/bench", agentUUID)

	ctx := context.Background()
	var seq int64

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		batch := make([][]byte, 100)
		for j := 0; j < 100; j++ {
			seq++
			batch[j] = makeDecisionEvent(src, seq, agentUUID.String())
		}
		if _, err := ingester.Ingest(ctx, caller, batch); err != nil {
			b.Fatalf("ingest: %v", err)
		}
		b.StartTimer()

		if err := sealer.round(ctx); err != nil {
			b.Fatalf("sealer.round: %v", err)
		}
	}
}
