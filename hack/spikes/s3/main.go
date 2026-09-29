// Spike S3 (plan P0-05): can PostgreSQL with Merkle tree sealing sustain the
// audit load of NFR-07 within the sealing delay of NFR-09?
//
// One process against a PostgreSQL database whose whitetower schema it
// recreates from the real migration. It measures ingestion and sealing at
// 200 events per second sustained, 2,000 in a 60-second burst and 10,000 to
// find the headroom, signs checkpoints, grows the log with a bulk load,
// verifies the whole log, proves inclusion and consistency, drops a month of
// events as retention would, and compares the tree with a plain hash chain.
// See README.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/mod/sumdb/tlog"
)

// report is everything the run measured.
type report struct {
	Phases         []phaseResult    `json:"phases"`
	Checkpoints    int              `json:"checkpoints_signed"`
	BulkEvents     int              `json:"bulk_events"`
	BulkDuration   time.Duration    `json:"bulk_duration_ns"`
	BulkPerSecond  float64          `json:"bulk_events_per_second"`
	TreeSize       int64            `json:"tree_size"`
	Verify         verifyResult     `json:"verify"`
	VerifyTenM     time.Duration    `json:"verify_extrapolated_10m_ns"`
	Proofs         proofResult      `json:"proofs"`
	DropDuration   time.Duration    `json:"retention_drop_ns"`
	VerifyAfter    verifyResult     `json:"verify_after_retention"`
	ProofsAfter    proofResult      `json:"proofs_after_retention"`
	Sizes          map[string]int64 `json:"table_bytes"`
	BytesPerEvent  map[string]int64 `json:"bytes_per_event"`
	Chain          chainResult      `json:"hash_chain_comparison"`
	CheckpointTime summary          `json:"checkpoint_ms"`
	HashReadsSeal  int64            `json:"tree_hashes_read_from_database_while_sealing"`
	HashReadsTotal int64            `json:"tree_hashes_read_from_database"`
}

// phaseResult is one rate test.
type phaseResult struct {
	Name          string        `json:"name"`
	Rate          int           `json:"rate_per_second"`
	Duration      time.Duration `json:"duration_ns"`
	Elapsed       time.Duration `json:"publishing_took_ns"`
	Achieved      float64       `json:"achieved_per_second"`
	Events        int64         `json:"events"`
	Sealed        int64         `json:"sealed"`
	LateBatches   int64         `json:"late_batches"`
	IngestLatency summary       `json:"ingest_batch_ms"`
	SealingDelay  summary       `json:"sealing_delay_ms"`
	MaxBacklog    int64         `json:"max_queue"`
	DrainTime     time.Duration `json:"drain_after_end_ns"`
	SealTx        summary       `json:"sealing_transaction_ms"`
	SealBatchMean float64       `json:"sealing_batch_mean"`
	SealBatchMax  int           `json:"sealing_batch_max"`
	SealerBusy    float64       `json:"sealer_busy_fraction"`
	SealerRate    float64       `json:"sealed_per_second_of_sealing"`
	SealSteps     sealSteps     `json:"sealing_time_by_step"`
	SlowestSeal   sealSteps     `json:"slowest_sealing_transaction"`
	DBCheckpoints int64         `json:"database_checkpoints"` // PostgreSQL's own, which flush to disk
}

// dbCheckpoints counts PostgreSQL's checkpoints so far (version 17 or later),
// or returns 0.
func dbCheckpoints(ctx context.Context, pool *pgxpool.Pool) int64 {
	var n int64
	_ = pool.QueryRow(ctx, `SELECT num_timed + num_requested FROM pg_stat_checkpointer`).Scan(&n)
	return n
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "s3:", err)
		os.Exit(1)
	}
}

func run() error {
	adminDB := flag.String("db", "", "database URL of a superuser (the whitetower schema is recreated)")
	migration := flag.String("migration", "../../../internal/platform/db/migrations/00001_init.sql", "the core's migration")
	sustainedRate := flag.Int("sustained-rate", 200, "events per second, sustained (NFR-07)")
	sustained := flag.Duration("sustained", 3*time.Minute, "duration of the sustained phase")
	burstRate := flag.Int("burst-rate", 2000, "events per second in the burst (NFR-07)")
	burst := flag.Duration("burst", 60*time.Second, "duration of the burst")
	stressRate := flag.Int("stress-rate", 10_000, "events per second in the stress phase, which looks for the headroom")
	stress := flag.Duration("stress", 30*time.Second, "duration of the stress phase (0 skips it)")
	publishers := flag.Int("publishers", 20, "concurrent publishers")
	interval := flag.Duration("batch-interval", 250*time.Millisecond, "how often each publisher sends a batch")
	sealEvery := flag.Duration("seal-every", 200*time.Millisecond, "sealing round interval")
	sealBatch := flag.Int("seal-batch", 5000, "most events sealed per transaction")
	checkpointEvery := flag.Duration("checkpoint-every", 60*time.Second, "checkpoint interval (NFR-09)")
	bulk := flag.Int("bulk", 1_000_000, "total leaves to reach with the bulk load")
	past := flag.Int("past-events", 10_000, "events ingested in a past month, dropped by the retention test")
	verifyChunk := flag.Int64("verify-chunk", 10_000, "leaves read per query when verifying")
	shared := flag.Bool("shared-sources", false, "every publisher sends events from any source, instead of from its own agents")
	outFile := flag.String("out", "results.json", "where to write the raw results")
	flag.Parse()
	if *adminDB == "" {
		return errors.New("-db is required")
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	ctx := context.Background()

	const origin = "whitetower.spike/audit"
	signer, verifier, pub, err := checkpointKey(origin)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	pastMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -2, 0)
	runtimeURL, err := setupDB(ctx, *adminDB, *migration, pastMonth, pub, "checkpoint-s3")
	if err != nil {
		return err
	}
	cfg, err := pgxpool.ParseConfig(runtimeURL)
	if err != nil {
		return err
	}
	cfg.MaxConns = int32(*publishers + 5) //nolint:gosec // G115: a small flag value
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	g := newGenerator(1000)
	store := newHashStore(pool)
	s := &sealer{pool: pool, store: store, batch: *sealBatch, signer: signer, origin: origin, keyID: "checkpoint-s3"}
	rep := report{}
	var trees []tlog.Tree

	// 1. Events of a past month, which the retention test drops later.
	if _, err := s.bulkLoad(ctx, g, *past, pastMonth, pastMonth.AddDate(0, 1, 0), 5000); err != nil {
		return fmt.Errorf("past month: %w", err)
	}
	first, err := s.checkpoint(ctx)
	if err != nil {
		return err
	}
	trees = append(trees, first)
	log.Printf("past month: %d leaves, checkpoint at %d", *past, first.N)

	// 2. Sustained rate, the burst, then the stress phase, with the sealer
	// running.
	type phase struct {
		name string
		rate int
		d    time.Duration
	}
	phases := []phase{{"sustained", *sustainedRate, *sustained}, {"burst", *burstRate, *burst}}
	if *stress > 0 {
		phases = append(phases, phase{"stress", *stressRate, *stress})
	}
	for _, p := range phases {
		res, got, err := ratePhase(ctx, pool, g, s, p.name, p.rate, p.d, *publishers, *interval, *sealEvery, *checkpointEvery, *shared)
		if err != nil {
			return err
		}
		trees = append(trees, got...)
		rep.Phases = append(rep.Phases, res)
		log.Printf("%s: %d events at %.0f/s (target %d); sealing delay %s; queue max %d; drained %v after the end; sealer busy %.1f%%",
			p.name, res.Events, res.Achieved, p.rate, res.SealingDelay, res.MaxBacklog, res.DrainTime.Round(time.Millisecond), 100*res.SealerBusy)
	}

	// 3. Grow the log, then sign a checkpoint.
	if remaining := int64(*bulk) - s.size; remaining > 0 {
		d, err := s.bulkLoad(ctx, g, int(remaining), time.Now().UTC().Add(-time.Hour), time.Now().UTC(), 20000)
		if err != nil {
			return fmt.Errorf("bulk: %w", err)
		}
		rep.BulkEvents, rep.BulkDuration, rep.BulkPerSecond = int(remaining), d, float64(remaining)/d.Seconds()
		log.Printf("bulk: %d events in %v (%.0f/s)", remaining, d.Round(time.Millisecond), rep.BulkPerSecond)
	}
	latest, err := s.checkpoint(ctx)
	if err != nil {
		return err
	}
	trees = append(trees, latest)
	rep.TreeSize = latest.N

	// 4. Proofs against the latest checkpoint.
	rep.HashReadsSeal = store.reads.Load()
	if rep.Proofs, err = proveAndCheck(ctx, pool, store, latest, trees, 200); err != nil {
		return err
	}
	log.Printf("proofs: inclusion %s ms (%d hashes), consistency %s ms (%d hashes)",
		rep.Proofs.Inclusion, rep.Proofs.InclusionHashes, rep.Proofs.Consistency, rep.Proofs.ConsistencySize)

	// 5. Verify the whole log from the stored events.
	signed, err := latestCheckpoint(ctx, pool)
	if err != nil {
		return err
	}
	var leaves []tlog.Hash
	if rep.Verify, leaves, err = verifyLog(ctx, pool, signed, verifier, *verifyChunk); err != nil {
		return err
	}
	rep.VerifyTenM = time.Duration(float64(rep.Verify.Duration) * 10_000_000 / float64(rep.Verify.Leaves))
	log.Printf("verify: %d leaves in %v (%.0f/s; reading %v at %.0f MB/s, hashing %v), root matches: %v, mismatches: %d",
		rep.Verify.Leaves, rep.Verify.Duration.Round(time.Millisecond), rep.Verify.PerSecond, rep.Verify.ReadTime.Round(time.Millisecond),
		rep.Verify.ReadMBPerSecond, rep.Verify.HashTime.Round(time.Millisecond), rep.Verify.RootMatches, rep.Verify.Mismatches)
	rep.Chain = compareChain(leaves)

	// 6. Storage, before retention drops anything.
	if rep.Sizes, err = tableSizes(ctx, *adminDB); err != nil {
		return err
	}
	rep.BytesPerEvent = map[string]int64{}
	for t, b := range rep.Sizes {
		rep.BytesPerEvent[t] = b / rep.TreeSize
	}

	// 7. Retention: drop the past month; the rest still verifies and proves.
	if rep.DropDuration, err = dropMonth(ctx, *adminDB, pastMonth); err != nil {
		return err
	}
	if rep.VerifyAfter, _, err = verifyLog(ctx, pool, signed, verifier, *verifyChunk); err != nil {
		return err
	}
	if rep.ProofsAfter, err = proveAndCheck(ctx, pool, store, latest, trees, 50); err != nil {
		return err
	}
	log.Printf("retention: dropped in %v; %d leaves verified by content, %d by stored hash; root matches: %v",
		rep.DropDuration.Round(time.Millisecond), rep.VerifyAfter.WithContent, rep.VerifyAfter.HashOnly, rep.VerifyAfter.RootMatches)
	rep.Checkpoints = len(trees)
	rep.HashReadsTotal = store.reads.Load()
	s.mu.Lock()
	rep.CheckpointTime = summarize(s.cpTimes)
	s.mu.Unlock()

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outFile, out, 0o600); err != nil {
		return err
	}
	printReport(rep)
	return nil
}

// ratePhase publishes at a rate with the sealer running, waits until every
// event is sealed, and measures the sealing delay of the phase's events.
func ratePhase(ctx context.Context, pool *pgxpool.Pool, g *generator, s *sealer, name string, rate int, d time.Duration,
	publishers int, interval, sealEvery, checkpointEvery time.Duration, shared bool,
) (phaseResult, []tlog.Tree, error) {
	res := phaseResult{Name: name, Rate: rate, Duration: d}
	firstLeaf := s.size
	sctx, stop := context.WithCancel(ctx)
	trees := make(chan tlog.Tree, 100)
	done := make(chan struct{})
	s.mu.Lock()
	s.backlogs, s.txTimes, s.txSizes, s.txSteps = nil, nil, nil, nil
	s.mu.Unlock()
	checkpointsBefore := dbCheckpoints(ctx, pool)
	start := time.Now()
	go func() {
		s.run(sctx, sealEvery, checkpointEvery, trees)
		close(done)
	}()
	var st publishStats
	if err := publish(ctx, pool, g, rate, publishers, interval, d, shared, &st); err != nil {
		stop()
		<-done
		return res, nil, err
	}
	end := time.Now()
	res.Elapsed = end.Sub(start)
	// Let the sealer drain what is left.
	for {
		var queued int64
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM whitetower.audit_unsealed`).Scan(&queued); err != nil {
			stop()
			<-done
			return res, nil, err
		}
		if queued == 0 {
			break
		}
		if time.Since(end) > 5*time.Minute {
			stop()
			<-done
			return res, nil, fmt.Errorf("%s: %d events still unsealed 5 minutes after the end", name, queued)
		}
		time.Sleep(100 * time.Millisecond)
	}
	res.DrainTime = time.Since(end)
	stop()
	<-done
	close(trees)
	var got []tlog.Tree
	for t := range trees {
		got = append(got, t)
	}
	total := time.Since(start)
	res.DBCheckpoints = dbCheckpoints(ctx, pool) - checkpointsBefore
	res.Events, res.LateBatches, res.IngestLatency = st.Events, st.Lag, summarize(st.Latency)
	res.Achieved = float64(st.Events) / res.Elapsed.Seconds()
	res.Sealed = s.size - firstLeaf
	s.mu.Lock()
	if len(s.backlogs) > 0 {
		res.MaxBacklog = slices.Max(s.backlogs)
	}
	var busy time.Duration
	for _, d := range s.txTimes {
		busy += d
	}
	res.SealTx = summarize(s.txTimes)
	if len(s.txSizes) > 0 {
		res.SealBatchMean = float64(res.Sealed) / float64(len(s.txSizes))
		res.SealBatchMax = slices.Max(s.txSizes)
	}
	res.SealerBusy = busy.Seconds() / total.Seconds()
	res.SealerRate = float64(res.Sealed) / busy.Seconds()
	var slowest time.Duration
	for i, st := range s.txSteps {
		res.SealSteps.Claim += st.Claim
		res.SealSteps.Fetch += st.Fetch
		res.SealSteps.Hash += st.Hash
		res.SealSteps.Write += st.Write
		res.SealSteps.Commit += st.Commit
		if s.txTimes[i] > slowest {
			slowest, res.SlowestSeal = s.txTimes[i], st
		}
	}
	s.mu.Unlock()

	rows, err := pool.Query(ctx, `SELECT extract(epoch FROM sealed_at - ingested_at)::float8 FROM whitetower.audit_leaves
	                              WHERE leaf_index >= $1 AND leaf_index < $2`, firstLeaf, s.size)
	if err != nil {
		return res, got, err
	}
	var delays []time.Duration
	for rows.Next() {
		var sec float64
		if err := rows.Scan(&sec); err != nil {
			rows.Close()
			return res, got, err
		}
		delays = append(delays, time.Duration(sec*float64(time.Second)))
	}
	rows.Close()
	res.SealingDelay = summarize(delays)
	return res, got, rows.Err()
}

// summary is a latency distribution in milliseconds.
type summary struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

func summarize(ds []time.Duration) summary {
	if len(ds) == 0 {
		return summary{}
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	at := func(q float64) float64 {
		i := int(q*float64(len(s))+0.5) - 1
		i = max(0, min(i, len(s)-1))
		return float64(s[i].Microseconds()) / 1000
	}
	return summary{N: len(s), P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: float64(s[len(s)-1].Microseconds()) / 1000}
}

func (s summary) String() string {
	return fmt.Sprintf("%d | %.1f | %.1f | %.1f | %.1f", s.N, s.P50, s.P95, s.P99, s.Max)
}

func printReport(r report) {
	fmt.Println("\n## S3 results")
	fmt.Println("\n| Phase | Target | Achieved | Published / sealed | Late batches | Ingest batch p50 / p99, ms | Sealing delay p50 / p95 / p99 / max, ms | Max queue | Drained after the end |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, p := range r.Phases {
		fmt.Printf("| %s | %d/s for %v | %.0f/s | %d / %d | %d | %.1f / %.1f | %.0f / %.0f / %.0f / %.0f | %d | %v |\n",
			p.Name, p.Rate, p.Duration, p.Achieved, p.Events, p.Sealed, p.LateBatches, p.IngestLatency.P50, p.IngestLatency.P99,
			p.SealingDelay.P50, p.SealingDelay.P95, p.SealingDelay.P99, p.SealingDelay.Max, p.MaxBacklog, p.DrainTime.Round(time.Millisecond))
	}
	fmt.Println("\n| Phase | Sealing transactions | Events per transaction, mean / max | Transaction p50 / p99 / max, ms | Sealer busy | Sealed per second of sealing | Database checkpoints |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- |")
	for _, p := range r.Phases {
		fmt.Printf("| %s | %d | %.0f / %d | %.1f / %.1f / %.1f | %.1f%% | %.0f | %d |\n",
			p.Name, p.SealTx.N, p.SealBatchMean, p.SealBatchMax, p.SealTx.P50, p.SealTx.P99, p.SealTx.Max, 100*p.SealerBusy, p.SealerRate, p.DBCheckpoints)
	}
	fmt.Println("\n| Phase | Sealing time by step: claim / fetch / hash / write / commit, s | Slowest transaction, same steps, ms |")
	fmt.Println("| --- | --- | --- |")
	for _, p := range r.Phases {
		t, w := p.SealSteps, p.SlowestSeal
		fmt.Printf("| %s | %.2f / %.2f / %.2f / %.2f / %.2f | %d / %d / %d / %d / %d |\n", p.Name,
			t.Claim.Seconds(), t.Fetch.Seconds(), t.Hash.Seconds(), t.Write.Seconds(), t.Commit.Seconds(),
			w.Claim.Milliseconds(), w.Fetch.Milliseconds(), w.Hash.Milliseconds(), w.Write.Milliseconds(), w.Commit.Milliseconds())
	}
	fmt.Printf("\nCheckpoints signed: %d, taking %s ms (n | p50 | p95 | p99 | max). Bulk load: %d events in %v (%.0f per second). Tree size: %d.\n",
		r.Checkpoints, r.CheckpointTime, r.BulkEvents, r.BulkDuration.Round(time.Millisecond), r.BulkPerSecond, r.TreeSize)
	v := r.Verify
	fmt.Printf("\nFull verification: %d leaves in %v (%.0f per second), root matches the checkpoint: %v, content mismatches: %d.\n",
		v.Leaves, v.Duration.Round(time.Millisecond), v.PerSecond, v.RootMatches, v.Mismatches)
	fmt.Printf("Reading %d MB took %v (%.0f MB/s), hashing %v. Chunks of %d leaves: %s ms.\n",
		v.BytesRead/1_000_000, v.ReadTime.Round(time.Millisecond), v.ReadMBPerSecond, v.HashTime.Round(time.Millisecond), v.Chunk, v.ChunkTime)
	fmt.Printf("Extrapolated to 10 million leaves: %v.\n", r.VerifyTenM.Round(time.Second))
	fmt.Printf("\nProofs (ms: n | p50 | p95 | p99 | max): inclusion %s, %d hashes; consistency %s, %d hashes.\n",
		r.Proofs.Inclusion, r.Proofs.InclusionHashes, r.Proofs.Consistency, r.Proofs.ConsistencySize)
	a := r.VerifyAfter
	fmt.Printf("\nRetention: partitions dropped in %v. Afterwards: %d leaves verified from their events, %d from their stored hashes, root matches: %v; %d proofs verified.\n",
		r.DropDuration.Round(time.Millisecond), a.WithContent, a.HashOnly, a.RootMatches, r.ProofsAfter.Verified)
	fmt.Println("\n| Table | Bytes per event |")
	fmt.Println("| --- | --- |")
	for _, t := range []string{"audit_events", "audit_event_ids", "audit_leaves", "audit_tree_hashes"} {
		fmt.Printf("| %s | %d |\n", t, r.BytesPerEvent[t])
	}
	c := r.Chain
	fmt.Printf("\nHash chain against Merkle tree, %d leaves: computing %v against %v; worst inclusion proof %d hashes against %d; %.2f stored tree hashes per leaf against none.\n",
		c.Leaves, c.ChainCompute.Round(time.Millisecond), c.MerkleCompute.Round(time.Millisecond), c.ChainProofMax, c.MerkleProof, c.MerkleBytes)
	fmt.Printf("Tree hashes read from the database: %d while sealing, %d in all.\n", r.HashReadsSeal, r.HashReadsTotal)
}
