package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/jackc/pgx/v5/pgxpool"
)

// event is one audit event, as the core stores it.
type event struct {
	ID        string
	Source    string
	EventID   string
	Seq       int64
	Type      string
	Time      time.Time
	Agent     string
	Action    string
	Outcome   string
	Reason    string
	TraceID   string
	Canonical []byte
}

// generator produces decision events from many enforcement points, the bulk
// of what the audit log receives.
type generator struct {
	mu      sync.Mutex
	sources []string
	agents  []string
	seqs    map[string]int64
}

func newGenerator(sources int) *generator {
	g := &generator{seqs: map[string]int64{}}
	for range sources {
		agent := newUUID()
		g.agents = append(g.agents, agent)
		g.sources = append(g.sources, "/agents/"+agent+"/ep/"+newUUID()[:8])
	}
	return g
}

var tools = []string{"read_invoice", "send_email", "post_ledger", "search_documents", "create_ticket", "summarize"}

// next returns a decision event with its canonical JSON (RFC 8785), which is
// what the Merkle tree hashes. The event comes from a random source of one of
// `shards` equal shares of the sources: a publisher is a module instance, and
// publishes for its own agents.
func (g *generator) next(at time.Time, shard, shards int) (event, error) {
	per := len(g.sources) / shards
	i := shard*per + mathrand.IntN(per) //nolint:gosec // G404: test data needs no cryptographic randomness
	g.mu.Lock()
	g.seqs[g.sources[i]]++
	seq := g.seqs[g.sources[i]]
	g.mu.Unlock()
	tool := tools[mathrand.IntN(len(tools))] //nolint:gosec // G404: test data
	decision, reason := "allow", "policy.permit"
	if mathrand.IntN(10) == 0 { //nolint:gosec // G404: test data
		decision, reason = "deny", "policy.forbid"
	}
	e := event{
		ID: newUUID(), Source: g.sources[i], Seq: seq, Type: "whitetower.decision.made.v1", Time: at,
		Agent: g.agents[i], Action: "tool.invoke", Outcome: decision, Reason: reason, TraceID: randomHex(16),
	}
	e.EventID = e.ID
	cloudEvent := map[string]any{
		"specversion": "1.0", "id": e.EventID, "source": e.Source, "type": e.Type,
		"time": at.UTC().Format("2006-01-02T15:04:05.000Z"), "subject": e.Agent, "datacontenttype": "application/json",
		"wtseq": fmt.Sprint(seq), "traceparent": "00-" + e.TraceID + "-" + randomHex(8) + "-01",
		"data": map[string]any{
			"decision": decision, "reason": reason, "action": "tool.invoke",
			"resource": map[string]any{"type": "tool", "id": tool}, "environment": "production",
			"policies":       []string{"0192f1c2-7a3b-7c4d-8e5f-000000000202"},
			"bundle_version": 42, "state_version": 918, "evaluation_us": 310,
			"task_id":   "run-" + randomHex(4),
			"arguments": map[string]any{"names": []string{"to", "subject", "body"}},
		},
	}
	raw, err := json.Marshal(cloudEvent)
	if err != nil {
		return e, err
	}
	e.Canonical, err = jcs.Transform(raw)
	return e, err
}

// ingest stores a batch of events the way the core does (plan P1-02): de-
// duplication, the event, its source sequence and its place in the queue of
// unsealed events, all in one transaction.
func ingest(ctx context.Context, pool *pgxpool.Pool, batch []event) error {
	n := len(batch)
	ids, sources, eventIDs, seqs, types, times := make([]string, n), make([]string, n), make([]string, n), make([]int64, n), make([]string, n), make([]time.Time, n)
	agents, actions, outcomes, reasons, traces, canonical := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([][]byte, n)
	for i, e := range batch {
		ids[i], sources[i], eventIDs[i], seqs[i], types[i], times[i] = e.ID, e.Source, e.EventID, e.Seq, e.Type, e.Time
		agents[i], actions[i], outcomes[i], reasons[i], traces[i], canonical[i] = e.Agent, e.Action, e.Outcome, e.Reason, e.TraceID, e.Canonical
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// De-duplication: events already seen this month are skipped.
	rows, err := tx.Query(ctx, `INSERT INTO whitetower.audit_event_ids (source, event_id, ingest_month, audit_id)
	                            SELECT s, e, date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date, i
	                            FROM unnest($1::text[], $2::text[], $3::uuid[]) AS t(s, e, i)
	                            ON CONFLICT DO NOTHING RETURNING audit_id::text`, sources, eventIDs, ids)
	if err != nil {
		return err
	}
	fresh := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		fresh[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(fresh) != n {
		return fmt.Errorf("%d of %d events were duplicates", n-len(fresh), n)
	}
	// The events, and their place in the queue of unsealed events, in one
	// statement.
	if _, err := tx.Exec(ctx, `WITH stored AS (
	                             INSERT INTO whitetower.audit_events (id, ingested_at, source, event_id, source_seq, type, event_time,
	                               subject_agent_id, actor_type, actor_id, action, outcome, reason, trace_id, canonical)
	                             SELECT i, clock_timestamp(), s, e, q, t, tm, a::uuid, 'agent', a, ac, o, r, tr, c
	                             FROM unnest($1::uuid[], $2::text[], $3::text[], $4::bigint[], $5::text[], $6::timestamptz[],
	                                         $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::bytea[])
	                                  AS t(i, s, e, q, t, tm, a, ac, o, r, tr, c)
	                             RETURNING id, ingested_at)
	                           INSERT INTO whitetower.audit_unsealed (audit_id, ingested_at) SELECT id, ingested_at FROM stored`,
		ids, sources, eventIDs, seqs, types, times, agents, actions, outcomes, reasons, traces, canonical); err != nil {
		return err
	}
	// Gap detection keeps the highest sequence seen per source. The rows are
	// locked in the order of their source, so that batches sharing sources
	// cannot deadlock.
	if _, err := tx.Exec(ctx, `INSERT INTO whitetower.audit_source_sequences (source, last_seq)
	                           SELECT s, max(q) FROM unnest($1::text[], $2::bigint[]) AS t(s, q) GROUP BY s ORDER BY s
	                           ON CONFLICT (source) DO UPDATE SET last_seq = greatest(audit_source_sequences.last_seq, excluded.last_seq),
	                                                             last_seen_at = now()`, sources, seqs); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// publishStats is what the publishers saw.
type publishStats struct {
	Events  int64
	Batches int64
	Lag     int64 // batches sent late because ingestion could not keep up
	mu      sync.Mutex
	Latency []time.Duration
}

// publish runs publishers that together send `rate` events per second for
// `d`, each sending one batch per interval, like enforcement points flushing
// their buffers.
func publish(ctx context.Context, pool *pgxpool.Pool, g *generator, rate, publishers int, interval, d time.Duration, shared bool, st *publishStats) error {
	shards := publishers
	if shared {
		shards = 1 // every publisher sends events from any source
	}
	// Each publisher's share of a batch may be fractional (200 events per
	// second from 20 publishers every 250 ms is 2.5 events a batch), so each
	// one carries the fraction over to its next batch.
	share := float64(rate) * interval.Seconds() / float64(publishers)
	deadline := time.Now().Add(d)
	var wg sync.WaitGroup
	var firstErr atomic.Value
	for p := range publishers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Spread the publishers over the interval.
			next := time.Now().Add(time.Duration(p) * interval / time.Duration(publishers))
			owed := float64(p) / float64(publishers) // staggered, so the fractions do not line up
			for next.Before(deadline) && ctx.Err() == nil {
				if wait := time.Until(next); wait > 0 {
					time.Sleep(wait)
				} else if wait < -interval {
					atomic.AddInt64(&st.Lag, 1)
				}
				owed += share
				n := int(owed)
				owed -= float64(n)
				if n == 0 {
					next = next.Add(interval)
					continue
				}
				batch := make([]event, n)
				now := time.Now()
				for i := range batch {
					e, err := g.next(now, p%shards, shards)
					if err != nil {
						firstErr.CompareAndSwap(nil, err)
						return
					}
					batch[i] = e
				}
				start := time.Now()
				if err := ingest(ctx, pool, batch); err != nil {
					firstErr.CompareAndSwap(nil, err)
					return
				}
				lat := time.Since(start)
				st.mu.Lock()
				st.Latency = append(st.Latency, lat)
				st.mu.Unlock()
				atomic.AddInt64(&st.Events, int64(n))
				atomic.AddInt64(&st.Batches, 1)
				next = next.Add(interval)
			}
		}()
	}
	wg.Wait()
	if err, ok := firstErr.Load().(error); ok {
		return err
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
