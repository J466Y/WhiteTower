package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
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

// Stream IDs name evidence buffers, by 16 to 64 lowercase hexadecimal
// characters (contracts, section 8.2).
const (
	stream      = "b7e2c1d40f9a3e65"
	otherStream = "5c1e8a2f7d3b9046"
	otherAgent  = "0192f1c2-7a3b-7c4d-8e5f-000000000099"
)

var agentUUID = uuid.MustParse(agent)

// epSource is a stream of an enforcement point inside an agent.
func epSource(agentID, streamID string) string { return "/agents/" + agentID + "/ep/" + streamID }

// moduleSource is a stream of an instance of a module, by its slug.
func moduleSource(slug, streamID string) string { return "/modules/" + slug + "/" + streamID }

// enforcementPoint is an instance of ep-python inside the agent.
func enforcementPoint() audit.IngestCaller {
	return audit.IngestCaller{
		InstanceID:    "inst-01",
		Module:        "ep-python",
		Agent:         agentUUID,
		AllowedAgents: []uuid.UUID{agentUUID},
		AllowedTypes:  []string{"whitetower.decision.made.v1"},
	}
}

// quarantineModule is an instance of k8s-quarantine, whose scope is the agent.
func quarantineModule() audit.IngestCaller {
	return audit.IngestCaller{
		InstanceID:    "inst-02",
		Module:        "k8s-quarantine",
		AllowedAgents: []uuid.UUID{agentUUID},
		AllowedTypes:  []string{"whitetower.instance.started.v1"},
	}
}

// roomy are limits that the tests do not reach, unless they mean to.
var roomy = audit.IngesterOptions{RateLimit: 1000, RateBurst: 1000, MaxSealingLag: time.Hour}

// newIngester returns an ingester on pool, with clk and the limits of opts.
func newIngester(t *testing.T, pool *db.DB, clk *clocktest.Fake, opts audit.IngesterOptions) *audit.Ingester {
	t.Helper()
	cat, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	opts.DB, opts.Catalog, opts.Writer, opts.Clock = pool, cat, audit.NewWriter(cat, clk), clk
	return audit.NewIngester(opts)
}

// setupIngester returns a database and an ingester with roomy limits. The
// ingester de-duplicates in the month of its clock, which lies before the
// months that the migration made partitions for: the database gets the
// partitions of that month, and of the months of also.
func setupIngester(t *testing.T, clk *clocktest.Fake, also ...time.Time) (*db.DB, *audit.Ingester) {
	t.Helper()
	d := dbtest.New(t)
	for _, at := range append(also, clk.Now()) {
		d.EnsureAuditPartitions(t, at)
	}
	pool := d.Open(t)
	return pool, newIngester(t, pool, clk, roomy)
}

// decisionEvent is a decision about agentID; a seq of 0 leaves wtseq out.
func decisionEvent(source, eventID string, seq int64, agentID, decision, reason string) []byte {
	m := map[string]any{
		"specversion":     "1.0",
		"id":              eventID,
		"source":          source,
		"type":            "whitetower.decision.made.v1",
		"time":            "2026-10-14T10:00:00.000Z",
		"subject":         agentID,
		"datacontenttype": "application/json",
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
	if seq > 0 {
		m["wtseq"] = fmt.Sprint(seq)
	}
	b, _ := json.Marshal(m)
	return b
}

// instanceStartedEvent is the start of an instance, about subject unless it
// is empty.
func instanceStartedEvent(source, eventID string, seq int64, subject string) []byte {
	m := map[string]any{
		"specversion":     "1.0",
		"id":              eventID,
		"source":          source,
		"type":            "whitetower.instance.started.v1",
		"time":            "2026-10-14T10:00:00.000Z",
		"datacontenttype": "application/json",
		"wtseq":           fmt.Sprint(seq),
		"data": map[string]any{
			"module":           "k8s-quarantine",
			"module_version":   "1.0.0",
			"contract_version": "v1alpha1",
			"instance_id":      "0192f1c2-9e00-7c4d-8e5f-000000000051",
		},
	}
	if subject != "" {
		m["subject"] = subject
	}
	b, _ := json.Marshal(m)
	return b
}

// ingestOne ingests one event, and returns its result.
func ingestOne(t *testing.T, ing *audit.Ingester, caller audit.IngestCaller, event []byte) audit.IngestResult {
	t.Helper()
	res, err := ing.Ingest(context.Background(), caller, [][]byte{event})
	if err != nil {
		t.Fatal(err)
	}
	return res[0]
}

// finding is the data of a finding about a source's sequence.
type finding struct {
	Source      string `json:"source"`
	ExpectedSeq int64  `json:"expected_seq,omitempty"`
	LastSeq     int64  `json:"last_seq,omitempty"`
	ReceivedSeq int64  `json:"received_seq"`
	GapSize     int64  `json:"gap_size,omitempty"`
	EventID     string `json:"event_id,omitempty"`
	InstanceID  string `json:"instance_id"`
}

// findings returns the findings of type typ about source, by the sequence
// number received.
func findings(t *testing.T, pool *db.DB, typ, source string) []finding {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT convert_from(canonical, 'UTF-8')::jsonb->'data' AS data
		FROM whitetower.audit_events
		WHERE type = $1 AND convert_from(canonical, 'UTF-8')::jsonb->'data'->>'source' = $2
		ORDER BY (convert_from(canonical, 'UTF-8')::jsonb->'data'->>'received_seq')::bigint`, typ, source)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []finding
	for rows.Next() {
		var data []byte
		var f finding
		if err := rows.Scan(&data); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// lastSeq returns the position recorded for source, 0 for none.
func lastSeq(t *testing.T, pool *db.DB, source string) int64 {
	t.Helper()
	var last int64
	if err := pool.QueryRow(context.Background(),
		`SELECT coalesce(max(last_seq), 0) FROM whitetower.audit_source_sequences WHERE source = $1`, source).Scan(&last); err != nil {
		t.Fatal(err)
	}
	return last
}

// count counts the rows of a query's result.
func count(t *testing.T, pool *db.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM ("+query+") AS q", args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Security test ST-10: Ingestion refuses event types outside the instance's manifest, sources
// other than its agent's or its module's streams, and agents outside its scope; per-instance
// rate limits and backpressure keep one flooding instance from slowing the others
func TestST10IngestionSecurityAndIsolation(t *testing.T) {
	clk := clocktest.New(epoch)
	pool, ing := setupIngester(t, clk)
	ctx := context.Background()

	ep, module := enforcementPoint(), quarantineModule()
	epOfTheCore := ep
	epOfTheCore.AllowedTypes = []string{"whitetower.agent.created.v1"}
	epOfTwoAgents := ep
	epOfTwoAgents.AllowedAgents = []uuid.UUID{agentUUID, uuid.MustParse(otherAgent)}
	epStarting := ep
	epStarting.AllowedTypes = []string{"whitetower.instance.started.v1"}
	moduleDeciding := module
	moduleDeciding.AllowedTypes = []string{"whitetower.decision.made.v1"}

	coreData, _ := json.Marshal(created().Data)
	coreEvent, _ := json.Marshal(map[string]any{
		"specversion": "1.0", "id": "ev-core-01", "source": epSource(agent, stream), "type": "whitetower.agent.created.v1",
		"time": "2026-10-14T10:00:00.000Z", "subject": agent, "wtseq": "1", "data": json.RawMessage(coreData),
	})

	for _, tt := range []struct {
		name   string
		caller audit.IngestCaller
		event  []byte
		reason string
	}{
		{"a type its manifest does not declare", ep, instanceStartedEvent(epSource(agent, stream), "ev-01", 1, ""), "is not declared"},
		{"a type of the core", epOfTheCore, coreEvent, "cannot be emitted by modules"},
		{
			"another agent's stream, from an enforcement point inside an agent", epOfTwoAgents,
			decisionEvent(epSource(otherAgent, stream), "ev-02", 1, otherAgent, "allow", "policy.permit"), "does not own source",
		},
		{"a subject other than its agent", ep, decisionEvent(epSource(agent, stream), "ev-03", 1, otherAgent, "allow", "policy.permit"), "subject does not match"},
		{
			"its module's stream, from an enforcement point inside an agent", epStarting,
			instanceStartedEvent(moduleSource("ep-python", stream), "ev-04", 1, ""), "does not own source",
		},
		{
			"an agent's stream, from an instance whose scope holds the agent", moduleDeciding,
			decisionEvent(epSource(agent, stream), "ev-05", 1, agent, "allow", "policy.permit"), "does not own source",
		},
		{"another module's stream", module, instanceStartedEvent(moduleSource("other-module", stream), "ev-06", 1, ""), "does not own source"},
		{"an agent outside its scope", module, instanceStartedEvent(moduleSource("k8s-quarantine", stream), "ev-07", 1, otherAgent), "not authorized for agent"},
		{"the core's source", ep, decisionEvent("/core", "ev-08", 0, agent, "allow", "policy.permit"), "does not own source"},
	} {
		t.Run("Refuses "+tt.name, func(t *testing.T) {
			if r := ingestOne(t, ing, tt.caller, tt.event); r.Status != audit.StatusRejected || !strings.Contains(r.Reason, tt.reason) {
				t.Fatalf("got %+v, want rejected for %q", r, tt.reason)
			}
		})
	}

	t.Run("AcceptsItsModulesStreamFromEveryInstance", func(t *testing.T) {
		// A source is not bound to the instance that first wrote it
		// (contracts, section 8.4), and the actor is the module, by its slug.
		another := module
		another.InstanceID = "inst-03"
		src := moduleSource("k8s-quarantine", otherStream)
		for i, caller := range []audit.IngestCaller{module, another} {
			if r := ingestOne(t, ing, caller, instanceStartedEvent(src, fmt.Sprintf("ev-mod-%d", i), int64(i+1), agent)); r.Status != audit.StatusAccepted {
				t.Fatalf("instance %s: %+v", caller.InstanceID, r)
			}
		}
		if n := count(t, pool, `SELECT 1 FROM whitetower.audit_events WHERE source = $1 AND actor_type = 'module' AND actor_id = 'k8s-quarantine'`, src); n != 2 {
			t.Errorf("%d events of the module's stream have the module as actor, want 2", n)
		}
	})

	t.Run("PerInstanceRateLimiting", func(t *testing.T) {
		rateLimitedIng := newIngester(t, pool, clk, audit.IngesterOptions{RateLimit: 1, RateBurst: 1, MaxSealingLag: time.Hour})
		src := epSource(agent, "00000000000000a1")
		if r := ingestOne(t, rateLimitedIng, ep, decisionEvent(src, "ev-rl-1", 1, agent, "allow", "policy.permit")); r.Status != audit.StatusAccepted {
			t.Fatalf("expected accepted, got %+v", r)
		}

		// Second call immediately from same instance should be rate-limited.
		ev2 := decisionEvent(src, "ev-rl-2", 2, agent, "allow", "policy.permit")
		_, err := rateLimitedIng.Ingest(ctx, ep, [][]byte{ev2})
		var rlErr *audit.ErrRateLimited
		if !errors.As(err, &rlErr) {
			t.Fatalf("expected ErrRateLimited, got %T: %v", err, err)
		}

		// Another instance is not affected (isolation).
		caller2 := ep
		caller2.InstanceID = "inst-02"
		evOther := decisionEvent(epSource(agent, "00000000000000a2"), "ev-rl-other", 1, agent, "allow", "policy.permit")
		if r := ingestOne(t, rateLimitedIng, caller2, evOther); r.Status != audit.StatusAccepted {
			t.Fatalf("expected other instance accepted, got %+v", r)
		}
	})

	t.Run("BackpressureOnSealingLag", func(t *testing.T) {
		// The lag is measured on the database's clock, which stamps when an
		// event was ingested, whatever the ingester's clock says.
		tight := audit.IngesterOptions{RateLimit: 1000, RateBurst: 1000, MaxSealingLag: 2 * time.Second}

		t.Run("a clock a day ahead of the database's refuses nothing", func(t *testing.T) {
			ahead := clocktest.New(time.Now().Add(24 * time.Hour))
			pool, _ := setupIngester(t, ahead)
			bpIng := newIngester(t, pool, ahead, tight)
			// The first batch finds no event awaiting sealing, the second
			// finds the first's, just ingested.
			for seq := int64(1); seq <= 2; seq++ {
				ev := decisionEvent(epSource(agent, stream), fmt.Sprintf("ev-bp-%d", seq), seq, agent, "allow", "policy.permit")
				if r := ingestOne(t, bpIng, ep, ev); r.Status != audit.StatusAccepted {
					t.Fatalf("batch %d: %+v", seq, r)
				}
			}
		})

		t.Run("an event that waited longer than the threshold refuses the batch", func(t *testing.T) {
			// The ingester's clock is in the past of the database's, which
			// would hide the lag if it measured it.
			pool, _ := setupIngester(t, clk)
			bpIng := newIngester(t, pool, clk, tight)
			if _, err := pool.Exec(ctx, `INSERT INTO whitetower.audit_unsealed (audit_id, ingested_at) VALUES ($1, now() - interval '1 minute')`, uuid.New()); err != nil {
				t.Fatal(err)
			}
			ev := decisionEvent(epSource(agent, stream), "ev-bp-1", 1, agent, "allow", "policy.permit")
			_, err := bpIng.Ingest(ctx, ep, [][]byte{ev})
			var resExErr *audit.ErrResourceExhausted
			if !errors.As(err, &resExErr) {
				t.Fatalf("expected ErrResourceExhausted, got %T: %v", err, err)
			}
		})
	})
}

func TestIngestBatchProcessing(t *testing.T) {
	clk := clocktest.New(epoch)
	pool, ing := setupIngester(t, clk)
	ctx := context.Background()

	caller := enforcementPoint()
	src := epSource(agent, stream)
	gap := func(expected, received int64) finding {
		return finding{Source: src, ExpectedSeq: expected, ReceivedSeq: received, GapSize: received - expected, InstanceID: "inst-01"}
	}
	repeat := func(last, received int64, eventID string) finding {
		return finding{Source: src, LastSeq: last, ReceivedSeq: received, EventID: eventID, InstanceID: "inst-01"}
	}
	check := func(t *testing.T, typ string, want ...finding) {
		t.Helper()
		if got := findings(t, pool, typ, src); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v, want %+v", typ, got, want)
		}
	}

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
		check(t, "whitetower.audit.gap_detected.v1", gap(2, 4))
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
		// A duplicate is no repeat: its event ID is not new.
		check(t, "whitetower.audit.repeat_detected.v1")
	})

	t.Run("RecordsAPositionThatGoesBackOrRepeats", func(t *testing.T) {
		// Current max sequence seen is 5. Under new event IDs, seq 3, which
		// the earlier gap left out, goes back, and seq 5 repeats: each is
		// accepted, and is a finding (contracts, section 8.4).
		ev3 := decisionEvent(src, "ev-seq-3", 3, agent, "allow", "policy.permit")
		ev5 := decisionEvent(src, "ev-seq-5-again", 5, agent, "allow", "policy.permit")
		res, err := ing.Ingest(ctx, caller, [][]byte{ev3, ev5})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].Status != audit.StatusAccepted || res[1].Status != audit.StatusAccepted {
			t.Fatalf("expected both accepted, got %+v", res)
		}
		check(t, "whitetower.audit.repeat_detected.v1", repeat(5, 3, "ev-seq-3"), repeat(5, 5, "ev-seq-5-again"))
		// The earlier gap stays, and the recorded position never moves back.
		check(t, "whitetower.audit.gap_detected.v1", gap(2, 4))
		if last := lastSeq(t, pool, src); last != 5 {
			t.Fatalf("expected lastSeq 5, got %d", last)
		}
	})

	t.Run("ARejectedEventLeavesItsGap", func(t *testing.T) {
		ev6 := decisionEvent(src, "ev-seq-6", 6, agent, "allow", "policy.permit")
		ev7 := decisionEvent(src, "ev-seq-7", 7, otherAgent, "allow", "policy.permit")
		ev8 := decisionEvent(src, "ev-seq-8", 8, agent, "allow", "policy.permit")
		res, err := ing.Ingest(ctx, caller, [][]byte{ev6, ev7, ev8})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 3 || res[0].Status != audit.StatusAccepted || res[1].Status != audit.StatusRejected || res[2].Status != audit.StatusAccepted {
			t.Fatalf("expected the second rejected and the others accepted, got %+v", res)
		}
		check(t, "whitetower.audit.gap_detected.v1", gap(2, 4), gap(7, 8))
		if n := count(t, pool, `SELECT 1 FROM whitetower.audit_event_ids WHERE event_id = 'ev-seq-7'`); n != 0 {
			t.Errorf("the rejected event's ID is recorded %d times", n)
		}
	})

	t.Run("ConcurrentBatchesDoNotDeadlock", func(t *testing.T) {
		srcA := epSource(agent, "000000000000000a")
		srcB := epSource(agent, "000000000000000b")

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

// A retry of an accepted event stays a duplicate whatever the caller's scope,
// types and module are now: de-duplication comes before the rules of section
// 4.3 (contracts, section 8.4). An event refused for its scope records no ID
// and moves no sequence.
func TestADuplicateIsDecidedBeforeTheRules(t *testing.T) {
	clk := clocktest.New(epoch)
	pool, ing := setupIngester(t, clk)
	module := quarantineModule()
	src := moduleSource("k8s-quarantine", stream)
	event := instanceStartedEvent(src, "ev-01", 1, agent)
	if r := ingestOne(t, ing, module, event); r.Status != audit.StatusAccepted {
		t.Fatalf("the first delivery: %+v", r)
	}

	outOfScope := module
	outOfScope.AllowedAgents = nil
	undeclared := module
	undeclared.AllowedTypes = nil
	otherModule := audit.IngestCaller{InstanceID: "inst-09", Module: "other-module", AllowedTypes: module.AllowedTypes}
	for name, caller := range map[string]audit.IngestCaller{
		"its agent has left the scope":   outOfScope,
		"its type is no longer declared": undeclared,
		"another module's instance":      otherModule,
	} {
		t.Run(name, func(t *testing.T) {
			if r := ingestOne(t, ing, caller, event); r.Status != audit.StatusDuplicate {
				t.Fatalf("got %+v, want a duplicate", r)
			}
		})
	}

	t.Run("an event refused for its scope records nothing", func(t *testing.T) {
		if r := ingestOne(t, ing, outOfScope, instanceStartedEvent(src, "ev-02", 2, agent)); r.Status != audit.StatusRejected {
			t.Fatalf("got %+v, want rejected", r)
		}
		if n := count(t, pool, `SELECT 1 FROM whitetower.audit_event_ids WHERE event_id = 'ev-02'`); n != 0 {
			t.Errorf("its ID is recorded %d times", n)
		}
		if last := lastSeq(t, pool, src); last != 1 {
			t.Errorf("the source's position is %d, want 1", last)
		}
	})
}

// De-duplication recognizes an event for at least 28 days: from the last
// second of a month, to the last second of the next, which may be 28 days
// later. It also finds the ID that a replica whose clock is ahead recorded in
// the next month.
func TestAnEventIsRecognizedForAtLeast28Days(t *testing.T) {
	lastSecond := time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)
	nextMonth := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	clk := clocktest.New(lastSecond)
	pool, ing := setupIngester(t, clk, nextMonth)
	ep := enforcementPoint()
	src := epSource(agent, stream)

	event := decisionEvent(src, "ev-01", 1, agent, "allow", "policy.permit")
	if r := ingestOne(t, ing, ep, event); r.Status != audit.StatusAccepted {
		t.Fatalf("the first delivery: %+v", r)
	}
	clk.Advance(28 * 24 * time.Hour)
	if r := ingestOne(t, ing, ep, event); r.Status != audit.StatusDuplicate {
		t.Fatalf("28 days later, in the next month: %+v, want a duplicate", r)
	}

	ahead := newIngester(t, pool, clocktest.New(nextMonth), roomy)
	behind := newIngester(t, pool, clocktest.New(lastSecond), roomy)
	event = decisionEvent(src, "ev-02", 2, agent, "allow", "policy.permit")
	if r := ingestOne(t, ahead, ep, event); r.Status != audit.StatusAccepted {
		t.Fatalf("the replica ahead: %+v", r)
	}
	if r := ingestOne(t, behind, ep, event); r.Status != audit.StatusDuplicate {
		t.Fatalf("the replica behind: %+v, want a duplicate", r)
	}
}

// Two replicas that deliver one event at once store it once. The one whose
// lookup ran before the other's transaction committed waits for it at this
// month's key, then finds the event a duplicate.
func TestAnEventDeliveredTwiceAtOnceIsStoredOnce(t *testing.T) {
	clk := clocktest.New(epoch)
	pool, ing := setupIngester(t, clk)
	ctx := context.Background()
	src := epSource(agent, stream)

	held, release, other := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		other <- pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			// The other replica has recorded the event's ID, and not committed.
			if _, err := tx.Exec(ctx, `INSERT INTO whitetower.audit_event_ids (source, event_id, ingest_month, audit_id)
				VALUES ($1, 'ev-01', date_trunc('month', $2::timestamptz AT TIME ZONE 'UTC')::date, $3)`, src, epoch, uuid.New()); err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	select {
	case <-held:
	case err := <-other:
		t.Fatal(err)
	}

	type outcome struct {
		res []audit.IngestResult
		err error
	}
	delivered := make(chan outcome, 1)
	go func() {
		res, err := ing.Ingest(ctx, enforcementPoint(), [][]byte{decisionEvent(src, "ev-01", 1, agent, "allow", "policy.permit")})
		delivered <- outcome{res, err}
	}()
	awaitLockWait(t, pool)
	close(release)
	if err := <-other; err != nil {
		t.Fatal(err)
	}
	got := <-delivered
	if got.err != nil || got.res[0].Status != audit.StatusDuplicate {
		t.Fatalf("got %+v (%v), want a duplicate", got.res, got.err)
	}
	if n := count(t, pool, `SELECT 1 FROM whitetower.audit_events WHERE event_id = 'ev-01'`); n != 0 {
		t.Errorf("the duplicate was stored %d times", n)
	}
}

// awaitLockWait waits until a session of the test's database waits for a
// lock.
func awaitLockWait(t *testing.T, pool *db.DB) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if count(t, pool, `SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no session ever waited for a lock")
		}
	}
}
