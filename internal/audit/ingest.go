package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/ratelimit"
)

// MaxBatchEvents is the maximum number of events accepted in a single batch
// (contracts, section 8.4; events.proto).
const MaxBatchEvents = 500

// MaxEventSize is the maximum allowed size of an event in bytes (64 KiB).
const MaxEventSize = 64 * 1024

// DefaultSealingLagThreshold is the default maximum lag between ingestion and sealing
// before backpressure triggers (NFR-09).
const DefaultSealingLagThreshold = 5 * time.Second

// IngestStatus is the outcome of ingesting an event.
type IngestStatus int

const (
	// StatusAccepted means the event was validated and stored.
	StatusAccepted IngestStatus = 1
	// StatusDuplicate means the event was already stored earlier.
	StatusDuplicate IngestStatus = 2
	// StatusRejected means the event was invalid or unauthorized and can never be accepted.
	StatusRejected IngestStatus = 3
)

// IngestResult is the outcome for one event in a batch.
type IngestResult struct {
	Status IngestStatus
	Reason string
}

// IngestCaller identifies the module instance publishing events and its
// authorized scope (contracts, section 4.3).
type IngestCaller struct {
	// InstanceID is the caller's unique module instance identifier. It keys
	// the per-instance rate limit, and the findings name it; a source never
	// does.
	InstanceID string
	// Module is the slug of the instance's module (metadata.name). An
	// instance that does not run inside an agent publishes only from
	// /modules/<Module>/<stream-id>.
	Module string
	// Agent is the agent that an enforcement point inside an agent
	// (identity: agent) authenticates as, and uuid.Nil for any other
	// instance. Such an enforcement point publishes only from
	// /agents/<Agent>/ep/<stream-id>, about its agent.
	Agent uuid.UUID
	// AllowedAgents are the IDs of the agents in the instance's scope: its
	// own agent for an enforcement point inside an agent, otherwise the
	// agents bound to its module.
	AllowedAgents []uuid.UUID
	// AllowedTypes are the event types declared in the instance's manifest.
	AllowedTypes []string
}

// IngesterOptions configures an Ingester.
type IngesterOptions struct {
	DB            *db.DB
	Catalog       *Catalog
	Writer        *Writer
	Clock         clock.Clock
	Logger        *slog.Logger
	RateLimit     float64
	RateBurst     int
	MaxSealingLag time.Duration
}

// ErrRateLimited reports that an instance exceeded its rate limit.
type ErrRateLimited struct {
	RetryAfter time.Duration
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf("audit: rate limited: retry after %s", e.RetryAfter)
}

// ErrResourceExhausted reports that the audit log is under backpressure.
type ErrResourceExhausted struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *ErrResourceExhausted) Error() string {
	return fmt.Sprintf("audit: resource exhausted (%s): retry after %s", e.Reason, e.RetryAfter)
}

// ErrBatchTooLarge reports that a batch exceeds the maximum allowed events.
var ErrBatchTooLarge = fmt.Errorf("audit: batch exceeds maximum size of %d events", MaxBatchEvents)

// Ingester processes batches of audit events from module instances (plan P1-02, step 5).
// It validates, de-duplicates, authorizes, tracks sequence numbers, detects gaps and
// repeats, and writes events to storage atomically.
type Ingester struct {
	db            *db.DB
	catalog       *Catalog
	writer        *Writer
	clock         clock.Clock
	logger        *slog.Logger
	limiter       *ratelimit.Limiter
	maxSealingLag time.Duration
}

// NewIngester returns an Ingester configured with opts.
func NewIngester(opts IngesterOptions) *Ingester {
	clk := opts.Clock
	if clk == nil {
		clk = clock.System
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	rateLimit := opts.RateLimit
	if rateLimit <= 0 {
		rateLimit = 200 // NFR-07: 200 events/s sustained
	}
	rateBurst := opts.RateBurst
	if rateBurst <= 0 {
		rateBurst = 500
	}
	maxLag := opts.MaxSealingLag
	if maxLag <= 0 {
		maxLag = DefaultSealingLagThreshold
	}

	return &Ingester{
		db:            opts.DB,
		catalog:       opts.Catalog,
		writer:        opts.Writer,
		clock:         clk,
		logger:        logger,
		limiter:       ratelimit.New(rateLimit, rateBurst),
		maxSealingLag: maxLag,
	}
}

type preparedEvent struct {
	index     int
	id        uuid.UUID
	eventID   string
	source    string
	seq       int64
	typ       string
	emitters  []string
	time      time.Time
	subject   *uuid.UUID // the agent the event is about, once authorized
	actorType string
	actorID   *string
	action    string
	outcome   *string
	reason    *string
	traceID   *string
	canonical []byte
}

// eventKey names an event as de-duplication does: by its source and ID.
type eventKey struct{ source, eventID string }

// Ingest processes a batch of raw CloudEvents from caller. Delivery is at least once.
// Each event is decided on its own (contracts, section 8.4): an invalid one is
// StatusRejected; then one the audit log already holds is StatusDuplicate,
// whatever the caller's scope is now; then one outside the rules of section 4.3
// is StatusRejected, and the others are stored, StatusAccepted. A gap in a
// source's sequence records whitetower.audit.gap_detected.v1, and a position
// that repeats or goes back under a new event ID whitetower.audit.repeat_detected.v1.
func (ing *Ingester) Ingest(ctx context.Context, caller IngestCaller, rawEvents [][]byte) ([]IngestResult, error) {
	if len(rawEvents) == 0 {
		return []IngestResult{}, nil
	}
	if len(rawEvents) > MaxBatchEvents {
		return nil, ErrBatchTooLarge
	}
	if caller.InstanceID == "" {
		return nil, errors.New("audit: missing instance id")
	}
	if caller.Module == "" {
		return nil, errors.New("audit: missing module slug")
	}

	now := ing.clock.Now().UTC()

	// Rate limiting per instance (threat model, T-11, T-36; ST-10).
	if allowed, wait := ing.limiter.Allow(caller.InstanceID, now); !allowed {
		return nil, &ErrRateLimited{RetryAfter: wait}
	}

	// Backpressure: check sealing lag (NFR-08, NFR-09; ST-10).
	if err := ing.checkSealingLag(ctx); err != nil {
		return nil, err
	}

	results := make([]IngestResult, len(rawEvents))
	var prepared []preparedEvent

	for i, raw := range rawEvents {
		if len(raw) > MaxEventSize {
			results[i] = IngestResult{Status: StatusRejected, Reason: fmt.Sprintf("event exceeds %d bytes", MaxEventSize)}
			continue
		}

		canonical, decoded, err := canonicalize(json.RawMessage(raw))
		if err != nil {
			results[i] = IngestResult{Status: StatusRejected, Reason: "malformed JSON: " + err.Error()}
			continue
		}

		et, err := ing.catalog.check(decoded)
		if err != nil {
			results[i] = IngestResult{Status: StatusRejected, Reason: err.Error()}
			continue
		}

		// The envelope's schema requires wtseq of every source but /core,
		// which no module owns.
		var seq int64
		if seqStr, ok := decoded["wtseq"].(string); ok {
			if seq, err = strconv.ParseInt(seqStr, 10, 64); err != nil || seq <= 0 {
				results[i] = IngestResult{Status: StatusRejected, Reason: "invalid wtseq"}
				continue
			}
		}

		eventID, _ := decoded["id"].(string)
		if eventID == "" {
			results[i] = IngestResult{Status: StatusRejected, Reason: "missing event id"}
			continue
		}

		timeStr, _ := decoded["time"].(string)
		eventTime, err := time.Parse(time.RFC3339Nano, timeStr)
		if err != nil {
			results[i] = IngestResult{Status: StatusRejected, Reason: "invalid event time"}
			continue
		}

		f, err := factsOf(et, decoded)
		if err != nil {
			results[i] = IngestResult{Status: StatusRejected, Reason: err.Error()}
			continue
		}

		var subject *uuid.UUID
		if s, ok := decoded["subject"].(string); ok {
			id, err := uuid.Parse(s)
			if err != nil {
				results[i] = IngestResult{Status: StatusRejected, Reason: "invalid subject"}
				continue
			}
			subject = &id
		}

		auditID, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}

		var traceID *string
		if tp, ok := decoded["traceparent"].(string); ok && len(tp) >= 35 && tp[:3] == "00-" {
			tid := tp[3:35]
			traceID = &tid
		}

		typ, _ := decoded["type"].(string)
		source, _ := decoded["source"].(string)
		prepared = append(prepared, preparedEvent{
			index:     i,
			id:        auditID,
			eventID:   eventID,
			source:    source,
			seq:       seq,
			typ:       typ,
			emitters:  et.emitters,
			time:      eventTime,
			subject:   subject,
			actorType: f.actorType,
			actorID:   optional(f.actorID),
			action:    f.action,
			outcome:   optional(f.outcome),
			reason:    optional(f.reason),
			traceID:   traceID,
			canonical: canonical,
		})
	}

	if len(prepared) == 0 {
		return results, nil
	}
	if ing.db == nil {
		// Without a database, as the fuzz test runs, the log holds no event
		// yet and nothing is stored.
		decide(caller, prepared, map[eventKey]bool{}, results)
		return results, nil
	}

	// Persist the batch atomically in one transaction. De-duplication comes
	// first (contracts, section 8.4), so that a retry of an accepted event
	// stays a duplicate whatever the caller's scope is now; an event refused
	// then records no ID and moves no sequence, so the gap it leaves stays
	// visible.
	err := ing.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		qtx := auditdb.New(tx)
		month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

		// 1. De-duplication on source and ID, for at least 28 days: in the
		// previous month's partition as in this month's. The next month's
		// partition holds what a replica whose clock is ahead recorded.
		lookup := auditdb.SeenEventIDsParams{
			FromMonth: pgtype.Date{Time: month.AddDate(0, -1, 0), Valid: true},
			ToMonth:   pgtype.Date{Time: month.AddDate(0, 1, 0), Valid: true},
		}
		for _, p := range prepared {
			lookup.Sources = append(lookup.Sources, p.source)
			lookup.EventIds = append(lookup.EventIds, p.eventID)
		}
		seenRows, err := qtx.SeenEventIDs(ctx, lookup)
		if err != nil {
			return fmt.Errorf("audit: looking up event ids: %w", err)
		}
		seen := make(map[eventKey]bool, len(seenRows))
		for _, r := range seenRows {
			seen[eventKey{r.Source, r.EventID}] = true
		}
		fresh := decide(caller, prepared, seen, results)
		if len(fresh) == 0 {
			return nil
		}

		// 2. Record the new events' IDs in this month. One that another
		// transaction recorded since the lookup is a duplicate.
		ids := auditdb.RecordEventIDsParams{IngestMonth: pgtype.Date{Time: month, Valid: true}}
		for _, p := range fresh {
			ids.Sources = append(ids.Sources, p.source)
			ids.EventIds = append(ids.EventIds, p.eventID)
			ids.AuditIds = append(ids.AuditIds, p.id)
		}
		recorded, err := qtx.RecordEventIDs(ctx, ids)
		if err != nil {
			return fmt.Errorf("audit: recording event ids: %w", err)
		}
		isRecorded := make(map[eventKey]bool, len(recorded))
		for _, r := range recorded {
			isRecorded[eventKey{r.Source, r.EventID}] = true
		}
		fresh = slices.DeleteFunc(fresh, func(p preparedEvent) bool {
			if !isRecorded[eventKey{p.source, p.eventID}] {
				results[p.index] = IngestResult{Status: StatusDuplicate}
				return true
			}
			return false
		})
		if len(fresh) == 0 {
			return nil
		}

		// 3. Lock sequence rows in alphabetical order of sources to prevent deadlocks (spike S3).
		sourceSet := map[string]bool{}
		for _, p := range fresh {
			sourceSet[p.source] = true
		}
		uniqueSources := make([]string, 0, len(sourceSet))
		for s := range sourceSet {
			uniqueSources = append(uniqueSources, s)
		}
		slices.Sort(uniqueSources)

		lockedRows, err := qtx.LockSourceSequences(ctx, uniqueSources)
		if err != nil {
			return fmt.Errorf("audit: locking source sequences: %w", err)
		}
		lastSeqs := map[string]int64{}
		for _, r := range lockedRows {
			lastSeqs[r.Source] = r.LastSeq
		}

		// 4. Check sequences, record findings, and update sequence records in
		// sorted source order.
		freshBySource := map[string][]preparedEvent{}
		for _, p := range fresh {
			freshBySource[p.source] = append(freshBySource[p.source], p)
		}

		for _, source := range uniqueSources {
			// A new source has reached no position, and starts at 1
			// (contracts, section 8.4).
			last := lastSeqs[source]
			for _, p := range freshBySource[source] {
				switch {
				case p.seq <= last:
					// A position the source reached already, under an event
					// ID new to it: the event is decided as any other.
					if err := ing.recordFinding(ctx, tx, "whitetower.audit.repeat_detected.v1", p, map[string]any{
						"source":       source,
						"last_seq":     last,
						"received_seq": p.seq,
						"event_id":     p.eventID,
						"instance_id":  caller.InstanceID,
					}); err != nil {
						return err
					}
				case p.seq > last+1:
					if err := ing.recordFinding(ctx, tx, "whitetower.audit.gap_detected.v1", p, map[string]any{
						"source":       source,
						"expected_seq": last + 1,
						"received_seq": p.seq,
						"gap_size":     p.seq - last - 1,
						"instance_id":  caller.InstanceID,
					}); err != nil {
						return err
					}
				}
				last = max(last, p.seq)
			}

			// The recorded position never moves back.
			if err := qtx.UpsertSourceSequence(ctx, auditdb.UpsertSourceSequenceParams{
				Source:     source,
				LastSeq:    last,
				LastSeenAt: now,
			}); err != nil {
				return fmt.Errorf("audit: updating sequence for %s: %w", source, err)
			}
		}

		// 5. Store accepted events and queue them for sealing in one atomic statement.
		for _, p := range fresh {
			err := qtx.IngestEvent(ctx, auditdb.IngestEventParams{
				ID:             p.id,
				Source:         p.source,
				EventID:        p.eventID,
				SourceSeq:      &p.seq,
				Type:           p.typ,
				EventTime:      p.time,
				SubjectAgentID: p.subject,
				ActorType:      p.actorType,
				ActorID:        p.actorID,
				Action:         p.action,
				Outcome:        p.outcome,
				Reason:         p.reason,
				RequestID:      nil,
				TraceID:        p.traceID,
				Canonical:      p.canonical,
			})
			if err != nil {
				return fmt.Errorf("audit: storing event %s: %w", p.eventID, err)
			}
			results[p.index] = IngestResult{Status: StatusAccepted}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

// decide decides the valid events of a batch, in its order: an event whose
// key is in seen, the keys of the events that the audit log holds, is a
// duplicate, and one outside the rules of section 4.3 is refused. It adds the
// key of every other event to seen, so that a later copy in the batch is a
// duplicate, and returns those events, to store.
func decide(caller IngestCaller, valid []preparedEvent, seen map[eventKey]bool, results []IngestResult) []preparedEvent {
	var fresh []preparedEvent
	for _, p := range valid {
		key := eventKey{p.source, p.eventID}
		if seen[key] {
			results[p.index] = IngestResult{Status: StatusDuplicate}
			continue
		}
		if reason := authorize(caller, &p); reason != "" {
			results[p.index] = IngestResult{Status: StatusRejected, Reason: reason}
			continue
		}
		seen[key] = true
		fresh = append(fresh, p)
	}
	return fresh
}

// authorize applies the rules of contracts section 4.3 to an event: a type
// that the caller's manifest declares and a module may emit, from a source
// the caller owns, about an agent in its scope. It sets the agent the event
// is about, and returns why the event is refused, or "".
func authorize(caller IngestCaller, p *preparedEvent) string {
	if !slices.Contains(caller.AllowedTypes, p.typ) {
		return fmt.Sprintf("event type %q is not declared by instance", p.typ)
	}
	if slices.Equal(p.emitters, []string{"core"}) {
		return fmt.Sprintf("event type %q cannot be emitted by modules", p.typ)
	}
	// The emitter that the source names is the actor that the audit log
	// indexes, so the actor is the agent or the module checked here.
	kind, owner := emitter(p.source)
	if caller.Agent != uuid.Nil {
		if kind != "agent" || owner != caller.Agent.String() {
			return fmt.Sprintf("instance does not own source %q", p.source)
		}
		if p.subject != nil && *p.subject != caller.Agent {
			return "subject does not match agent in source"
		}
		agent := caller.Agent
		p.subject = &agent
	} else if kind != "module" || owner != caller.Module {
		return fmt.Sprintf("instance does not own source %q", p.source)
	}
	if p.subject != nil && !slices.Contains(caller.AllowedAgents, *p.subject) {
		return fmt.Sprintf("instance is not authorized for agent %q", p.subject.String())
	}
	return ""
}

// recordFinding records a finding about the sequence of p's source, in tx
// (AUD-02). The finding stays, whatever comes later.
func (ing *Ingester) recordFinding(ctx context.Context, tx *db.Tx, typ string, p preparedEvent, data map[string]any) error {
	var subject string
	if p.subject != nil {
		subject = p.subject.String()
	}
	if err := ing.writer.Record(ctx, tx, Event{Type: typ, Subject: subject, Data: data}); err != nil {
		return fmt.Errorf("audit: recording %s: %w", typ, err)
	}
	return nil
}

// checkSealingLag refuses a batch while the oldest event awaiting sealing has
// waited longer than the threshold (NFR-08, NFR-09). The wait is measured on
// the database's clock, which stamped the event's ingestion time and dates the
// sealer's leaves: the ingester's clock, ahead of the database's, would refuse
// every batch, and behind it would hide the lag.
func (ing *Ingester) checkSealingLag(ctx context.Context) error {
	if ing.maxSealingLag <= 0 || ing.db == nil {
		return nil
	}
	var lagMicros int64
	err := ing.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		lagMicros, err = auditdb.New(tx).SealingLag(ctx)
		return err
	})
	if err != nil {
		return fmt.Errorf("audit: checking sealing lag: %w", err)
	}
	if lagMicros > ing.maxSealingLag.Microseconds() {
		return &ErrResourceExhausted{
			Reason:     "sealing lag exceeded threshold",
			RetryAfter: time.Second,
		}
	}
	return nil
}
