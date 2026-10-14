package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// IngestCaller identifies the module instance publishing events and its authorized scope.
type IngestCaller struct {
	// InstanceID is the caller's unique module instance identifier.
	InstanceID string
	// AllowedAgents are the IDs of the agents this instance serves.
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
// It authorizes, validates, de-duplicates, tracks sequence numbers, detects gaps, and
// writes events to storage atomically.
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
	time      time.Time
	subject   *uuid.UUID
	actorType string
	actorID   *string
	action    string
	outcome   *string
	reason    *string
	traceID   *string
	canonical []byte
}

// Ingest processes a batch of raw CloudEvents from caller. Delivery is at least once.
// Events are validated against the catalog and authorized against the instance scope.
// Duplicate events are marked as StatusDuplicate, invalid/unauthorized as StatusRejected,
// and fresh valid events as StatusAccepted. Gaps in sequences produce whitetower.audit.gap_detected.v1 events.
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

	now := ing.clock.Now().UTC()

	// Rate limiting per instance (threat model, T-11, T-36; ST-10).
	if allowed, wait := ing.limiter.Allow(caller.InstanceID, now); !allowed {
		return nil, &ErrRateLimited{RetryAfter: wait}
	}

	// Backpressure: check sealing lag (NFR-08, NFR-09; ST-10).
	if err := ing.checkSealingLag(ctx, now); err != nil {
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

		typ, _ := decoded["type"].(string)
		if !slices.Contains(caller.AllowedTypes, typ) {
			results[i] = IngestResult{Status: StatusRejected, Reason: fmt.Sprintf("event type %q is not declared by instance", typ)}
			continue
		}
		if slices.Contains(et.emitters, "core") && len(et.emitters) == 1 {
			results[i] = IngestResult{Status: StatusRejected, Reason: fmt.Sprintf("event type %q cannot be emitted by modules", typ)}
			continue
		}

		source, _ := decoded["source"].(string)
		parts := strings.Split(strings.TrimPrefix(source, "/"), "/")
		var subjectAgentID *uuid.UUID
		switch {
		case len(parts) == 4 && parts[0] == "agents" && parts[2] == "ep":
			agentID, err := uuid.Parse(parts[1])
			if err != nil || !slices.Contains(caller.AllowedAgents, agentID) {
				results[i] = IngestResult{Status: StatusRejected, Reason: fmt.Sprintf("instance is not authorized for agent %q", parts[1])}
				continue
			}
			subjectAgentID = &agentID
			if subjStr, ok := decoded["subject"].(string); ok && subjStr != "" {
				if subjStr != parts[1] {
					results[i] = IngestResult{Status: StatusRejected, Reason: "subject does not match agent in source"}
					continue
				}
			}
		case len(parts) == 3 && parts[0] == "modules":
			if parts[2] != caller.InstanceID {
				results[i] = IngestResult{Status: StatusRejected, Reason: fmt.Sprintf("instance is not authorized for module source %q", source)}
				continue
			}
			if subjStr, ok := decoded["subject"].(string); ok && subjStr != "" {
				subjID, err := uuid.Parse(subjStr)
				if err != nil || !slices.Contains(caller.AllowedAgents, subjID) {
					results[i] = IngestResult{Status: StatusRejected, Reason: fmt.Sprintf("instance is not authorized for subject agent %q", subjStr)}
					continue
				}
				subjectAgentID = &subjID
			}
		default:
			results[i] = IngestResult{Status: StatusRejected, Reason: fmt.Sprintf("invalid or unauthorized source %q", source)}
			continue
		}

		seqStr, _ := decoded["wtseq"].(string)
		seq, err := strconv.ParseInt(seqStr, 10, 64)
		if err != nil || seq <= 0 {
			results[i] = IngestResult{Status: StatusRejected, Reason: "invalid or missing wtseq"}
			continue
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

		auditID, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}

		var traceID *string
		if tp, ok := decoded["traceparent"].(string); ok && len(tp) >= 35 && tp[:3] == "00-" {
			tid := tp[3:35]
			traceID = &tid
		}

		prepared = append(prepared, preparedEvent{
			index:     i,
			id:        auditID,
			eventID:   eventID,
			source:    source,
			seq:       seq,
			typ:       typ,
			time:      eventTime,
			subject:   subjectAgentID,
			actorType: f.actorType,
			actorID:   optional(f.actorID),
			action:    f.action,
			outcome:   optional(f.outcome),
			reason:    optional(f.reason),
			traceID:   traceID,
			canonical: canonical,
		})
	}

	if len(prepared) == 0 || ing.db == nil {
		return results, nil
	}

	// Persist the batch atomically in one transaction.
	err := ing.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		qtx := auditdb.New(tx)
		ingestMonth := pgtype.Date{
			Time:  time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC),
			Valid: true,
		}

		// 1. De-duplication on (source, event_id, ingest_month).
		var fresh []preparedEvent
		for _, p := range prepared {
			_, err := qtx.RecordEventID(ctx, auditdb.RecordEventIDParams{
				Source:      p.source,
				EventID:     p.eventID,
				IngestMonth: ingestMonth,
				AuditID:     p.id,
			})
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					results[p.index] = IngestResult{Status: StatusDuplicate}
					continue
				}
				return fmt.Errorf("audit: recording event id: %w", err)
			}
			fresh = append(fresh, p)
		}

		if len(fresh) == 0 {
			return nil
		}

		// 2. Lock sequence rows in alphabetical order of sources to prevent deadlocks (spike S3).
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
		seenSources := map[string]bool{}
		for _, r := range lockedRows {
			lastSeqs[r.Source] = r.LastSeq
			seenSources[r.Source] = true
		}

		// 3. Check sequences, detect gaps, and update sequence records in sorted source order.
		freshBySource := map[string][]preparedEvent{}
		for _, p := range fresh {
			freshBySource[p.source] = append(freshBySource[p.source], p)
		}

		for _, source := range uniqueSources {
			events := freshBySource[source]
			lastSeq, seen := lastSeqs[source]
			var expected int64
			if !seen {
				expected = 1 // New source starts at 1 (contract, section 8.4)
			} else {
				expected = lastSeq + 1
			}

			maxSeq := lastSeq
			for _, p := range events {
				if p.seq > expected {
					// Gap detected!
					gapSize := p.seq - expected
					var subject string
					if p.subject != nil {
						subject = p.subject.String()
					}
					gapData := map[string]any{
						"source":       source,
						"expected_seq": expected,
						"received_seq": p.seq,
						"gap_size":     gapSize,
						"instance_id":  caller.InstanceID,
					}
					if err := ing.writer.Record(ctx, tx, Event{
						Type:    "whitetower.audit.gap_detected.v1",
						Subject: subject,
						Data:    gapData,
					}); err != nil {
						return fmt.Errorf("audit: recording gap event: %w", err)
					}
					expected = p.seq + 1
				} else if p.seq == expected {
					expected = p.seq + 1
				}
				if p.seq > maxSeq {
					maxSeq = p.seq
				}
			}

			if err := qtx.UpsertSourceSequence(ctx, auditdb.UpsertSourceSequenceParams{
				Source:     source,
				LastSeq:    maxSeq,
				LastSeenAt: now,
			}); err != nil {
				return fmt.Errorf("audit: updating sequence for %s: %w", source, err)
			}
		}

		// 4. Store accepted events and queue them for sealing in one atomic statement.
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

func (ing *Ingester) checkSealingLag(ctx context.Context, now time.Time) error {
	if ing.maxSealingLag <= 0 || ing.db == nil {
		return nil
	}
	var oldest time.Time
	err := ing.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		oldest, err = auditdb.New(tx).OldestUnsealedTime(ctx)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("audit: checking sealing lag: %w", err)
	}
	if !oldest.IsZero() && now.Sub(oldest) > ing.maxSealingLag {
		return &ErrResourceExhausted{
			Reason:     "sealing lag exceeded threshold",
			RetryAfter: time.Second,
		}
	}
	return nil
}
