package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/auth"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// ErrEventNotFound is returned when an audit event does not exist.
var ErrEventNotFound = errors.New("audit event not found")

// EventFilter specifies filter parameters for querying the audit log.
type EventFilter struct {
	From             *time.Time
	To               *time.Time
	AgentID          *uuid.UUID
	ActorID          *string
	ActorType        *string
	EventType        *string
	Action           *string
	Outcome          *string
	Source           *string
	Cursor           string
	Limit            int
	OwnerPrincipalID *uuid.UUID
}

// EventRecord represents an audit event as stored in the database.
type EventRecord struct {
	ID             uuid.UUID
	Time           time.Time
	Source         string
	Type           string
	SubjectAgentID *uuid.UUID
	ActorType      *string
	ActorID        *string
	Action         *string
	Outcome        *string
	Reason         *string
	RequestID      *string
	TraceID        *string
	IngestedAt     time.Time
	Data           map[string]any
	Canonical      string
}

// InclusionProof represents the cryptographic Merkle tree audit path for an event.
type InclusionProof struct {
	LeafIndex  int64
	TreeSize   int64
	RootHash   string   // base64
	Hashes     []string // base64
	Checkpoint string   // signed note
}

// EventDetail holds an audit event and its cryptographic inclusion proof.
type EventDetail struct {
	Event EventRecord
	Proof *InclusionProof
}

// QueryResult represents a paginated page of audit events.
type QueryResult struct {
	Events     []EventRecord
	NextCursor string
}

// CheckpointRecord holds a signed checkpoint of the audit log.
type CheckpointRecord struct {
	TreeSize  int64
	RootHash  string
	KeyID     string
	Note      string
	CreatedAt time.Time
}

// encodeCursor formats (event_time, id) as an opaque URL-safe string.
func encodeCursor(t time.Time, id uuid.UUID) string {
	raw := fmt.Sprintf("%s,%s", t.Format(time.RFC3339Nano), id.String())
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor parses an opaque cursor string into (event_time, id).
func decodeCursor(cursor string) (*time.Time, *uuid.UUID, error) {
	if cursor == "" {
		return nil, nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid cursor: %w", err)
	}
	parts := strings.Split(string(b), ",")
	if len(parts) != 2 {
		return nil, nil, errors.New("invalid cursor format")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid cursor timestamp: %w", err)
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid cursor id: %w", err)
	}
	return &t, &id, nil
}

// QueryEvents searches the audit log with keyset cursor pagination.
func (l *Log) QueryEvents(ctx context.Context, filter EventFilter) (QueryResult, error) {
	limit := 50
	if filter.Limit > 0 {
		limit = min(filter.Limit, 100)
	}
	limit32 := int32(limit) //nolint:gosec // G115: limit is bounded between 1 and 100

	cursorTime, cursorID, err := decodeCursor(filter.Cursor)
	if err != nil {
		return QueryResult{}, err
	}

	var rows []auditdb.QueryEventsRow
	err = l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		rows, err = auditdb.New(tx).QueryEvents(ctx, auditdb.QueryEventsParams{
			FromTime:         filter.From,
			ToTime:           filter.To,
			SubjectAgentID:   filter.AgentID,
			ActorID:          filter.ActorID,
			ActorType:        filter.ActorType,
			EventType:        filter.EventType,
			EventAction:      filter.Action,
			Outcome:          filter.Outcome,
			EventSource:      filter.Source,
			CursorTime:       cursorTime,
			CursorID:         cursorID,
			OwnerPrincipalID: filter.OwnerPrincipalID,
			PageLimit:        limit32 + 1,
		})
		return err
	})
	if err != nil {
		return QueryResult{}, err
	}

	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}

	events := make([]EventRecord, len(rows))
	for i, r := range rows {
		var data map[string]any
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(r.Canonical, &env); err == nil {
			data = env.Data
		}
		if data == nil {
			data = make(map[string]any)
		}
		events[i] = EventRecord{
			ID:             r.ID,
			Time:           r.EventTime,
			Source:         r.Source,
			Type:           r.Type,
			SubjectAgentID: r.SubjectAgentID,
			ActorType:      &r.ActorType,
			ActorID:        r.ActorID,
			Action:         &r.Action,
			Outcome:        r.Outcome,
			Reason:         r.Reason,
			RequestID:      r.RequestID,
			TraceID:        r.TraceID,
			IngestedAt:     r.IngestedAt,
			Data:           data,
			Canonical:      string(r.Canonical),
		}
	}

	var nextCursor string
	if hasMore && len(events) > 0 {
		last := events[len(events)-1]
		nextCursor = encodeCursor(last.Time, last.ID)
	}

	return QueryResult{
		Events:     events,
		NextCursor: nextCursor,
	}, nil
}

// GetEvent fetches an event by ID and computes its Merkle inclusion proof against
// the latest signed checkpoint, if sealed.
func (l *Log) GetEvent(ctx context.Context, id uuid.UUID) (EventDetail, error) {
	var row auditdb.GetEventByIDRow
	var cp auditdb.WhitetowerAuditCheckpoint
	var hasCP bool
	var proof tlog.RecordProof

	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		row, err = auditdb.New(tx).GetEventByID(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEventNotFound
			}
			return err
		}

		if row.LeafIndex == nil {
			return nil
		}

		cp, err = auditdb.New(tx).GetLatestCheckpoint(ctx)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		hasCP = true

		leafIndex := *row.LeafIndex
		if leafIndex >= cp.TreeSize {
			return nil
		}

		hr := &txHashReader{ctx: ctx, tx: tx}
		proof, err = tlog.ProveRecord(cp.TreeSize, leafIndex, hr)
		if err != nil {
			return fmt.Errorf("proving leaf %d in tree of size %d: %w", leafIndex, cp.TreeSize, err)
		}
		return nil
	})
	if err != nil {
		return EventDetail{}, err
	}

	var data map[string]any
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(row.Canonical, &env); err == nil {
		data = env.Data
	}
	if data == nil {
		data = make(map[string]any)
	}

	event := EventRecord{
		ID:             row.ID,
		Time:           row.EventTime,
		Source:         row.Source,
		Type:           row.Type,
		SubjectAgentID: row.SubjectAgentID,
		ActorType:      &row.ActorType,
		ActorID:        row.ActorID,
		Action:         &row.Action,
		Outcome:        row.Outcome,
		Reason:         row.Reason,
		RequestID:      row.RequestID,
		TraceID:        row.TraceID,
		IngestedAt:     row.IngestedAt,
		Data:           data,
		Canonical:      string(row.Canonical),
	}

	var p *InclusionProof
	if proof != nil && hasCP {
		hashes := make([]string, len(proof))
		for i, h := range proof {
			hashes[i] = base64.StdEncoding.EncodeToString(h[:])
		}
		p = &InclusionProof{
			LeafIndex:  *row.LeafIndex,
			TreeSize:   cp.TreeSize,
			RootHash:   base64.StdEncoding.EncodeToString(cp.RootHash),
			Hashes:     hashes,
			Checkpoint: cp.SignedNote,
		}
	}

	return EventDetail{
		Event: event,
		Proof: p,
	}, nil
}

type txHashReader struct {
	ctx context.Context
	tx  *db.Tx
}

func (r *txHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	rows, err := auditdb.New(r.tx).TreeHashes(r.ctx, indexes)
	if err != nil {
		return nil, err
	}
	hashIndex := make(map[int64]tlog.Hash, len(rows))
	for _, row := range rows {
		if h, ok := toHash(row.Hash); ok {
			hashIndex[row.HashIndex] = h
		}
	}
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		h, ok := hashIndex[idx]
		if !ok {
			return nil, fmt.Errorf("missing tree hash at index %d", idx)
		}
		out[i] = h
	}
	return out, nil
}

// ListCheckpoints returns stored checkpoints signed over the audit log Merkle tree.
func (l *Log) ListCheckpoints(ctx context.Context) ([]CheckpointRecord, error) {
	var rows []auditdb.WhitetowerAuditCheckpoint
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		rows, err = auditdb.New(tx).ListCheckpoints(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]CheckpointRecord, len(rows))
	for i, r := range rows {
		out[i] = CheckpointRecord{
			TreeSize:  r.TreeSize,
			RootHash:  base64.StdEncoding.EncodeToString(r.RootHash),
			KeyID:     r.KeyID,
			Note:      r.SignedNote,
			CreatedAt: r.CreatedAt,
		}
	}
	return out, nil
}

// IsAgentOwner checks if the principal is an active owner or delegate of the specified agent.
func (l *Log) IsAgentOwner(ctx context.Context, agentID, principalID uuid.UUID) (bool, error) {
	var isOwner bool
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		isOwner, err = auditdb.New(tx).IsAgentOwner(ctx, auditdb.IsAgentOwnerParams{
			AgentID:     agentID,
			PrincipalID: principalID,
		})
		return err
	})
	return isOwner, err
}

// ReadAuditParams defines details for auditing a read operation (AUD-09).
type ReadAuditParams struct {
	Actor          *auth.Principal
	Operation      string // "query", "get", "checkpoints", "keys"
	Query          map[string]any
	ResultsCount   int
	SubjectAgentID *uuid.UUID
}

// RecordRead writes a whitetower.audit.read.v1 event for an audit read operation (AUD-09).
func (l *Log) RecordRead(ctx context.Context, p ReadAuditParams) error {
	if l.writer == nil {
		return nil
	}

	actorType := "system"
	var actorID string
	if p.Actor != nil {
		actorID = p.Actor.ID
		if p.Actor.IsBreakglass {
			actorType = "breakglass"
		} else if p.Actor.Kind == auth.ServiceAccount {
			actorType = "service_account"
		} else {
			actorType = "human"
		}
	}

	actorData := map[string]any{
		"type": actorType,
	}
	if actorID != "" {
		actorData["id"] = actorID
	}

	data := map[string]any{
		"actor":         actorData,
		"operation":     p.Operation,
		"results_count": p.ResultsCount,
	}
	if len(p.Query) > 0 {
		data["query"] = p.Query
	}

	var subject string
	if p.SubjectAgentID != nil {
		subject = p.SubjectAgentID.String()
	}

	event := Event{
		Type:    "whitetower.audit.read.v1",
		Subject: subject,
		Data:    data,
	}

	return l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return l.writer.Record(ctx, tx, event)
	})
}
