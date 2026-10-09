package audit

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/clock"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/jobs"
	"github.com/J466Y/WhiteTower/internal/platform/keys"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

const (
	// sealRound is how often the sealer drains the queue: an event waits
	// about one round to be sealed (spike S3).
	sealRound = 200 * time.Millisecond
	// maxBatch bounds the events that one transaction seals.
	maxBatch = 5000
	// checkpointLeaves is how many new leaves call for a checkpoint before
	// its interval has passed.
	checkpointLeaves = 10000
	// maxRetry bounds the wait after failed rounds.
	maxRetry = 5 * time.Second
)

// SealerOptions are what the sealer needs from the rest of the server.
type SealerOptions struct {
	DB *db.DB
	// Writer records the checkpoints' events.
	Writer *Writer
	// Key signs the checkpoints.
	Key keys.Ed25519
	// Origin is the log's name in its checkpoints.
	Origin string
	// Interval is the longest wait for a checkpoint over a sealed event.
	Interval time.Duration
	Clock    clock.Clock
	Logger   *slog.Logger
	Metrics  *metrics.Audit
}

// Sealer appends the queued events to the audit log's Merkle tree (RFC 6962,
// with golang.org/x/mod/sumdb/tlog), and signs checkpoints over it (plan
// P1-02, steps 3 and 4). It runs as the background job audit-sealer, on one
// replica at a time.
//
// Each round drains the queue, a batch of at most 5,000 events per
// transaction: their leaves, in the order of the queue, and the tree's new
// hashes. The sealer keeps the right edge of the tree in memory, which is
// all that an append reads. Should two sealers ever run at once, the primary
// key of the leaves refuses the batch of one of them; any failure makes the
// next round load the tree again from the database, so that a crash, even in
// the middle of a batch, leaves no gap and no duplicate.
type Sealer struct {
	opts SealerOptions

	// The tree as the database holds it, while loaded.
	loaded bool
	size   int64
	edge   map[int64]tlog.Hash
	last   checkpointed
	// failing is Run's: whether the last round failed.
	failing bool
}

// checkpointed is the latest checkpoint.
type checkpointed struct {
	size int64
	at   time.Time
}

// NewSealer returns a sealer.
func NewSealer(opts SealerOptions) *Sealer {
	opts.Clock = cmp.Or[clock.Clock](opts.Clock, clock.System)
	return &Sealer{opts: opts}
}

// Job returns the sealer as the background job audit-sealer.
func (s *Sealer) Job() jobs.Job {
	return jobs.Job{Name: "audit-sealer", Schedule: jobs.Every(sealRound), Run: s.Run}
}

// Run seals, round after round, until ctx ends, which is when this replica
// stops leading the job. It starts from the tree that the database holds,
// which another replica may have grown.
func (s *Sealer) Run(ctx context.Context) error {
	s.loaded = false
	retry := sealRound
	for {
		wait := sealRound
		err := s.round(ctx)
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err != nil:
			s.loaded = false
			s.opts.Metrics.Failed()
			level := slog.LevelDebug
			if !s.failing {
				s.failing, level = true, slog.LevelWarn
			}
			s.opts.Logger.Log(ctx, level, "audit sealer: a round failed; the next one loads the tree again",
				"error", logging.Sanitize(err.Error()), "retry_in", retry.String())
			wait, retry = retry, min(2*retry, maxRetry)
		case s.failing:
			s.failing, retry = false, sealRound
			s.opts.Logger.InfoContext(ctx, "audit sealer: sealing again")
		}
		t := s.opts.Clock.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C():
		}
	}
}

// round drains the queue, then signs a checkpoint if one is due.
func (s *Sealer) round(ctx context.Context) error {
	if !s.loaded {
		if err := s.load(ctx); err != nil {
			return fmt.Errorf("loading the tree: %w", err)
		}
	}
	for {
		n, err := s.seal(ctx)
		if err != nil {
			return fmt.Errorf("sealing: %w", err)
		}
		if n < maxBatch {
			break
		}
	}
	if err := s.checkpoint(ctx); err != nil {
		return fmt.Errorf("signing a checkpoint: %w", err)
	}
	return nil
}

// load reads the tree's size, its right edge and its latest checkpoint from
// the database, and registers the checkpoint key.
func (s *Sealer) load(ctx context.Context) error {
	var size int64
	var edge map[int64]tlog.Hash
	var last checkpointed
	err := s.opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := auditdb.New(tx)
		var err error
		if size, err = q.TreeSize(ctx); err != nil {
			return err
		}
		indexes := rightEdge(size)
		rows, err := q.TreeHashes(ctx, indexes)
		if err != nil {
			return err
		}
		if len(rows) != len(indexes) {
			return fmt.Errorf("%d of the %d hashes of the tree's right edge are missing", len(indexes)-len(rows), len(indexes))
		}
		edge = make(map[int64]tlog.Hash, len(rows))
		for _, r := range rows {
			edge[r.HashIndex] = tlog.Hash(r.Hash)
		}
		latest, err := q.LatestCheckpoint(ctx)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			last = checkpointed{}
		case err != nil:
			return err
		default:
			last = checkpointed{size: latest.TreeSize, at: latest.CreatedAt}
		}
		return registerKey(ctx, q, s.opts.Key)
	})
	if err != nil {
		return err
	}
	s.loaded, s.size, s.edge, s.last = true, size, edge, last
	s.opts.Metrics.Size(size)
	return nil
}

// seal seals a batch of the queue, and returns its size.
func (s *Sealer) seal(ctx context.Context) (int, error) {
	var (
		claimed []auditdb.WhitetowerAuditUnsealed
		sealed  time.Time
		size    int64
		added   map[int64]tlog.Hash
	)
	err := s.opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := auditdb.New(tx)
		start := s.opts.Clock.Now()
		var err error
		if claimed, err = q.ClaimUnsealed(ctx, maxBatch); err != nil || len(claimed) == 0 {
			return err
		}
		s.opts.Metrics.Claimed(s.opts.Clock.Now().Sub(start))
		// The order of the log: ingestion time, then audit ID.
		slices.SortFunc(claimed, func(a, b auditdb.WhitetowerAuditUnsealed) int {
			return cmp.Or(a.IngestedAt.Compare(b.IngestedAt), cmp.Compare(a.AuditID.String(), b.AuditID.String()))
		})
		ids := make([]uuid.UUID, len(claimed))
		for i, c := range claimed {
			ids[i] = c.AuditID
		}
		rows, err := q.CanonicalEvents(ctx, ids)
		if err != nil {
			return err
		}
		canonical := make(map[uuid.UUID][]byte, len(rows))
		for _, r := range rows {
			canonical[r.ID] = r.Canonical
		}
		if sealed, err = q.SealingTime(ctx); err != nil {
			return err
		}

		added = map[int64]tlog.Hash{}
		read := s.reader(ctx, q, added)
		size = s.size
		leaves := make([]auditdb.InsertLeavesParams, 0, len(claimed))
		var hashes []auditdb.InsertTreeHashesParams
		for _, c := range claimed {
			raw, ok := canonical[c.AuditID]
			if !ok {
				return fmt.Errorf("event %s is queued but not stored", c.AuditID)
			}
			leaf := tlog.RecordHash(raw)
			stored, err := tlog.StoredHashesForRecordHash(size, leaf, read)
			if err != nil {
				return err
			}
			base := tlog.StoredHashIndex(0, size)
			for i, h := range stored {
				added[base+int64(i)] = h
				hashes = append(hashes, auditdb.InsertTreeHashesParams{HashIndex: base + int64(i), Hash: h[:]})
			}
			leaves = append(leaves, auditdb.InsertLeavesParams{
				LeafIndex: size, AuditID: c.AuditID, IngestedAt: c.IngestedAt, LeafHash: leaf[:], SealedAt: sealed,
			})
			size++
		}
		if _, err := q.InsertLeaves(ctx, leaves); err != nil {
			return err
		}
		_, err = q.InsertTreeHashes(ctx, hashes)
		return err
	})
	if err != nil || len(claimed) == 0 {
		return 0, err
	}
	for idx, h := range added {
		s.edge[idx] = h
	}
	s.size = size
	keep := rightEdge(size)
	for idx := range s.edge {
		if !slices.Contains(keep, idx) {
			delete(s.edge, idx)
		}
	}
	for _, c := range claimed {
		s.opts.Metrics.Sealed(sealed.Sub(c.IngestedAt), size)
	}
	return len(claimed), nil
}

// reader reads the tree's hashes for an append: those of the batch, then
// those of the right edge, then, should any be missing, those in the
// database.
func (s *Sealer) reader(ctx context.Context, q *auditdb.Queries, added map[int64]tlog.Hash) tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		var missing []int64
		for i, idx := range indexes {
			if h, ok := added[idx]; ok {
				out[i] = h
			} else if h, ok := s.edge[idx]; ok {
				out[i] = h
			} else {
				missing = append(missing, idx)
			}
		}
		if len(missing) == 0 {
			return out, nil
		}
		rows, err := q.TreeHashes(ctx, missing)
		if err != nil {
			return nil, err
		}
		found := make(map[int64]tlog.Hash, len(rows))
		for _, r := range rows {
			found[r.HashIndex] = tlog.Hash(r.Hash)
		}
		for i, idx := range indexes {
			if slices.Contains(missing, idx) {
				h, ok := found[idx]
				if !ok {
					return nil, fmt.Errorf("tree hash %d is missing", idx)
				}
				out[i] = h
			}
		}
		return out, nil
	})
}

// rightEdge returns the indexes of the hashes that an append to a tree of
// size n reads: the roots of its complete subtrees.
func rightEdge(n int64) []int64 {
	var out []int64
	start := int64(0)
	for level := 62; level >= 0; level-- {
		if n>>level&1 == 1 {
			out = append(out, tlog.StoredHashIndex(level, start>>level))
			start += 1 << level
		}
	}
	return out
}
