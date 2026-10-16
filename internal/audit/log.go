package audit

import (
	"context"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Log reads the audit log as the database holds it, to verify it with
// pkg/auditverify: its methods are those of auditverify.Source, which a domain
// package does not import (docs/development/internals.md). It hands over what
// the database holds, and leaves the judging to the verifier.
type Log struct {
	db     *db.DB
	writer *Writer
}

// NewLog returns the audit log of a database.
func NewLog(d *db.DB) *Log { return &Log{db: d} }

// WithWriter attaches an audit writer to record log access events.
func (l *Log) WithWriter(w *Writer) *Log {
	l.writer = w
	return l
}

// Size returns how many leaves the log has.
func (l *Log) Size(ctx context.Context) (int64, error) {
	var size int64
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		size, err = auditdb.New(tx).TreeSize(ctx)
		return err
	})
	return size, err
}

// Leaves calls visit with each leaf of index from to to-1, in index order: its
// index, its stored hash and its event's canonical bytes, nil when the event
// is missing. A leaf whose stored hash is not a hash is left out, as missing.
func (l *Log) Leaves(ctx context.Context, from, to int64, visit func(index int64, hash tlog.Hash, event []byte) error) error {
	var rows []auditdb.LogLeavesRow
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		rows, err = auditdb.New(tx).LogLeaves(ctx, auditdb.LogLeavesParams{FromIndex: from, ToIndex: to})
		return err
	})
	if err != nil {
		return err
	}
	for _, r := range rows {
		h, ok := toHash(r.LeafHash)
		if !ok {
			continue
		}
		if err := visit(r.LeafIndex, h, r.Canonical); err != nil {
			return err
		}
	}
	return nil
}

// TreeHashes returns those of the given stored hashes of the tree that the log
// has, by index. A stored value that is not a hash is left out, as missing.
func (l *Log) TreeHashes(ctx context.Context, indexes []int64) (map[int64]tlog.Hash, error) {
	var rows []auditdb.WhitetowerAuditTreeHash
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		rows, err = auditdb.New(tx).TreeHashes(ctx, indexes)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make(map[int64]tlog.Hash, len(rows))
	for _, r := range rows {
		if h, ok := toHash(r.Hash); ok {
			out[r.HashIndex] = h
		}
	}
	return out, nil
}

// Checkpoints calls visit with each stored checkpoint, in order of size: the
// size and root hash stored with it, and its signed note.
func (l *Log) Checkpoints(ctx context.Context, visit func(size int64, root tlog.Hash, note []byte) error) error {
	var rows []auditdb.LogCheckpointsRow
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		rows, err = auditdb.New(tx).LogCheckpoints(ctx)
		return err
	})
	if err != nil {
		return err
	}
	for _, r := range rows {
		// A stored root that is not a hash differs from the signed one.
		root, _ := toHash(r.RootHash)
		if err := visit(r.TreeSize, root, []byte(r.SignedNote)); err != nil {
			return err
		}
	}
	return nil
}

// CheckpointKeys returns the public halves of the checkpoint keys the
// database holds, active, next and retired, as JSON Web Keys. Keys from the
// database verify a log only against itself: a log rewritten and signed again
// comes with its new key (see auditverify.Keys).
func (l *Log) CheckpointKeys(ctx context.Context) ([][]byte, error) {
	var keys [][]byte
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		keys, err = auditdb.New(tx).CheckpointKeys(ctx)
		return err
	})
	return keys, err
}

// Pruned calls visit with each pruned range [from, to) the log has,
// in ascending index order. It satisfies auditverify.PrunedSource through
// structural typing without importing pkg/auditverify.
func (l *Log) Pruned(ctx context.Context, visit func(from, to int64) error) error {
	var rows []auditdb.WhitetowerAuditPrunedRange
	err := l.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		rows, err = auditdb.New(tx).ListPrunedRanges(ctx)
		return err
	})
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := visit(r.FromLeafIndex, r.ToLeafIndex); err != nil {
			return err
		}
	}
	return nil
}

// toHash reads a stored hash, and reports whether it is one: the database
// refuses other lengths, unless someone changed it from outside the core.
func toHash(b []byte) (tlog.Hash, bool) {
	var h tlog.Hash
	return h, copy(h[:], b) == len(h) && len(b) == len(h)
}
