package auditverify

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/mod/sumdb/tlog"
)

// Source reads a log as it is stored. Verify checks what it reads.
type Source interface {
	// Size returns how many leaves the log has.
	Size(ctx context.Context) (int64, error)
	// Leaves calls visit with each leaf of index from to to-1 that the log
	// has, in index order: its index, the hash stored for it, and the
	// canonical bytes of its event, nil when the log has not got them.
	Leaves(ctx context.Context, from, to int64, visit func(index int64, hash Hash, event []byte) error) error
	// TreeHashes returns those of the given stored hashes of the tree that
	// the log has, by their index in the layout of golang.org/x/mod/sumdb/tlog.
	TreeHashes(ctx context.Context, indexes []int64) (map[int64]Hash, error)
	// Checkpoints calls visit with each checkpoint the log stores, in order of
	// size: the size and root hash stored with it, and its signed note.
	Checkpoints(ctx context.Context, visit func(size int64, root Hash, note []byte) error) error
}

// PrunedRange represents a range of leaf indexes [From, To) whose events were
// dropped by retention (plan P1-02, step 9).
type PrunedRange struct {
	From int64
	To   int64
}

// PrunedSource is an optional capability of a Source that tracks leaf ranges
// whose events were pruned by retention. Found with a type assertion.
type PrunedSource interface {
	// Pruned calls visit with each pruned range [from, to) the log has,
	// in ascending index order.
	Pruned(ctx context.Context, visit func(from, to int64) error) error
}

// Options tune Verify.
type Options struct {
	// Keys are those the checkpoints must be signed with (see Keys). Required.
	Keys *Keys
	// Chunk is how many leaves Verify reads at a time: 10,000 by default,
	// which keeps each read of the core's database to index lookups.
	Chunk int64
	// MaxProblems is how many problems a report lists at most: 100 by default.
	MaxProblems int
}

// Kind is a kind of problem.
type Kind string

// The kinds of problem that Verify reports.
const (
	// A leaf is missing from the log.
	LeafMissing Kind = "leaf_missing"
	// A leaf's event is missing.
	EventMissing Kind = "event_missing"
	// A leaf's event does not hash to the leaf: it was changed or replaced.
	EventAltered Kind = "event_altered"
	// A stored hash of the tree is missing, or differs from the one the
	// events give.
	TreeAltered Kind = "tree_altered"
	// A checkpoint does not verify: none of the keys signed it, or it is
	// malformed, or it is another log's.
	CheckpointInvalid Kind = "checkpoint_invalid"
	// A checkpoint's stored size or root differs from what it signs.
	CheckpointAltered Kind = "checkpoint_altered"
	// A checkpoint signs a tree larger than the log: leaves were removed.
	CheckpointBeyond Kind = "checkpoint_beyond"
	// The events give a checkpoint's tree another root than the one it signs.
	CheckpointMismatch Kind = "checkpoint_mismatch"
)

// Problem is a place where the log differs from what was signed.
type Problem struct {
	Kind Kind
	// Index is the leaf's index or, for a checkpoint, the size of the tree it
	// signs.
	Index int64
	// Detail says what differs.
	Detail string
}

func (p Problem) String() string { return fmt.Sprintf("%s at %d: %s", p.Kind, p.Index, p.Detail) }

// Report is what Verify found.
type Report struct {
	// Size is how many leaves the log has. Verify read them all.
	Size int64
	// Checkpoints is how many checkpoints verified and match the events.
	Checkpoints int
	// Latest is the latest of those checkpoints, nil if there is none. The
	// leaves after it are not signed yet: the next checkpoint signs them.
	Latest *Checkpoint
	// PrunedRanges lists the ranges of leaves whose events were pruned by
	// retention.
	PrunedRanges []PrunedRange
	// PrunedLeaves is how many leaves had their events pruned within those
	// ranges.
	PrunedLeaves int64
	// Problems are the first problems found, in the order of the log: the
	// first is where the log first differs from what was signed.
	Problems []Problem
	// Total is how many problems were found, including those not listed.
	Total int
}

// OK reports whether the log verified: no problem at all.
func (r *Report) OK() bool { return r.Total == 0 }

// Verify reads the whole log. It recomputes every leaf from its event and the
// tree from the leaves, and checks the stored leaves, tree hashes and
// checkpoints against them.
//
// A log rewritten in full, tree and checkpoints included, and signed again
// with another key verifies with that key. Hence opts.Keys, and Extends, which
// checks the log against a checkpoint kept outside it.
func Verify(ctx context.Context, src Source, opts Options) (*Report, error) {
	v := &verifier{src: src, keys: opts.Keys, chunk: cmp.Or(opts.Chunk, 10_000), max: cmp.Or(opts.MaxProblems, 100)}
	switch {
	case v.keys == nil:
		return nil, errors.New("auditverify: Verify needs the keys checkpoints are signed with")
	case v.chunk < 1 || v.max < 1:
		return nil, errors.New("auditverify: Chunk and MaxProblems must be positive")
	}
	return v.run(ctx)
}

// verifier is the state of one Verify.
type verifier struct {
	src   Source
	keys  *Keys
	chunk int64
	max   int

	pruned []PrunedRange

	report Report
	// signed holds the problems of the checkpoints themselves, found first;
	// found, the others, found in the order of the log.
	signed, found []Problem
	// pending are the checkpoints that verified, by size, each waiting for
	// the tree to reach its size.
	pending []Checkpoint
	// tree is rebuilt from the events; nil once it cannot be.
	tree *tree
	// diverged is set once a stored hash of the tree differed: those after it
	// would all differ, and say nothing more.
	diverged bool
}

func (v *verifier) run(ctx context.Context) (*Report, error) {
	// The checkpoints first, then the size: the log only grows, so a
	// checkpoint read before the size signs more leaves only if some were
	// removed.
	err := v.src.Checkpoints(ctx, func(size int64, root Hash, signed []byte) error {
		cp, err := OpenCheckpoint(signed, v.keys)
		switch {
		case err != nil:
			v.problem(&v.signed, CheckpointInvalid, size, "%v", err)
		case cp.Size != size || cp.Root != root:
			v.problem(&v.signed, CheckpointAltered, size, "stored for %d leaves and the root %x, signed for %d leaves and the root %x",
				size, root, cp.Size, cp.Root)
		default:
			v.pending = append(v.pending, cp)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	size, err := v.src.Size(ctx)
	if err != nil {
		return nil, err
	}
	v.report.Size = size
	slices.SortStableFunc(v.pending, func(a, b Checkpoint) int { return cmp.Compare(a.Size, b.Size) })
	for i, cp := range v.pending {
		if cp.Size > size {
			for _, cp := range v.pending[i:] {
				v.problem(&v.signed, CheckpointBeyond, cp.Size, "it signs %d leaves, and the log has %d", cp.Size, size)
			}
			v.pending = v.pending[:i]
			break
		}
	}

	if ps, ok := v.src.(PrunedSource); ok {
		err := ps.Pruned(ctx, func(from, to int64) error {
			if from < to {
				v.pruned = append(v.pruned, PrunedRange{From: from, To: to})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(v.pruned, func(a, b PrunedRange) int { return cmp.Compare(a.From, b.From) })
		v.report.PrunedRanges = slices.Clone(v.pruned)
	}

	v.tree = &tree{}
	for from := int64(0); from < size; from += v.chunk {
		if err := v.read(ctx, from, min(from+v.chunk, size)); err != nil {
			return nil, err
		}
	}

	problems := slices.Concat(v.signed, v.found)
	slices.SortStableFunc(problems, func(a, b Problem) int { return cmp.Compare(a.Index, b.Index) })
	v.report.Problems = problems[:min(len(problems), v.max)]
	return &v.report, nil
}

func (v *verifier) isPruned(index int64) bool {
	_, found := slices.BinarySearchFunc(v.pruned, index, func(r PrunedRange, target int64) int {
		if target < r.From {
			return 1
		}
		if target >= r.To {
			return -1
		}
		return 0
	})
	return found
}

// read checks the leaves of index from to to-1, with the tree hashes stored
// for them.
func (v *verifier) read(ctx context.Context, from, to int64) error {
	var stored map[int64]Hash
	if !v.diverged && v.tree != nil {
		first, end := tlog.StoredHashIndex(0, from), tlog.StoredHashIndex(0, to)
		indexes := make([]int64, 0, end-first)
		for i := first; i < end; i++ {
			indexes = append(indexes, i)
		}
		var err error
		if stored, err = v.src.TreeHashes(ctx, indexes); err != nil {
			return err
		}
	}
	next := from
	err := v.src.Leaves(ctx, from, to, func(index int64, hash Hash, event []byte) error {
		if index < next || index >= to {
			return fmt.Errorf("auditverify: the source gave leaf %d where leaves %d to %d were expected", index, next, to-1)
		}
		for ; next < index; next++ {
			v.missing(next, stored)
		}
		v.leaf(index, hash, event, stored)
		next++
		return nil
	})
	if err != nil {
		return err
	}
	for ; next < to; next++ {
		v.missing(next, stored)
	}
	return nil
}

// leaf checks a leaf against its event, and adds it to the tree.
func (v *verifier) leaf(index int64, hash Hash, event []byte, stored map[int64]Hash) {
	if event == nil {
		if v.isPruned(index) {
			v.report.PrunedLeaves++
		} else {
			// The leaf's own hash keeps the tree going: its checkpoints still
			// verify what remains.
			v.problem(&v.found, EventMissing, index, "the event of leaf %d is missing", index)
		}
	} else if h := LeafHash(event); h != hash {
		v.problem(&v.found, EventAltered, index, "the event hashes to %x, and the leaf is %x", h, hash)
		// The tree is rebuilt from what the events say. Its stored hashes
		// hold the leaf, so they differ from here on, which says nothing
		// more.
		hash, v.diverged = h, true
	}
	v.append(index, hash, stored)
}

// missing reports a leaf missing from the log. The tree goes on with the
// leaf's hash as the stored tree holds it, if it does.
func (v *verifier) missing(index int64, stored map[int64]Hash) {
	hash, ok := stored[tlog.StoredHashIndex(0, index)]
	if !ok && v.tree != nil {
		v.problem(&v.found, LeafMissing, index, "the log has no leaf %d, and the tree cannot be rebuilt past it", index)
		v.tree = nil
		return
	}
	v.problem(&v.found, LeafMissing, index, "the log has no leaf %d", index)
	v.append(index, hash, stored)
}

// append adds a leaf to the tree, compares the tree hashes the log stored for
// it, and checks the checkpoints of the tree's new size.
func (v *verifier) append(index int64, leaf Hash, stored map[int64]Hash) {
	if v.tree == nil {
		return
	}
	for _, h := range v.tree.append(leaf) {
		if v.diverged {
			break
		}
		if got, ok := stored[h.index]; !ok || got != h.hash {
			v.problem(&v.found, TreeAltered, index, "the tree hash %d stored with leaf %d is missing or differs from the events'", h.index, index)
			v.diverged = true
		}
	}
	for len(v.pending) > 0 && v.pending[0].Size == v.tree.size {
		cp := v.pending[0]
		v.pending = v.pending[1:]
		if root := v.tree.root(); root != cp.Root {
			v.problem(&v.found, CheckpointMismatch, cp.Size, "the events give the tree of %d leaves the root %x, and the checkpoint signs %x",
				cp.Size, root, cp.Root)
			continue
		}
		v.report.Checkpoints++
		v.report.Latest = &cp
	}
}

// problem records a problem in list, unless list is full.
func (v *verifier) problem(list *[]Problem, kind Kind, index int64, format string, args ...any) {
	v.report.Total++
	if len(*list) < v.max || list == &v.signed {
		*list = append(*list, Problem{Kind: kind, Index: index, Detail: fmt.Sprintf(format, args...)})
	}
}

// tree is a Merkle tree rebuilt leaf by leaf, of which it keeps only the
// right edge: the roots of its complete subtrees, largest first, which is all
// that an append and the root read.
type tree struct {
	size int64
	edge []subtree
}

// subtree is a complete subtree: its level, 0 for a leaf, and its hash.
type subtree struct {
	level int
	hash  Hash
}

// stored is a hash of the tree, with its index in the layout of tlog.
type stored struct {
	index int64
	hash  Hash
}

// append adds a leaf, and returns the hashes a log stores for it: the leaf's,
// then those of the subtrees it completes.
func (t *tree) append(leaf Hash) []stored {
	n := t.size
	out := []stored{{tlog.StoredHashIndex(0, n), leaf}}
	t.edge = append(t.edge, subtree{0, leaf})
	for len(t.edge) >= 2 {
		left, right := t.edge[len(t.edge)-2], t.edge[len(t.edge)-1]
		if left.level != right.level {
			break
		}
		h := tlog.NodeHash(left.hash, right.hash)
		t.edge = append(t.edge[:len(t.edge)-2], subtree{left.level + 1, h})
		out = append(out, stored{tlog.StoredHashIndex(left.level+1, n>>(left.level+1)), h})
	}
	t.size++
	return out
}

// root returns the root hash of the tree, as tlog.TreeHash computes it.
func (t *tree) root() Hash {
	if len(t.edge) == 0 {
		return Hash{}
	}
	h := t.edge[len(t.edge)-1].hash
	for i := len(t.edge) - 2; i >= 0; i-- {
		h = tlog.NodeHash(t.edge[i].hash, h)
	}
	return h
}
