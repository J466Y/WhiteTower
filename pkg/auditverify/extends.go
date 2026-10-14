package auditverify

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"
)

var (
	// ErrShorter means that the log has fewer leaves than a checkpoint signed:
	// it was rolled back.
	ErrShorter = errors.New("the log is shorter than the checkpoint")
	// ErrForked means that the log's tree, at the size a checkpoint signed,
	// has another root: its history was changed.
	ErrForked = errors.New("the log does not extend the checkpoint")
)

// Extends checks that the log still holds the tree of cp, a checkpoint kept
// outside it, for example by the SIEM: that the log's first cp.Size leaves
// have the root that cp signs. A log rolled back fails with ErrShorter, and a
// log whose history was rewritten, even in full and signed again, with
// ErrForked.
//
// Extends reads a few stored hashes of the tree, so it can run often, for
// example after each checkpoint the SIEM receives. Verify checks those
// hashes against the events. Together, they prove that the events are those
// that cp signed.
func Extends(ctx context.Context, src Source, cp Checkpoint) error {
	size, err := src.Size(ctx)
	if err != nil {
		return err
	}
	if size < cp.Size {
		return fmt.Errorf("auditverify: %w: it has %d leaves, and the checkpoint signs %d", ErrShorter, size, cp.Size)
	}
	root, err := tlog.TreeHash(cp.Size, hashReader{ctx, src})
	switch {
	case errors.Is(err, errHashMissing):
		return fmt.Errorf("auditverify: %w: %w", ErrForked, err)
	case err != nil:
		return err
	case root != cp.Root:
		return fmt.Errorf("auditverify: %w: its tree of %d leaves has the root %x, and the checkpoint signs %x", ErrForked, cp.Size, root, cp.Root)
	}
	return nil
}

// errHashMissing means that the log has not got a stored hash of its tree.
var errHashMissing = errors.New("a stored hash of the tree is missing")

// hashReader reads a Source's stored hashes for tlog, whose HashReader takes
// no context: it carries the one of the call.
type hashReader struct {
	ctx context.Context
	src Source
}

func (r hashReader) ReadHashes(indexes []int64) ([]Hash, error) {
	got, err := r.src.TreeHashes(r.ctx, indexes)
	if err != nil {
		return nil, err
	}
	out := make([]Hash, len(indexes))
	for i, index := range indexes {
		h, ok := got[index]
		if !ok {
			return nil, fmt.Errorf("%w: %d", errHashMissing, index)
		}
		out[i] = h
	}
	return out, nil
}
