package auditverify

import (
	"fmt"

	"golang.org/x/mod/sumdb/tlog"
)

// CheckInclusion checks that event is the leaf at index in the tree of cp,
// with the proof of inclusion that the log gave for them.
func CheckInclusion(proof []Hash, cp Checkpoint, index int64, event []byte) error {
	if index < 0 || index >= cp.Size {
		return fmt.Errorf("auditverify: a tree of %d leaves has no leaf %d", cp.Size, index)
	}
	if err := tlog.CheckRecord(proof, cp.Size, cp.Root, index, LeafHash(event)); err != nil {
		return fmt.Errorf("auditverify: the event is not leaf %d of the tree of %d leaves: %w", index, cp.Size, err)
	}
	return nil
}

// CheckConsistency checks that the tree of newer extends the tree of older:
// that its first older.Size leaves are those of older. The proof is the one
// the log gave for the two sizes.
func CheckConsistency(proof []Hash, older, newer Checkpoint) error {
	switch {
	case older.Origin != newer.Origin:
		return fmt.Errorf("auditverify: checkpoints of two logs, %q and %q", older.Origin, newer.Origin)
	case older.Size > newer.Size:
		return fmt.Errorf("auditverify: the older checkpoint signs %d leaves, more than the newer's %d", older.Size, newer.Size)
	}
	if err := tlog.CheckTree(proof, newer.Size, newer.Root, older.Size, older.Root); err != nil {
		return fmt.Errorf("auditverify: the tree of %d leaves does not extend the tree of %d: %w", newer.Size, older.Size, err)
	}
	return nil
}
