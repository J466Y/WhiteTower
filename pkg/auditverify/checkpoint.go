package auditverify

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// Checkpoint is a checkpoint whose signature verified: in the log named
// Origin, the tree of Size leaves has the root hash Root.
type Checkpoint struct {
	Origin string
	Size   int64
	Root   Hash
	// Note is the signed note, exactly as signed.
	Note []byte
}

// OpenCheckpoint verifies a checkpoint, a signed note in the C2SP
// tlog-checkpoint format, and reads it. It fails unless one of the keys signed
// it, and its text names the keys' origin.
func OpenCheckpoint(signed []byte, keys *Keys) (Checkpoint, error) {
	if keys == nil {
		return Checkpoint{}, errors.New("auditverify: no keys to verify the checkpoint with")
	}
	n, err := note.Open(signed, keys.verifiers)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("auditverify: checkpoint: %w", err)
	}
	c, err := parseCheckpoint(n.Text)
	if err != nil {
		return Checkpoint{}, err
	}
	if c.Origin != keys.origin {
		return Checkpoint{}, fmt.Errorf("auditverify: checkpoint of the log %q, not of %q", c.Origin, keys.origin)
	}
	c.Note = bytes.Clone(signed)
	return c, nil
}

// parseCheckpoint reads the text of a checkpoint: the origin, the tree size
// in decimal and the root hash in base64, each on a line of its own. Lines
// after them are extensions, which carry nothing that verification needs.
func parseCheckpoint(text string) (Checkpoint, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if !strings.HasSuffix(text, "\n") || len(lines) < 3 || lines[0] == "" {
		return Checkpoint{}, errors.New("auditverify: checkpoint: not an origin, a size and a root hash")
	}
	size, err := parseSize(lines[1])
	if err != nil {
		return Checkpoint{}, err
	}
	root, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(root) != len(Hash{}) {
		return Checkpoint{}, fmt.Errorf("auditverify: checkpoint: %q is not a root hash", lines[2])
	}
	return Checkpoint{Origin: lines[0], Size: size, Root: Hash(root)}, nil
}

// parseSize reads a tree size: ASCII decimal digits, with no sign and no
// leading zero.
func parseSize(s string) (int64, error) {
	valid := s != "" && (s == "0" || s[0] != '0')
	for _, c := range s {
		valid = valid && c >= '0' && c <= '9'
	}
	size, err := strconv.ParseInt(s, 10, 64)
	if !valid || err != nil {
		return 0, fmt.Errorf("auditverify: checkpoint: %q is not a tree size", s)
	}
	return size, nil
}
