package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/internal/audit/auditdb"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/keys"
)

// checkpointData is the data of a whitetower.audit.checkpoint.v1 event.
type checkpointData struct {
	TreeSize int64  `json:"tree_size"`
	RootHash string `json:"root_hash"`
	KeyID    string `json:"key_id"`
	Note     string `json:"note"`
}

// checkpoint signs a checkpoint over the tree when one is due: when its
// interval has passed, or enough leaves have come, since the last one. It
// stores the checkpoint and records its event, which the next round seals:
// the tree holds the checkpoints up to the one before the latest. A
// checkpoint needs a leaf besides the latest checkpoint's own event, so an
// idle log signs no more.
func (s *Sealer) checkpoint(ctx context.Context) error {
	now := s.opts.Clock.Now()
	fresh := s.size - s.last.size
	switch {
	case fresh == 0, s.last.size > 0 && fresh < 2:
		return nil
	case now.Sub(s.last.at) < s.opts.Interval && fresh < checkpointLeaves:
		return nil
	}
	root, err := tlog.TreeHash(s.size, tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			h, ok := s.edge[idx]
			if !ok {
				return nil, fmt.Errorf("tree hash %d is not on the right edge", idx)
			}
			out[i] = h
		}
		return out, nil
	}))
	if err != nil {
		return err
	}
	signed, err := SignCheckpoint(s.opts.Origin, s.size, root, s.opts.Key)
	if err != nil {
		return err
	}
	err = s.opts.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := auditdb.New(tx).InsertCheckpoint(ctx, auditdb.InsertCheckpointParams{
			TreeSize: s.size, RootHash: root[:], SignedNote: signed, KeyID: s.opts.Key.ID(),
		}); err != nil {
			return err
		}
		return s.opts.Writer.Record(ctx, tx, Event{Type: "whitetower.audit.checkpoint.v1", Data: checkpointData{
			TreeSize: s.size, RootHash: base64.StdEncoding.EncodeToString(root[:]), KeyID: s.opts.Key.ID(), Note: signed,
		}})
	})
	if err != nil {
		return err
	}
	s.last = checkpointed{size: s.size, at: now}
	s.opts.Metrics.Checkpointed(now)
	return nil
}

// SignCheckpoint signs a checkpoint over a tree of size leaves and root, as a
// C2SP signed note under origin, the name of the key.
func SignCheckpoint(origin string, size int64, root tlog.Hash, key keys.Ed25519) (string, error) {
	signed, err := note.Sign(&note.Note{Text: CheckpointText(origin, size, root)}, newNoteSigner(origin, key))
	return string(signed), err
}

// CheckpointText is the body of a checkpoint in the C2SP tlog-checkpoint
// format: the log's origin, the tree's size and its root hash.
func CheckpointText(origin string, size int64, root tlog.Hash) string {
	return fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root[:]))
}

// registerKey makes key the active checkpoint key, keeping the public halves
// of the others, so that the checkpoints they signed still verify.
func registerKey(ctx context.Context, q *auditdb.Queries, key keys.Ed25519) error {
	jwk, err := json.Marshal(key.PublicJWK())
	if err != nil {
		return err
	}
	if err := q.AddCheckpointKey(ctx, auditdb.AddCheckpointKeyParams{
		KeyID: key.ID(), Algorithm: key.Algorithm(), PublicJwk: jwk,
	}); err != nil {
		return err
	}
	if err := q.RetireOtherCheckpointKeys(ctx, key.ID()); err != nil {
		return err
	}
	return q.ActivateCheckpointKey(ctx, key.ID())
}

// noteSigner signs checkpoints as C2SP signed notes, under the log's origin
// as the key's name.
type noteSigner struct {
	name string
	hash uint32
	key  keys.Ed25519
}

func newNoteSigner(name string, key keys.Ed25519) noteSigner {
	return noteSigner{name: name, hash: noteKeyHash(name, key.PublicKey()), key: key}
}

func (s noteSigner) Name() string { return s.name }

func (s noteSigner) KeyHash() uint32 { return s.hash }

func (s noteSigner) Sign(msg []byte) ([]byte, error) { return s.key.Sign(msg) }

// NoteVerifierKey returns the verifier key of a checkpoint key, as the tools
// of signed notes, such as golang.org/x/mod/sumdb/note, read it:
// name+hash+key.
func NoteVerifierKey(name string, public ed25519.PublicKey) string {
	return fmt.Sprintf("%s+%08x+%s", name, noteKeyHash(name, public),
		base64.StdEncoding.EncodeToString(append([]byte{noteEd25519}, public...)))
}

// noteEd25519 is the algorithm byte of Ed25519 keys in signed notes.
const noteEd25519 = 1

// noteKeyHash is the key hash of C2SP signed notes: the first four bytes of
// the SHA-256 of the key's name, a newline, and the key with its algorithm
// byte.
func noteKeyHash(name string, public ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name + "\n"))
	h.Write([]byte{noteEd25519})
	h.Write(public)
	return binary.BigEndian.Uint32(h.Sum(nil))
}
