package auditverify_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

const origin = "whitetower.test/audit"

// signer signs checkpoints with an Ed25519 key, as the core does.
type signer struct {
	name   string
	hash   uint32
	key    ed25519.PrivateKey
	public ed25519.PublicKey
}

func newSigner(t testing.TB) *signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vkey, err := auditverify.VerifierKey(origin, public)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{name: origin, hash: v.KeyHash(), key: private, public: public}
}

func (s *signer) Name() string                    { return s.name }
func (s *signer) KeyHash() uint32                 { return s.hash }
func (s *signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.key, msg), nil }

// keys returns the keys that verify the signer's checkpoints.
func (s *signer) keys(t testing.TB) *auditverify.Keys {
	t.Helper()
	k, err := auditverify.NewKeys(origin, s.public)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sign signs a checkpoint text.
func (s *signer) sign(t testing.TB, text string) []byte {
	t.Helper()
	signed, err := note.Sign(&note.Note{Text: text}, s)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func checkpointText(o string, size int64, root tlog.Hash) string {
	return fmt.Sprintf("%s\n%d\n%s\n", o, size, base64.StdEncoding.EncodeToString(root[:]))
}

// memLog is a log in memory, laid out as the core stores it, and built with
// tlog's own functions, so that Verify's tree is checked against them.
type memLog struct {
	leaves      map[int64]memLeaf
	hashes      map[int64]tlog.Hash
	checkpoints []memCheckpoint
	err         error
}

type memLeaf struct {
	hash  tlog.Hash
	event []byte
}

type memCheckpoint struct {
	size int64
	root tlog.Hash
	note []byte
}

func event(i int64) []byte {
	return fmt.Appendf(nil, `{"id":"%d","source":"/core","type":"whitetower.test.v1"}`, i)
}

// newLog returns a log of n events, with a checkpoint every so many leaves,
// signed by s.
func newLog(t *testing.T, s *signer, n, every int64) *memLog {
	t.Helper()
	m := &memLog{leaves: map[int64]memLeaf{}, hashes: map[int64]tlog.Hash{}}
	events := make([][]byte, n)
	for i := range n {
		events[i] = event(i)
	}
	m.build(t, s, events, every)
	return m
}

// build stores events as the leaves of a new tree, with its hashes and
// checkpoints.
func (m *memLog) build(t *testing.T, s *signer, events [][]byte, every int64) {
	t.Helper()
	m.leaves, m.hashes, m.checkpoints = map[int64]memLeaf{}, map[int64]tlog.Hash{}, nil
	for i, e := range events {
		n := int64(i)
		hashes, err := tlog.StoredHashes(n, e, m.reader())
		if err != nil {
			t.Fatal(err)
		}
		for j, h := range hashes {
			m.hashes[tlog.StoredHashIndex(0, n)+int64(j)] = h
		}
		m.leaves[n] = memLeaf{hash: tlog.RecordHash(e), event: e}
		if (n+1)%every == 0 {
			m.checkpoint(t, s, n+1)
		}
	}
}

// checkpoint stores a checkpoint over the first size leaves, signed by s.
func (m *memLog) checkpoint(t *testing.T, s *signer, size int64) {
	t.Helper()
	root := m.root(t, size)
	m.checkpoints = append(m.checkpoints, memCheckpoint{size: size, root: root, note: s.sign(t, checkpointText(origin, size, root))})
}

func (m *memLog) root(t *testing.T, size int64) tlog.Hash {
	t.Helper()
	root, err := tlog.TreeHash(size, m.reader())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func (m *memLog) reader() tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, index := range indexes {
			h, ok := m.hashes[index]
			if !ok {
				return nil, fmt.Errorf("hash %d missing", index)
			}
			out[i] = h
		}
		return out, nil
	})
}

// opened returns the checkpoint of the given size, verified.
func (m *memLog) opened(t *testing.T, keys *auditverify.Keys, size int64) auditverify.Checkpoint {
	t.Helper()
	for _, c := range m.checkpoints {
		if c.size == size {
			cp, err := auditverify.OpenCheckpoint(c.note, keys)
			if err != nil {
				t.Fatal(err)
			}
			return cp
		}
	}
	t.Fatalf("no checkpoint of %d leaves", size)
	return auditverify.Checkpoint{}
}

func (m *memLog) Size(context.Context) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	size := int64(0)
	for i := range m.leaves {
		size = max(size, i+1)
	}
	return size, nil
}

func (m *memLog) Leaves(_ context.Context, from, to int64, visit func(int64, tlog.Hash, []byte) error) error {
	for _, i := range slices.Sorted(maps.Keys(m.leaves)) {
		if i >= from && i < to {
			if err := visit(i, m.leaves[i].hash, m.leaves[i].event); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *memLog) TreeHashes(_ context.Context, indexes []int64) (map[int64]tlog.Hash, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := map[int64]tlog.Hash{}
	for _, i := range indexes {
		if h, ok := m.hashes[i]; ok {
			out[i] = h
		}
	}
	return out, nil
}

func (m *memLog) Checkpoints(_ context.Context, visit func(int64, tlog.Hash, []byte) error) error {
	for _, c := range m.checkpoints {
		if err := visit(c.size, c.root, c.note); err != nil {
			return err
		}
	}
	return nil
}

var _ auditverify.Source = (*memLog)(nil)
