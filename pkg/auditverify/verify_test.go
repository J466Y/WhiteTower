package auditverify_test

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

func verify(t *testing.T, m *memLog, keys *auditverify.Keys, chunk int64) *auditverify.Report {
	t.Helper()
	r, err := auditverify.Verify(context.Background(), m, auditverify.Options{Keys: keys, Chunk: chunk})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A log as the core writes it verifies, whatever the size of the chunks it is
// read in, and its tree is the one tlog computes.
func TestAnUntouchedLogVerifies(t *testing.T) {
	s := newSigner(t)
	m := newLog(t, s, 50, 10)
	for _, chunk := range []int64{1, 7, 10, 0} {
		r := verify(t, m, s.keys(t), chunk)
		if !r.OK() || r.Size != 50 || r.Checkpoints != 5 || r.Latest == nil || r.Latest.Size != 50 {
			t.Fatalf("chunk %d: %+v", chunk, r)
		}
		if _, err := auditverify.OpenCheckpoint(r.Latest.Note, s.keys(t)); err != nil {
			t.Fatalf("the latest checkpoint's note: %v", err)
		}
	}
}

// Each way of changing a log is found, at the first leaf it changes. These
// are the unit-level counterparts of the tamper suite of plan P1-02 (ST-06),
// which runs them against the core's database.
func TestEachChangeIsFoundWhereItStarts(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*testing.T, *signer, *memLog)
		kind   auditverify.Kind
		index  int64
		total  int
	}{
		{"an event changed", func(_ *testing.T, _ *signer, m *memLog) {
			m.leaves[23] = memLeaf{hash: m.leaves[23].hash, event: event(99)}
		}, auditverify.EventAltered, 23, 4},
		{"an event deleted", func(_ *testing.T, _ *signer, m *memLog) {
			m.leaves[23] = memLeaf{hash: m.leaves[23].hash}
		}, auditverify.EventMissing, 23, 1},
		{"a leaf deleted", func(_ *testing.T, _ *signer, m *memLog) {
			delete(m.leaves, 23)
		}, auditverify.LeafMissing, 23, 1},
		{"a leaf deleted with its tree hash", func(_ *testing.T, _ *signer, m *memLog) {
			delete(m.leaves, 23)
			delete(m.hashes, tlog.StoredHashIndex(0, 23))
		}, auditverify.LeafMissing, 23, 1},
		{"an event and its leaf replaced", func(_ *testing.T, _ *signer, m *memLog) {
			m.leaves[23] = memLeaf{hash: tlog.RecordHash(event(99)), event: event(99)}
		}, auditverify.TreeAltered, 23, 4},
		{"two leaves swapped", func(_ *testing.T, _ *signer, m *memLog) {
			m.leaves[12], m.leaves[17] = m.leaves[17], m.leaves[12]
		}, auditverify.TreeAltered, 12, 5},
		{"a leaf inserted", func(_ *testing.T, _ *signer, m *memLog) {
			for i := int64(49); i >= 20; i-- {
				m.leaves[i+1] = m.leaves[i]
			}
			m.leaves[20] = memLeaf{hash: tlog.RecordHash(event(99)), event: event(99)}
		}, auditverify.TreeAltered, 20, 4},
		{"a stored tree hash changed", func(_ *testing.T, _ *signer, m *memLog) {
			// The hash of leaves 10 and 11, stored with leaf 11.
			m.hashes[tlog.StoredHashIndex(1, 5)] = tlog.RecordHash(event(99))
		}, auditverify.TreeAltered, 11, 1},
		{"a checkpoint signed with another key", func(t *testing.T, _ *signer, m *memLog) {
			c := &m.checkpoints[2]
			c.note = newSigner(t).sign(t, checkpointText(origin, c.size, c.root))
		}, auditverify.CheckpointInvalid, 30, 1},
		{"a checkpoint of another log", func(t *testing.T, s *signer, m *memLog) {
			c := &m.checkpoints[2]
			c.note = s.sign(t, checkpointText("whitetower.test/other", c.size, c.root))
		}, auditverify.CheckpointInvalid, 30, 1},
		{"a checkpoint's stored root changed", func(_ *testing.T, _ *signer, m *memLog) {
			m.checkpoints[2].root = tlog.RecordHash(event(99))
		}, auditverify.CheckpointAltered, 30, 1},
		{"the latest leaves removed", func(_ *testing.T, _ *signer, m *memLog) {
			for i := int64(45); i < 50; i++ {
				delete(m.leaves, i)
			}
		}, auditverify.CheckpointBeyond, 50, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t)
			m := newLog(t, s, 50, 10)
			tt.change(t, s, m)
			r := verify(t, m, s.keys(t), 7)
			if r.OK() || r.Problems[0].Kind != tt.kind || r.Problems[0].Index != tt.index || r.Total != tt.total {
				t.Fatalf("got %d problems, the first %v; want %d, the first %s at %d", r.Total, r.Problems, tt.total, tt.kind, tt.index)
			}
		})
	}
}

// A log whose tree is rebuilt over a changed event, and whose checkpoints are
// signed again with another key, verifies with that key, and only with it.
func TestARewrittenLogVerifiesOnlyWithItsNewKey(t *testing.T) {
	genuine, forger := newSigner(t), newSigner(t)
	m := newLog(t, genuine, 50, 10)
	events := make([][]byte, 50)
	for i := range int64(50) {
		events[i] = m.leaves[i].event
	}
	events[23] = event(99)
	m.build(t, forger, events, 10)

	if r := verify(t, m, forger.keys(t), 0); !r.OK() {
		t.Fatalf("with the forger's key: %v", r.Problems)
	}
	both, err := auditverify.NewKeys(origin, genuine.public, forger.public, forger.public)
	if err != nil {
		t.Fatal(err)
	}
	if r := verify(t, m, both, 0); !r.OK() {
		t.Fatalf("with both keys, one of them twice: %v", r.Problems)
	}
	r := verify(t, m, genuine.keys(t), 0)
	if r.Total != 5 || r.Problems[0].Kind != auditverify.CheckpointInvalid || r.Checkpoints != 0 {
		t.Fatalf("with the genuine key: %d problems, %v", r.Total, r.Problems)
	}
}

// A report lists at most MaxProblems problems, and counts them all.
func TestReportsAreCapped(t *testing.T) {
	s := newSigner(t)
	m := newLog(t, s, 30, 10)
	for i := range int64(30) {
		m.leaves[i] = memLeaf{hash: m.leaves[i].hash}
	}
	r, err := auditverify.Verify(context.Background(), m, auditverify.Options{Keys: s.keys(t), MaxProblems: 4})
	if err != nil || r.Total != 30 || len(r.Problems) != 4 || r.Problems[3].Index != 3 {
		t.Fatalf("%v: %d problems, listed %v", err, r.Total, r.Problems)
	}
}

// outOfOrder gives its leaves in the wrong order.
type outOfOrder struct{ *memLog }

func (o outOfOrder) Leaves(ctx context.Context, from, to int64, visit func(int64, tlog.Hash, []byte) error) error {
	for i := to - 1; i >= from; i-- {
		if err := visit(i, o.leaves[i].hash, o.leaves[i].event); err != nil {
			return err
		}
	}
	return nil
}

func TestVerifyRefusesWhatItCannotTrust(t *testing.T) {
	s := newSigner(t)
	m := newLog(t, s, 20, 10)
	ctx := context.Background()
	if _, err := auditverify.Verify(ctx, m, auditverify.Options{}); err == nil {
		t.Error("verified without keys")
	}
	if _, err := auditverify.Verify(ctx, m, auditverify.Options{Keys: s.keys(t), Chunk: -1}); err == nil {
		t.Error("verified with a negative chunk")
	}
	if _, err := auditverify.Verify(ctx, outOfOrder{m}, auditverify.Options{Keys: s.keys(t)}); err == nil {
		t.Error("verified leaves given out of order")
	}
	m.err = errors.New("the database is down")
	if _, err := auditverify.Verify(ctx, m, auditverify.Options{Keys: s.keys(t)}); !errors.Is(err, m.err) {
		t.Errorf("a source that fails: %v", err)
	}
}

// prunedLog is a Source that also implements PrunedSource.
type prunedLog struct {
	*memLog
	pruned []auditverify.PrunedRange
}

func (p prunedLog) Pruned(_ context.Context, visit func(from, to int64) error) error {
	for _, r := range p.pruned {
		if err := visit(r.From, r.To); err != nil {
			return err
		}
	}
	return nil
}

// A log with pruned ranges verifies: missing events within pruned ranges do
// not report problems, while missing events outside pruned ranges are still flagged.
func TestPrunedRangesVerifyAndReport(t *testing.T) {
	s := newSigner(t)
	m := newLog(t, s, 50, 10)

	// Prune leaves 10 to 20: keep hash, nil event.
	for i := int64(10); i < 20; i++ {
		m.leaves[i] = memLeaf{hash: m.leaves[i].hash, event: nil}
	}
	plog := prunedLog{
		memLog: m,
		pruned: []auditverify.PrunedRange{{From: 10, To: 20}},
	}

	r := verify(t, plog.memLog, s.keys(t), 7)
	// Without PrunedSource, leaves 10..20 are reported as missing events.
	if r.OK() || r.Total != 10 || r.Problems[0].Kind != auditverify.EventMissing || r.Problems[0].Index != 10 {
		t.Fatalf("without PrunedSource: got %d problems, want 10 starting at 10: %v", r.Total, r.Problems)
	}

	// With PrunedSource, pruned leaves are acknowledged, and the log verifies.
	pr, err := auditverify.Verify(context.Background(), plog, auditverify.Options{Keys: s.keys(t), Chunk: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !pr.OK() {
		t.Fatalf("pruned log did not verify: %v", pr.Problems)
	}
	if pr.PrunedLeaves != 10 {
		t.Errorf("got %d pruned leaves, want 10", pr.PrunedLeaves)
	}
	if len(pr.PrunedRanges) != 1 || pr.PrunedRanges[0] != (auditverify.PrunedRange{From: 10, To: 20}) {
		t.Errorf("got pruned ranges %v, want [{10 20}]", pr.PrunedRanges)
	}

	// An event missing OUTSIDE the pruned range is still detected as a problem.
	m.leaves[35] = memLeaf{hash: m.leaves[35].hash, event: nil}
	pr2, err := auditverify.Verify(context.Background(), plog, auditverify.Options{Keys: s.keys(t), Chunk: 7})
	if err != nil {
		t.Fatal(err)
	}
	if pr2.OK() || pr2.Total != 1 || pr2.Problems[0].Kind != auditverify.EventMissing || pr2.Problems[0].Index != 35 {
		t.Fatalf("got %d problems (%v); want 1 EventMissing at index 35", pr2.Total, pr2.Problems)
	}
}
