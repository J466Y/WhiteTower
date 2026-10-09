package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/keys"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

const origin = "whitetower.test/audit"

var epoch = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) keys.Ed25519 {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewEd25519(private)
}

// lockedBuffer collects the logs that a running sealer writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testSealer is a sealer of a test, with what the test reads from it.
type testSealer struct {
	*Sealer
	writer   *Writer
	registry *prometheus.Registry
	logs     *lockedBuffer
}

func newTestSealer(t *testing.T, pool *db.DB, key keys.Ed25519, clk *clocktest.Fake) *testSealer {
	t.Helper()
	reg := prometheus.NewRegistry()
	logs := &lockedBuffer{}
	w := NewWriter(loadCatalog(t), clk)
	s := NewSealer(SealerOptions{
		DB: pool, Writer: w, Key: key, Origin: origin, Interval: time.Minute, Clock: clk,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), Metrics: metrics.NewAudit(reg),
	})
	return &testSealer{Sealer: s, writer: w, registry: reg, logs: logs}
}

// record records n events of the core, each in a transaction of its own.
func record(t *testing.T, pool *db.DB, w *Writer, n int) {
	t.Helper()
	for range n {
		agent, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		err = pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
			return w.Record(ctx, tx, Event{Type: "whitetower.agent.created.v1", Subject: agent.String(), Data: map[string]any{
				"slug": "invoice-triage", "kind": "in_house", "risk_tier": "high",
				"use_case_id": "0192f1c2-7a3b-7c4d-8e5f-000000000010", "primary_owner": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
				"actor": map[string]any{"type": "human", "id": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"}, "state_version": 1,
			}})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// verifyTree recomputes the tree from the events' canonical bytes, in the
// order of the leaves, and checks what the database holds against it: no gap
// or duplicate among the leaves, each leaf the hash of its event, and every
// tree hash as tlog computes it. It returns the tree's size and root.
func verifyTree(t *testing.T, superuser *pgx.Conn) (int64, tlog.Hash) {
	t.Helper()
	ctx := context.Background()
	rows, err := superuser.Query(ctx, `SELECT l.leaf_index, l.leaf_hash, e.canonical
		FROM whitetower.audit_leaves l JOIN whitetower.audit_events e ON e.id = l.audit_id ORDER BY l.leaf_index`)
	if err != nil {
		t.Fatal(err)
	}
	var memory []tlog.Hash
	read := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			out[i] = memory[idx]
		}
		return out, nil
	})
	var n int64
	for rows.Next() {
		var index int64
		var leaf, canonical []byte
		if err := rows.Scan(&index, &leaf, &canonical); err != nil {
			t.Fatal(err)
		}
		if index != n {
			t.Fatalf("leaf %d where leaf %d belongs: a gap or a duplicate", index, n)
		}
		want := tlog.RecordHash(canonical)
		if !bytes.Equal(leaf, want[:]) {
			t.Fatalf("leaf %d is not the hash of its event", n)
		}
		stored, err := tlog.StoredHashesForRecordHash(n, want, read)
		if err != nil {
			t.Fatal(err)
		}
		memory = append(memory, stored...)
		n++
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	hashes, err := superuser.Query(ctx, "SELECT hash_index, hash FROM whitetower.audit_tree_hashes ORDER BY hash_index")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for ; hashes.Next(); count++ {
		var index int64
		var h []byte
		if err := hashes.Scan(&index, &h); err != nil {
			t.Fatal(err)
		}
		if index != int64(count) || index >= int64(len(memory)) || !bytes.Equal(h, memory[index][:]) {
			t.Fatalf("tree hash %d is not the one tlog computes", index)
		}
	}
	if count != len(memory) {
		t.Fatalf("%d tree hashes stored, %d computed", count, len(memory))
	}
	if n == 0 {
		return 0, tlog.Hash{}
	}
	root, err := tlog.TreeHash(n, read)
	if err != nil {
		t.Fatal(err)
	}
	return n, root
}

func count(t *testing.T, superuser *pgx.Conn, table string) int {
	t.Helper()
	var n int
	if err := superuser.QueryRow(context.Background(), "SELECT count(*) FROM whitetower."+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTheSealerSealsEveryEvent(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	s := newTestSealer(t, pool, newKey(t), clocktest.New(epoch))
	record(t, pool, s.writer, 7)

	if err := s.round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if size, _ := verifyTree(t, superuser); size != 7 {
		t.Fatalf("%d leaves, want 7", size)
	}
	// The checkpoint over the 7 events waits for the next round, which seals
	// its event and signs no other checkpoint: only that event is new.
	if count(t, superuser, "audit_checkpoints") != 1 || count(t, superuser, "audit_unsealed") != 1 {
		t.Fatal("the first round signs a checkpoint, whose event waits in the queue")
	}
	if err := s.round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if size, _ := verifyTree(t, superuser); size != 8 || count(t, superuser, "audit_checkpoints") != 1 ||
		count(t, superuser, "audit_unsealed") != 0 {
		t.Fatalf("after the second round: %d leaves, %d checkpoints", size, count(t, superuser, "audit_checkpoints"))
	}
	for name, want := range map[string]float64{"whitetower_audit_tree_size": 8, "whitetower_audit_sealed_total": 8} {
		if got := gather(t, s.registry, name); got != want {
			t.Errorf("%s %v, want %v", name, got, want)
		}
	}
	if n := testutil.CollectAndCount(s.registry, "whitetower_audit_sealing_delay_seconds"); n != 1 {
		t.Errorf("sealing delay: %d series", n)
	}
}

// gather returns the value of a metric without labels.
func gather(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name && len(f.GetMetric()) == 1 {
			m := f.GetMetric()[0]
			return m.GetGauge().GetValue() + m.GetCounter().GetValue()
		}
	}
	return -1
}

// The criterion of plan P1-02, step 3: a batch that fails in its middle, as
// a crash would leave it, leaves a consistent tree, and the next round goes
// on from it.
func TestAFailedBatchLeavesTheTreeConsistent(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	ctx := context.Background()
	s := newTestSealer(t, pool, newKey(t), clocktest.New(epoch))
	record(t, pool, s.writer, 3)
	if err := s.round(ctx); err != nil {
		t.Fatal(err)
	}

	for _, stmt := range []string{
		`CREATE FUNCTION whitetower.crash() RETURNS trigger LANGUAGE plpgsql AS $$
		 BEGIN RAISE EXCEPTION 'the sealer crashed'; END $$`,
		`CREATE TRIGGER crash BEFORE INSERT ON whitetower.audit_tree_hashes FOR EACH ROW EXECUTE FUNCTION whitetower.crash()`,
	} {
		if _, err := superuser.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	record(t, pool, s.writer, 2)
	if err := s.round(ctx); err == nil || !strings.Contains(err.Error(), "the sealer crashed") {
		t.Fatalf("round: %v", err)
	}
	if size, _ := verifyTree(t, superuser); size != 3 || count(t, superuser, "audit_unsealed") != 3 {
		t.Fatalf("after the crash: %d leaves, %d queued", size, count(t, superuser, "audit_unsealed"))
	}

	if _, err := superuser.Exec(ctx, "DROP TRIGGER crash ON whitetower.audit_tree_hashes"); err != nil {
		t.Fatal(err)
	}
	s.loaded = false // as Run does after a failed round
	if err := s.round(ctx); err != nil {
		t.Fatal(err)
	}
	if size, _ := verifyTree(t, superuser); size != 6 || count(t, superuser, "audit_unsealed") != 1 {
		t.Fatalf("after the restart: %d leaves, %d queued", size, count(t, superuser, "audit_unsealed"))
	}
}

// Should two sealers ever run at once, the tree does not fork: the one that
// is behind fails its batch, loads the tree and goes on from it.
func TestTwoSealersNeverForkTheTree(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	ctx := context.Background()
	key := newKey(t)
	a, b := newTestSealer(t, pool, key, clocktest.New(epoch)), newTestSealer(t, pool, key, clocktest.New(epoch))
	if err := b.round(ctx); err != nil { // b loads an empty tree
		t.Fatal(err)
	}
	record(t, pool, a.writer, 2)
	if err := a.round(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.round(ctx); err == nil {
		t.Fatal("a sealer that is behind sealed over the leaves of another")
	}
	b.loaded = false
	if err := b.round(ctx); err != nil {
		t.Fatal(err)
	}
	if size, _ := verifyTree(t, superuser); size != 3 {
		t.Fatalf("%d leaves, want the 2 events and the checkpoint's", size)
	}
}

// openCheckpoint opens a stored checkpoint with the verifier key of the key
// that signed it, as signed-note tools do, and returns its body.
func openCheckpoint(t *testing.T, signed string, key ed25519.PublicKey) string {
	t.Helper()
	verifier, err := note.NewVerifier(NoteVerifierKey(origin, key))
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open([]byte(signed), note.VerifierList(verifier))
	if err != nil {
		t.Fatalf("the checkpoint does not verify: %v\n%s", err, signed)
	}
	return n.Text
}

// The criterion of plan P1-02, step 4, first half: checkpoints verify with
// standard signed-note tools, and say what the tree is.
func TestCheckpointsVerifyAsSignedNotes(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	ctx := context.Background()
	key := newKey(t)
	s := newTestSealer(t, pool, key, clocktest.New(epoch))
	record(t, pool, s.writer, 3)
	if err := s.round(ctx); err != nil {
		t.Fatal(err)
	}
	size, root := verifyTree(t, superuser)

	var signed, keyID string
	var treeSize int64
	if err := superuser.QueryRow(ctx, "SELECT tree_size, signed_note, key_id FROM whitetower.audit_checkpoints").
		Scan(&treeSize, &signed, &keyID); err != nil {
		t.Fatal(err)
	}
	if text := openCheckpoint(t, signed, key.PublicKey()); text != CheckpointText(origin, size, root) || treeSize != size || keyID != key.ID() {
		t.Fatalf("checkpoint %q over %d leaves, by %s; the tree has %d leaves, root %x", text, treeSize, keyID, size, root)
	}
	if lines := strings.Split(signed, "\n"); lines[0] != origin || lines[1] != strconv.FormatInt(size, 10) ||
		lines[2] != base64.StdEncoding.EncodeToString(root[:]) || !strings.HasPrefix(lines[4], "\u2014 "+origin+" ") {
		t.Fatalf("not a C2SP tlog-checkpoint:\n%s", signed)
	}

	var status string
	var jwk []byte
	if err := superuser.QueryRow(ctx, "SELECT status, public_jwk FROM whitetower.signing_keys WHERE key_id = $1", key.ID()).
		Scan(&status, &jwk); err != nil {
		t.Fatal(err)
	}
	var public map[string]string
	if err := json.Unmarshal(jwk, &public); err != nil || status != "active" || public["x"] != key.PublicJWK()["x"] || public["d"] != "" {
		t.Fatalf("signing key: %s %s %v", status, jwk, err)
	}

	// The checkpoint is evidence too, and its event says what it says.
	var data []byte
	if err := superuser.QueryRow(ctx, `SELECT canonical FROM whitetower.audit_events WHERE type = 'whitetower.audit.checkpoint.v1'`).
		Scan(&data); err != nil {
		t.Fatal(err)
	}
	var event struct{ Data checkpointData }
	if err := json.Unmarshal(data, &event); err != nil || event.Data.Note != signed || event.Data.TreeSize != size ||
		event.Data.KeyID != key.ID() || event.Data.RootHash != base64.StdEncoding.EncodeToString(root[:]) {
		t.Fatalf("checkpoint event %s: %v", data, err)
	}
}

func TestCheckpointsComeAtTheirInterval(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	ctx := context.Background()
	clk := clocktest.New(epoch)
	s := newTestSealer(t, pool, newKey(t), clk)
	round := func() {
		t.Helper()
		if err := s.round(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record(t, pool, s.writer, 2)
	round()
	record(t, pool, s.writer, 2)
	round()
	if n := count(t, superuser, "audit_checkpoints"); n != 1 {
		t.Fatalf("%d checkpoints before the interval passed, want 1", n)
	}
	clk.Advance(time.Minute)
	round()
	if n := count(t, superuser, "audit_checkpoints"); n != 2 {
		t.Fatalf("%d checkpoints once the interval passed, want 2", n)
	}
	// An idle log signs no more, though each checkpoint adds its event.
	round()
	clk.Advance(time.Hour)
	round()
	if n := count(t, superuser, "audit_checkpoints"); n != 2 {
		t.Fatalf("%d checkpoints on an idle log, want 2", n)
	}
	if got := gather(t, s.registry, "whitetower_audit_last_checkpoint_timestamp_seconds"); got != float64(epoch.Add(time.Minute).Unix()) {
		t.Errorf("last checkpoint %v", got)
	}
}

// The criterion of plan P1-02, step 4, second half: after a rotation, the
// checkpoints of the old key still verify, with its public half, which the
// database keeps.
func TestRotationKeepsOldCheckpointsVerifiable(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	ctx := context.Background()
	oldKey, newKey := newKey(t), newKey(t)
	before := newTestSealer(t, pool, oldKey, clocktest.New(epoch))
	record(t, pool, before.writer, 2)
	if err := before.round(ctx); err != nil {
		t.Fatal(err)
	}
	after := newTestSealer(t, pool, newKey, clocktest.New(epoch.Add(time.Hour)))
	record(t, pool, after.writer, 2)
	if err := after.round(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := superuser.Query(ctx, `SELECT c.signed_note, k.public_jwk, k.status
		FROM whitetower.audit_checkpoints c JOIN whitetower.signing_keys k USING (key_id) ORDER BY c.tree_size`)
	if err != nil {
		t.Fatal(err)
	}
	var statuses []string
	for rows.Next() {
		var signed, status string
		var jwk []byte
		if err := rows.Scan(&signed, &jwk, &status); err != nil {
			t.Fatal(err)
		}
		var public map[string]string
		if err := json.Unmarshal(jwk, &public); err != nil {
			t.Fatal(err)
		}
		x, err := base64.RawURLEncoding.DecodeString(public["x"])
		if err != nil {
			t.Fatal(err)
		}
		openCheckpoint(t, signed, x)
		statuses = append(statuses, status)
	}
	if strings.Join(statuses, " ") != "retired active" {
		t.Fatalf("keys of the checkpoints: %v, want the old retired and the new active", statuses)
	}
}

// Run seals round after round; a failed round is logged once, and the
// rounds after it load the tree again.
func TestRunRecoversFromFailedRounds(t *testing.T) {
	d := dbtest.New(t)
	pool, superuser := d.Open(t), d.Superuser(t)
	ctx, cancel := context.WithCancel(context.Background())
	clk := clocktest.New(epoch)
	s := newTestSealer(t, pool, newKey(t), clk)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	until := func(cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !cond(); {
			if time.Now().After(deadline) {
				t.Fatal("timed out")
			}
			clk.WaitTimers(t, 1)
			clk.Advance(maxRetry)
		}
	}

	record(t, pool, s.writer, 1)
	until(func() bool { return count(t, superuser, "audit_leaves") == 1 })
	if _, err := superuser.Exec(ctx, "REVOKE INSERT ON whitetower.audit_leaves FROM whitetower_runtime"); err != nil {
		t.Fatal(err)
	}
	record(t, pool, s.writer, 1)
	until(func() bool { return gather(t, s.registry, "whitetower_audit_sealing_failures_total") >= 2 })
	if _, err := superuser.Exec(ctx, "GRANT INSERT ON whitetower.audit_leaves TO whitetower_runtime"); err != nil {
		t.Fatal(err)
	}
	until(func() bool { return count(t, superuser, "audit_unsealed") == 0 })
	if size, _ := verifyTree(t, superuser); size < 3 {
		t.Fatalf("%d leaves after recovering", size)
	}
	logs := s.logs.String()
	if strings.Count(logs, "a round failed") != 1 || !strings.Contains(logs, "sealing again") {
		t.Fatalf("logs:\n%s", logs)
	}
}
