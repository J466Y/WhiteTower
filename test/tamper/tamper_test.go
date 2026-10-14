// Package tamper is the tamper suite of the audit log (plan P1-02, step 10):
// a database administrator changes the sealed log behind the core's back, and
// the verification library, pkg/auditverify, finds every change. It lives
// apart from both, because a domain package does not import pkg/.
package tamper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/audit"
	"github.com/J466Y/WhiteTower/internal/platform/clock/clocktest"
	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/keys"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

const origin = "whitetower.test/audit"

// The core's audit log is a source for the verification library.
var (
	_ auditverify.Source       = (*audit.Log)(nil)
	_ auditverify.PrunedSource = (*audit.Log)(nil)
)

// fixture is a database whose audit log the core writes and seals, with the
// key that signs its checkpoints.
type fixture struct {
	pool      *db.DB
	superuser *pgx.Conn
	writer    *audit.Writer
	key       keys.Ed25519
	clk       *clocktest.Fake
	log       *audit.Log
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	catalog, err := audit.LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	clk := clocktest.New(time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC))
	pool := d.Open(t)
	return &fixture{
		pool: pool, superuser: d.Superuser(t), writer: audit.NewWriter(catalog, clk),
		key: newKey(t), clk: clk, log: audit.NewLog(pool),
	}
}

func newKey(t *testing.T) keys.Ed25519 {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewEd25519(private)
}

// record records an event of the core, and returns its audit ID.
func (f *fixture) record(t *testing.T) uuid.UUID {
	t.Helper()
	agent, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = f.pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return f.writer.Record(ctx, tx, audit.Event{Type: "whitetower.agent.created.v1", Subject: agent.String(), Data: map[string]any{
			"slug": "invoice-triage", "kind": "in_house", "risk_tier": "high",
			"use_case_id": "0192f1c2-7a3b-7c4d-8e5f-000000000010", "primary_owner": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
			"actor": map[string]any{"type": "human", "id": "0192f1c2-7a3b-7c4d-8e5f-0000000000a1"}, "state_version": 1,
		}})
	})
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := f.superuser.QueryRow(ctx, "SELECT audit_id FROM whitetower.audit_unsealed ORDER BY ingested_at DESC, audit_id DESC LIMIT 1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// grow records n events of the core and seals them as the server does: the
// latest checkpoint then signs every leaf but the one of its own event.
func (f *fixture) grow(t *testing.T, n int) {
	t.Helper()
	for range n {
		f.record(t)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := audit.NewSealer(audit.SealerOptions{
		DB: f.pool, Writer: f.writer, Key: f.key, Origin: origin, Interval: time.Minute, Clock: f.clk,
		Logger: slog.New(slog.DiscardHandler), Metrics: metrics.NewAudit(prometheus.NewRegistry()),
	})
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	for deadline := time.Now().Add(10 * time.Second); !f.settled(t); {
		if time.Now().After(deadline) {
			t.Fatal("the sealer did not settle")
		}
		f.clk.WaitTimers(t, 1)
		f.clk.Advance(time.Minute)
	}
}

// settled reports whether every event is sealed, and the latest checkpoint
// signs every leaf but the one of its own event.
func (f *fixture) settled(t *testing.T) bool {
	t.Helper()
	var queued, size, signed int64
	err := f.superuser.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM whitetower.audit_unsealed),
		(SELECT coalesce(max(leaf_index) + 1, 0) FROM whitetower.audit_leaves),
		(SELECT coalesce(max(tree_size), 0) FROM whitetower.audit_checkpoints)`).Scan(&queued, &size, &signed)
	if err != nil {
		t.Fatal(err)
	}
	return queued == 0 && size > 0 && signed == size-1
}

// tamper changes the database as its administrator can: as a superuser, with
// the append-only triggers off.
func (f *fixture) tamper(t *testing.T, change func(ctx context.Context, tx pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, f.superuser, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
			return err
		}
		return change(ctx, tx)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// exec runs a statement with tamper.
func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	f.tamper(t, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return fmt.Errorf("%s: %w", sql, err)
		}
		return nil
	})
}

// leafEvent returns the audit ID and the canonical bytes of the event of a
// leaf.
func (f *fixture) leafEvent(t *testing.T, index int64) (uuid.UUID, []byte) {
	t.Helper()
	var id uuid.UUID
	var event []byte
	err := f.superuser.QueryRow(context.Background(), `SELECT e.id, e.canonical FROM whitetower.audit_leaves l
		JOIN whitetower.audit_events e ON e.ingested_at = l.ingested_at AND e.id = l.audit_id WHERE l.leaf_index = $1`, index).Scan(&id, &event)
	if err != nil {
		t.Fatal(err)
	}
	return id, event
}

// altered returns an event with one byte of its data changed: still valid
// JSON, as an administrator would leave it.
func altered(t *testing.T, event []byte) []byte {
	t.Helper()
	out := bytes.Replace(event, []byte(`"invoice-triage"`), []byte(`"invoice-triagx"`), 1)
	if bytes.Equal(out, event) {
		t.Fatalf("no slug to change in %s", event)
	}
	return out
}

// rebuild alters the event of leaf k, then stores its leaf and every hash of
// the tree again from the events, as an administrator covering their tracks
// does. It returns the roots of the rebuilt tree, by size.
func (f *fixture) rebuild(t *testing.T, k int64) func(size int64) tlog.Hash {
	t.Helper()
	ctx := context.Background()
	rows, err := f.superuser.Query(ctx, `SELECT e.canonical FROM whitetower.audit_leaves l
		JOIN whitetower.audit_events e ON e.ingested_at = l.ingested_at AND e.id = l.audit_id ORDER BY l.leaf_index`)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	if err != nil {
		t.Fatal(err)
	}
	id, _ := f.leafEvent(t, k)
	evs[k] = altered(t, evs[k])
	hashes := map[int64]tlog.Hash{}
	read := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, index := range indexes {
			out[i] = hashes[index]
		}
		return out, nil
	})
	for i, e := range evs {
		stored, err := tlog.StoredHashes(int64(i), e, read)
		if err != nil {
			t.Fatal(err)
		}
		for j, h := range stored {
			hashes[tlog.StoredHashIndex(0, int64(i))+int64(j)] = h
		}
	}
	leaf := tlog.RecordHash(evs[k])
	f.tamper(t, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE whitetower.audit_events SET canonical = $1 WHERE id = $2", evs[k], id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE whitetower.audit_leaves SET leaf_hash = $1 WHERE leaf_index = $2", leaf[:], k); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM whitetower.audit_tree_hashes"); err != nil {
			return err
		}
		copied := make([][]any, 0, len(hashes))
		for index, h := range hashes {
			copied = append(copied, []any{index, h[:]})
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"whitetower", "audit_tree_hashes"}, []string{"hash_index", "hash"}, pgx.CopyFromRows(copied))
		return err
	})
	return func(size int64) tlog.Hash {
		root, err := tlog.TreeHash(size, read)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
}

// trusted returns the genuine checkpoint key, as kept outside the database.
func (f *fixture) trusted(t *testing.T) *auditverify.Keys {
	t.Helper()
	k, err := auditverify.NewKeys(origin, f.key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// stored returns the checkpoint keys that the database holds.
func (f *fixture) stored(t *testing.T) *auditverify.Keys {
	t.Helper()
	jwks, err := f.log.CheckpointKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var public []ed25519.PublicKey
	for _, jwk := range jwks {
		key, err := auditverify.ParseJWK(jwk)
		if err != nil {
			t.Fatal(err)
		}
		public = append(public, key)
	}
	k, err := auditverify.NewKeys(origin, public...)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// latest returns the latest checkpoint, verified as the SIEM that receives it
// verifies it.
func (f *fixture) latest(t *testing.T) auditverify.Checkpoint {
	t.Helper()
	var signed []byte
	if err := f.superuser.QueryRow(context.Background(),
		"SELECT signed_note FROM whitetower.audit_checkpoints ORDER BY tree_size DESC LIMIT 1").Scan(&signed); err != nil {
		t.Fatal(err)
	}
	cp, err := auditverify.OpenCheckpoint(signed, f.trusted(t))
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func (f *fixture) verify(t *testing.T, keys *auditverify.Keys) *auditverify.Report {
	t.Helper()
	r, err := auditverify.Verify(context.Background(), f.log, auditverify.Options{Keys: keys, Chunk: 16})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// newLog returns a fixture whose log has 42 leaves: 20 events, the first
// checkpoint's event, 20 more events and the second checkpoint's event. The
// checkpoints sign the trees of 20 and 41 leaves.
func newLog(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.grow(t, 20)
	f.grow(t, 20)
	if r := f.verify(t, f.trusted(t)); !r.OK() || r.Size != 42 || r.Checkpoints != 2 || r.Latest.Size != 41 {
		t.Fatalf("before any change: %+v", r)
	}
	return f
}

// Security test ST-06: as a superuser, modify, delete, insert and reorder
// sealed events: verification reports each case, where it starts.
func TestEveryChangeToSealedEventsIsFound(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*testing.T, *fixture)
		kind   auditverify.Kind
		index  int64
	}{
		{"an event modified", func(t *testing.T, f *fixture) {
			id, event := f.leafEvent(t, 5)
			f.exec(t, "UPDATE whitetower.audit_events SET canonical = $1 WHERE id = $2", altered(t, event), id)
		}, auditverify.EventAltered, 5},
		{"an event deleted", func(t *testing.T, f *fixture) {
			id, _ := f.leafEvent(t, 5)
			f.exec(t, "DELETE FROM whitetower.audit_events WHERE id = $1", id)
		}, auditverify.EventMissing, 5},
		{"a leaf deleted", func(t *testing.T, f *fixture) {
			f.exec(t, "DELETE FROM whitetower.audit_leaves WHERE leaf_index = 5")
		}, auditverify.LeafMissing, 5},
		{"an event inserted", func(t *testing.T, f *fixture) {
			id := f.record(t)
			var ingested time.Time
			var event []byte
			if err := f.superuser.QueryRow(context.Background(),
				"SELECT ingested_at, canonical FROM whitetower.audit_events WHERE id = $1", id).Scan(&ingested, &event); err != nil {
				t.Fatal(err)
			}
			leaf := auditverify.LeafHash(event)
			// Leaves 5 and after move up one, through indexes out of the way:
			// the primary key refuses a duplicate in the middle of a statement.
			f.exec(t, "UPDATE whitetower.audit_leaves SET leaf_index = leaf_index + 1000000 WHERE leaf_index >= 5")
			f.exec(t, "UPDATE whitetower.audit_leaves SET leaf_index = leaf_index - 999999 WHERE leaf_index >= 1000000")
			f.exec(t, "DELETE FROM whitetower.audit_unsealed WHERE audit_id = $1", id)
			f.exec(t, "INSERT INTO whitetower.audit_leaves (leaf_index, audit_id, ingested_at, leaf_hash) VALUES (5, $1, $2, $3)",
				id, ingested, leaf[:])
		}, auditverify.TreeAltered, 5},
		{"events reordered", func(t *testing.T, f *fixture) {
			f.exec(t, "UPDATE whitetower.audit_leaves SET leaf_index = 1000005 WHERE leaf_index = 5")
			f.exec(t, "UPDATE whitetower.audit_leaves SET leaf_index = 5 WHERE leaf_index = 6")
			f.exec(t, "UPDATE whitetower.audit_leaves SET leaf_index = 6 WHERE leaf_index = 1000005")
		}, auditverify.TreeAltered, 5},
		{"an event modified, with its leaf and the whole tree", func(t *testing.T, f *fixture) {
			f.rebuild(t, 5)
		}, auditverify.CheckpointMismatch, 20},
		{"a checkpoint's stored root modified", func(t *testing.T, f *fixture) {
			f.exec(t, "UPDATE whitetower.audit_checkpoints SET root_hash = sha256('forged'::bytea) WHERE tree_size = 20")
		}, auditverify.CheckpointAltered, 20},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newLog(t)
			tt.change(t, f)
			r := f.verify(t, f.trusted(t))
			if r.OK() || r.Problems[0].Kind != tt.kind || r.Problems[0].Index != tt.index {
				t.Fatalf("%d problems, the first of %v; want the first %s at %d", r.Total, r.Problems, tt.kind, tt.index)
			}
		})
	}
}

// Security test ST-07: remove the latest events and checkpoints. The log still
// verifies on its own, and the consistency check against a checkpoint
// exported earlier fails, also once the log has grown back past it.
func TestARollbackFailsTheConsistencyCheck(t *testing.T) {
	f := newLog(t)
	ctx := context.Background()
	first := f.grownTo(t, 20)
	second := f.latest(t)
	// Back to the tree of the first checkpoint, with its own event.
	f.exec(t, `DELETE FROM whitetower.audit_events e USING whitetower.audit_leaves l
		WHERE l.leaf_index >= 21 AND e.ingested_at = l.ingested_at AND e.id = l.audit_id`)
	f.exec(t, "DELETE FROM whitetower.audit_leaves WHERE leaf_index >= 21")
	f.exec(t, "DELETE FROM whitetower.audit_tree_hashes WHERE hash_index >= $1", tlog.StoredHashIndex(0, 21))
	f.exec(t, "DELETE FROM whitetower.audit_checkpoints WHERE tree_size > 21")
	if r := f.verify(t, f.trusted(t)); !r.OK() || r.Size != 21 {
		t.Fatalf("the rolled-back log does not verify on its own: %+v", r)
	}
	if err := auditverify.Extends(ctx, f.log, first); err != nil {
		t.Fatalf("against the first checkpoint: %v", err)
	}
	if err := auditverify.Extends(ctx, f.log, second); !errors.Is(err, auditverify.ErrShorter) {
		t.Fatalf("against the second checkpoint: %v", err)
	}
	f.grow(t, 25)
	if err := auditverify.Extends(ctx, f.log, second); !errors.Is(err, auditverify.ErrForked) {
		t.Fatalf("against the second checkpoint, once the log has grown back past it: %v", err)
	}
}

// grownTo returns the checkpoint of a tree of size leaves, verified with the
// genuine key.
func (f *fixture) grownTo(t *testing.T, size int64) auditverify.Checkpoint {
	t.Helper()
	var signed []byte
	if err := f.superuser.QueryRow(context.Background(),
		"SELECT signed_note FROM whitetower.audit_checkpoints WHERE tree_size = $1", size).Scan(&signed); err != nil {
		t.Fatal(err)
	}
	cp, err := auditverify.OpenCheckpoint(signed, f.trusted(t))
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// Security test ST-08: rebuild the tree over an altered event and sign its
// checkpoints with another key. The log verifies with the key the database now
// holds, not with the genuine one, and the consistency check against an
// exported checkpoint fails.
func TestARewriteFailsTheConsistencyCheck(t *testing.T) {
	f := newLog(t)
	kept := f.latest(t)
	root := f.rebuild(t, 5)
	forger := newKey(t)
	jwk, err := json.Marshal(forger.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	f.tamper(t, func(ctx context.Context, tx pgx.Tx) error {
		for _, s := range []string{
			"DELETE FROM whitetower.audit_checkpoints",
			"DELETE FROM whitetower.signing_keys WHERE purpose = 'checkpoint'",
		} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO whitetower.signing_keys (key_id, purpose, algorithm, public_jwk, status, activated_at)
			VALUES ($1, 'checkpoint', $2, $3, 'active', now())`, forger.ID(), forger.Algorithm(), jwk); err != nil {
			return err
		}
		for _, size := range []int64{20, 41} {
			signed, err := audit.SignCheckpoint(origin, size, root(size), forger)
			if err != nil {
				return err
			}
			r := root(size)
			if _, err := tx.Exec(ctx, "INSERT INTO whitetower.audit_checkpoints (tree_size, root_hash, signed_note, key_id) VALUES ($1, $2, $3, $4)",
				size, r[:], signed, forger.ID()); err != nil {
				return err
			}
		}
		return nil
	})

	if r := f.verify(t, f.stored(t)); !r.OK() || r.Checkpoints != 2 {
		t.Fatalf("with the key the database holds: %+v", r)
	}
	if r := f.verify(t, f.trusted(t)); r.OK() || r.Checkpoints != 0 || r.Problems[0].Kind != auditverify.CheckpointInvalid {
		t.Fatalf("with the genuine key: %d problems, %v", r.Total, r.Problems)
	}
	if err := auditverify.Extends(context.Background(), f.log, kept); !errors.Is(err, auditverify.ErrForked) {
		t.Fatalf("against the exported checkpoint: %v", err)
	}
}

// Lawful retention drop versus unlawful deletion (plan P1-02, step 9):
// Dropping a partition lawfully (recorded in audit_pruned_ranges) passes
// verification: auditverify acknowledges missing events in pruned ranges,
// confirms the root against checkpoints, and reports the pruned range.
// Any deletion outside the pruned range is detected and fails verification.
func TestRetentionDroppedPartitionPassesVerificationWhileUnlawfulDeletionFails(t *testing.T) {
	f := newLog(t)

	// Lawfully drop the first 20 leaves by recording the pruned range and deleting
	// the corresponding events (as DropExpiredPartitions does).
	f.tamper(t, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO whitetower.audit_pruned_ranges (from_leaf_index, to_leaf_index, partition_name)
			VALUES (0, 20, 'audit_events_2025_01')`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM whitetower.audit_events
			WHERE id IN (SELECT audit_id FROM whitetower.audit_leaves WHERE leaf_index < 20)`)
		return err
	})

	r := f.verify(t, f.trusted(t))
	if !r.OK() {
		t.Fatalf("lawfully pruned log failed verification: %+v", r)
	}
	if r.PrunedLeaves != 20 {
		t.Fatalf("expected 20 pruned leaves, got %d", r.PrunedLeaves)
	}
	if len(r.PrunedRanges) != 1 || r.PrunedRanges[0].From != 0 || r.PrunedRanges[0].To != 20 {
		t.Fatalf("expected pruned range [0, 20), got %v", r.PrunedRanges)
	}
	if r.Checkpoints != 2 {
		t.Fatalf("expected 2 valid checkpoints, got %d", r.Checkpoints)
	}

	// Unlawfully delete an event outside the pruned range (leaf 25).
	f.tamper(t, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM whitetower.audit_events
			WHERE id = (SELECT audit_id FROM whitetower.audit_leaves WHERE leaf_index = 25)`)
		return err
	})

	r2 := f.verify(t, f.trusted(t))
	if r2.OK() {
		t.Fatal("unlawful deletion outside pruned range passed verification")
	}
	if len(r2.Problems) == 0 || r2.Problems[0].Kind != auditverify.EventMissing || r2.Problems[0].Index != 25 {
		t.Fatalf("expected EventMissing at leaf 25, got: %v", r2.Problems)
	}
}
