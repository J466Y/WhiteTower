package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// bulkLoad stores n events and seals them directly, chunk by chunk, without
// the queue: the fastest path, used to grow the log for the verification
// test. Events get ingestion times spread over [from, to).
func (s *sealer) bulkLoad(ctx context.Context, g *generator, n int, from, to time.Time, chunk int) (time.Duration, error) {
	start := time.Now()
	span := to.Sub(from)
	for done := 0; done < n; {
		k := min(chunk, n-done)
		events, ids, leaves := make([][]any, 0, k), make([][]any, 0, k), make([][]any, 0, k)
		var hashes [][]any
		sealedAt := time.Now()
		for i := range k {
			at := from.Add(time.Duration(float64(span) * float64(done+i) / float64(n)))
			e, err := g.next(at, 0, 1)
			if err != nil {
				return 0, err
			}
			events = append(events, []any{
				e.ID, at, e.Source, e.EventID, e.Seq, e.Type, e.Time, e.Agent, "agent", e.Agent,
				e.Action, e.Outcome, e.Reason, e.TraceID, e.Canonical,
			})
			ids = append(ids, []any{e.Source, e.EventID, time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC), e.ID})
			leaf := tlog.RecordHash(e.Canonical)
			stored, err := tlog.StoredHashesForRecordHash(s.size, leaf, s.store)
			if err != nil {
				return 0, err
			}
			base := tlog.StoredHashIndex(0, s.size)
			for j, h := range stored {
				s.store.put(base+int64(j), h)
				hashes = append(hashes, []any{base + int64(j), h[:]})
			}
			leaves = append(leaves, []any{s.size, e.ID, at, leaf[:], sealedAt})
			s.size++
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return 0, err
		}
		copies := []struct {
			table string
			cols  []string
			rows  [][]any
		}{
			{"audit_events", []string{
				"id", "ingested_at", "source", "event_id", "source_seq", "type", "event_time", "subject_agent_id",
				"actor_type", "actor_id", "action", "outcome", "reason", "trace_id", "canonical",
			}, events},
			{"audit_event_ids", []string{"source", "event_id", "ingest_month", "audit_id"}, ids},
			{"audit_leaves", []string{"leaf_index", "audit_id", "ingested_at", "leaf_hash", "sealed_at"}, leaves},
			{"audit_tree_hashes", []string{"hash_index", "hash"}, hashes},
		}
		for _, c := range copies {
			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"whitetower", c.table}, c.cols, pgx.CopyFromRows(c.rows)); err != nil {
				_ = tx.Rollback(ctx)
				return 0, fmt.Errorf("%s: %w", c.table, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
		s.store.keepRightEdge(s.size)
		done += k
	}
	return time.Since(start), nil
}

// verifyResult is what a full verification found.
type verifyResult struct {
	Leaves          int64         `json:"leaves"`
	WithContent     int64         `json:"leaves_with_content"`
	HashOnly        int64         `json:"leaves_without_content"`
	Mismatches      int64         `json:"content_mismatches"`
	Duration        time.Duration `json:"duration_ns"`
	RootMatches     bool          `json:"root_matches_checkpoint"`
	PerSecond       float64       `json:"leaves_per_second"`
	ReadTime        time.Duration `json:"read_ns"`
	HashTime        time.Duration `json:"hash_ns"`
	BytesRead       int64         `json:"bytes_read"`
	ReadMBPerSecond float64       `json:"read_mb_per_second"`
	Chunk           int64         `json:"chunk_leaves"`
	ChunkTime       summary       `json:"chunk_ms"`
}

// openCheckpoint verifies a signed checkpoint and returns the tree it states.
func openCheckpoint(signed string, verifier note.Verifier) (tlog.Tree, error) {
	n, err := note.Open([]byte(signed), note.VerifierList(verifier))
	if err != nil {
		return tlog.Tree{}, err
	}
	lines := strings.Split(n.Text, "\n")
	if len(lines) < 3 {
		return tlog.Tree{}, errors.New("malformed checkpoint")
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return tlog.Tree{}, err
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != tlog.HashSize {
		return tlog.Tree{}, errors.New("malformed root hash")
	}
	return tlog.Tree{N: size, Hash: tlog.Hash(root)}, nil
}

// latestCheckpoint returns the most recent signed checkpoint.
func latestCheckpoint(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var signed string
	err := pool.QueryRow(ctx, `SELECT signed_note FROM whitetower.audit_checkpoints ORDER BY tree_size DESC LIMIT 1`).Scan(&signed)
	return signed, err
}

// verifyLog is what `wtctl audit verify` does: check the checkpoint's
// signature, recompute every leaf from the stored event, rebuild the tree and
// compare its root with the checkpoint. Leaves whose events were dropped by
// retention count with their stored hash.
//
// It reads the log in chunks of leaves, so each query looks events up through
// their primary key and needs little memory. One query over the whole log
// makes PostgreSQL hash-join and sort it on disk.
func verifyLog(ctx context.Context, pool *pgxpool.Pool, signed string, verifier note.Verifier, chunk int64) (verifyResult, []tlog.Hash, error) {
	res := verifyResult{Chunk: chunk}
	tree, err := openCheckpoint(signed, verifier)
	if err != nil {
		return res, nil, err
	}
	type row struct{ stored, canonical []byte }
	start := time.Now()
	leaves := make([]tlog.Hash, 0, tree.N)
	var stack []level
	var chunks []time.Duration
	for from := int64(0); from < tree.N; from += chunk {
		to := min(from+chunk, tree.N)
		readStart := time.Now()
		rows, err := pool.Query(ctx, `SELECT l.leaf_index, l.leaf_hash, e.canonical
		                              FROM whitetower.audit_leaves l
		                              LEFT JOIN whitetower.audit_events e ON e.ingested_at = l.ingested_at AND e.id = l.audit_id
		                              WHERE l.leaf_index >= $1 AND l.leaf_index < $2 ORDER BY l.leaf_index`, from, to)
		if err != nil {
			return res, nil, err
		}
		got := make([]row, 0, to-from)
		for rows.Next() {
			var idx int64
			var r row
			if err := rows.Scan(&idx, &r.stored, &r.canonical); err != nil {
				rows.Close()
				return res, nil, err
			}
			if idx != from+int64(len(got)) {
				rows.Close()
				return res, nil, fmt.Errorf("leaf %d missing", from+int64(len(got)))
			}
			res.BytesRead += int64(len(r.stored) + len(r.canonical))
			got = append(got, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return res, nil, err
		}
		if int64(len(got)) != to-from {
			return res, nil, fmt.Errorf("leaf %d missing", from+int64(len(got)))
		}
		hashStart := time.Now()
		res.ReadTime += hashStart.Sub(readStart)
		for _, r := range got {
			h := tlog.Hash(r.stored)
			if r.canonical != nil {
				res.WithContent++
				if computed := tlog.RecordHash(r.canonical); computed != h {
					res.Mismatches++
					h = computed
				}
			} else {
				res.HashOnly++
			}
			leaves = append(leaves, h)
			stack = push(stack, h)
			res.Leaves++
		}
		res.HashTime += time.Since(hashStart)
		chunks = append(chunks, time.Since(readStart))
	}
	res.RootMatches = root(stack) == tree.Hash && res.Leaves == tree.N
	res.Duration = time.Since(start)
	res.PerSecond = float64(res.Leaves) / res.Duration.Seconds()
	res.ReadMBPerSecond = float64(res.BytesRead) / 1e6 / res.ReadTime.Seconds()
	res.ChunkTime = summarize(chunks)
	return res, leaves, nil
}

// level is a complete subtree on the right edge of a tree being built.
type level struct {
	height int
	hash   tlog.Hash
}

// push appends a leaf to a compact Merkle range (RFC 6962 hashing).
func push(stack []level, h tlog.Hash) []level {
	stack = append(stack, level{0, h})
	for len(stack) >= 2 && stack[len(stack)-1].height == stack[len(stack)-2].height {
		l, r := stack[len(stack)-2], stack[len(stack)-1]
		stack = append(stack[:len(stack)-2], level{l.height + 1, tlog.NodeHash(l.hash, r.hash)})
	}
	return stack
}

// root folds the right edge into the tree's root hash.
func root(stack []level) tlog.Hash {
	if len(stack) == 0 {
		return tlog.Hash{}
	}
	h := stack[len(stack)-1].hash
	for i := len(stack) - 2; i >= 0; i-- {
		h = tlog.NodeHash(stack[i].hash, h)
	}
	return h
}

// proofResult is the cost of proofs.
type proofResult struct {
	Inclusion       summary `json:"inclusion_ms"`
	InclusionHashes int     `json:"inclusion_proof_hashes"`
	Consistency     summary `json:"consistency_ms"`
	ConsistencySize int     `json:"consistency_proof_hashes"`
	Verified        int     `json:"verified"`
}

// proveAndCheck proves random leaves against a checkpoint, and each earlier
// checkpoint against it, and checks every proof as a client would.
func proveAndCheck(ctx context.Context, pool *pgxpool.Pool, store *hashStore, tree tlog.Tree, earlier []tlog.Tree, count int) (proofResult, error) {
	var res proofResult
	var inc, cons []time.Duration
	for range count {
		n := mathrand.Int64N(tree.N) //nolint:gosec // G404: choosing a leaf needs no cryptographic randomness
		var leaf []byte
		if err := pool.QueryRow(ctx, `SELECT leaf_hash FROM whitetower.audit_leaves WHERE leaf_index = $1`, n).Scan(&leaf); err != nil {
			return res, err
		}
		start := time.Now()
		proof, err := tlog.ProveRecord(tree.N, n, store)
		if err != nil {
			return res, err
		}
		if err := tlog.CheckRecord(proof, tree.N, tree.Hash, n, tlog.Hash(leaf)); err != nil {
			return res, fmt.Errorf("inclusion of %d: %w", n, err)
		}
		inc = append(inc, time.Since(start))
		res.InclusionHashes = len(proof)
		res.Verified++
	}
	for _, old := range earlier {
		if old.N >= tree.N {
			continue
		}
		start := time.Now()
		proof, err := tlog.ProveTree(tree.N, old.N, store)
		if err != nil {
			return res, err
		}
		if err := tlog.CheckTree(proof, tree.N, tree.Hash, old.N, old.Hash); err != nil {
			return res, fmt.Errorf("consistency %d to %d: %w", old.N, tree.N, err)
		}
		cons = append(cons, time.Since(start))
		res.ConsistencySize = len(proof)
		res.Verified++
	}
	res.Inclusion, res.Consistency = summarize(inc), summarize(cons)
	return res, nil
}

// chainResult compares a plain hash chain with the Merkle tree, on the same
// leaves.
type chainResult struct {
	Leaves          int           `json:"leaves"`
	ChainCompute    time.Duration `json:"chain_compute_ns"`
	MerkleCompute   time.Duration `json:"merkle_compute_ns"`
	ChainProofMax   int           `json:"chain_inclusion_proof_hashes_worst"`
	MerkleProof     int           `json:"merkle_inclusion_proof_hashes"`
	ChainBytes      int64         `json:"chain_storage_bytes_per_leaf"`
	MerkleBytes     float64       `json:"merkle_tree_hash_rows_per_leaf"`
	StoredHashCount int64         `json:"merkle_stored_hashes"`
}

func compareChain(leaves []tlog.Hash) chainResult {
	res := chainResult{Leaves: len(leaves), ChainBytes: sha256.Size}
	start := time.Now()
	var prev [sha256.Size]byte
	for _, h := range leaves {
		prev = sha256.Sum256(append(prev[:], h[:]...))
	}
	res.ChainCompute = time.Since(start)
	start = time.Now()
	var stack []level
	for _, h := range leaves {
		stack = push(stack, h)
	}
	_ = root(stack)
	res.MerkleCompute = time.Since(start)
	// Proving the first leaf in a chain needs every later link; in the tree,
	// one hash per level.
	res.ChainProofMax = len(leaves) - 1
	for n := len(leaves); n > 1; n = (n + 1) / 2 {
		res.MerkleProof++
	}
	res.StoredHashCount = tlog.StoredHashCount(int64(len(leaves)))
	res.MerkleBytes = float64(res.StoredHashCount) / float64(len(leaves))
	return res
}
