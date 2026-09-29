package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// hashStore reads Merkle tree hashes: from memory for the right edge of the
// tree, which every append needs, and from the database for the rest, which
// only proofs need.
type hashStore struct {
	pool  *pgxpool.Pool
	mu    sync.Mutex
	cache map[int64]tlog.Hash
	reads atomic.Int64 // hashes read from the database
}

func newHashStore(pool *pgxpool.Pool) *hashStore {
	return &hashStore{pool: pool, cache: map[int64]tlog.Hash{}}
}

// ReadHashes implements tlog.HashReader.
func (s *hashStore) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	filled := make([]bool, len(indexes))
	var missing []int64
	s.mu.Lock()
	for i, idx := range indexes {
		if h, ok := s.cache[idx]; ok {
			out[i], filled[i] = h, true
		} else {
			missing = append(missing, idx)
		}
	}
	s.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}
	s.reads.Add(int64(len(missing)))
	rows, err := s.pool.Query(context.Background(), `SELECT hash_index, hash FROM whitetower.audit_tree_hashes WHERE hash_index = ANY($1)`, missing)
	if err != nil {
		return nil, err
	}
	found := map[int64]tlog.Hash{}
	for rows.Next() {
		var idx int64
		var h []byte
		if err := rows.Scan(&idx, &h); err != nil {
			rows.Close()
			return nil, err
		}
		found[idx] = tlog.Hash(h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, idx := range indexes {
		if !filled[i] {
			h, ok := found[idx]
			if !ok {
				return nil, fmt.Errorf("tree hash %d not found", idx)
			}
			out[i] = h
		}
	}
	return out, nil
}

// keepRightEdge forgets every cached hash except the roots of the complete
// subtrees of a tree of size n: the only ones the next append reads.
func (s *hashStore) keepRightEdge(n int64) {
	keep := map[int64]bool{}
	start := int64(0)
	for level := 62; level >= 0; level-- {
		if n>>level&1 == 1 {
			keep[tlog.StoredHashIndex(level, start>>level)] = true
			start += 1 << level
		}
	}
	s.mu.Lock()
	for idx := range s.cache {
		if !keep[idx] {
			delete(s.cache, idx)
		}
	}
	s.mu.Unlock()
}

func (s *hashStore) put(idx int64, h tlog.Hash) {
	s.mu.Lock()
	s.cache[idx] = h
	s.mu.Unlock()
}

// sealer appends ingested events to the Merkle tree and signs checkpoints. The
// core runs exactly one, on the leader replica.
type sealer struct {
	pool     *pgxpool.Pool
	store    *hashStore
	size     int64
	batch    int
	signer   note.Signer
	origin   string
	keyID    string
	sealed   atomic.Int64
	batches  atomic.Int64
	biggest  atomic.Int64
	mu       sync.Mutex
	backlogs []int64         // queue length seen at each round
	txTimes  []time.Duration // duration of each sealing transaction
	txSizes  []int           // events sealed by each
	txSteps  []sealSteps     // where each one's time went
	cpTimes  []time.Duration // duration of each checkpoint
}

// sealSteps is where a sealing transaction's time went.
type sealSteps struct {
	Claim  time.Duration `json:"claim_ns"`  // taking events off the queue
	Fetch  time.Duration `json:"fetch_ns"`  // reading their canonical bytes
	Hash   time.Duration `json:"hash_ns"`   // leaf and tree hashes
	Write  time.Duration `json:"write_ns"`  // copying leaves and tree hashes
	Commit time.Duration `json:"commit_ns"` // committing
}

// sealBatch seals up to s.batch events from the queue in one transaction and
// returns how many it sealed.
//
// It claims events by deleting them from the queue, without row locks: only
// one sealer runs, and if a second one ever did, the DELETE would still hand
// each event to one of them, and the primary key on the leaf index would
// reject the second one's batch. So the runtime role needs no UPDATE on the
// queue, which row locks would require.
func (s *sealer) sealBatch(ctx context.Context) (int, error) {
	start := time.Now()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var steps sealSteps
	mark := time.Now()
	lap := func(d *time.Duration) {
		now := time.Now()
		*d, mark = now.Sub(mark), now
	}
	rows, err := tx.Query(ctx, `DELETE FROM whitetower.audit_unsealed WHERE audit_id IN (
	                              SELECT audit_id FROM whitetower.audit_unsealed ORDER BY ingested_at, audit_id LIMIT $1)
	                            RETURNING audit_id::text, ingested_at`, s.batch)
	if err != nil {
		return 0, err
	}
	type pending struct {
		id string
		at time.Time
	}
	var batch []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.at); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(batch) == 0 {
		return 0, err
	}
	lap(&steps.Claim)
	// The log's order: ingestion time, then ID.
	slices.SortFunc(batch, func(a, b pending) int {
		if c := a.at.Compare(b.at); c != 0 {
			return c
		}
		if a.id < b.id {
			return -1
		}
		return 1
	})
	ids := make([]string, len(batch))
	for i, p := range batch {
		ids[i] = p.id
	}
	canon := map[string][]byte{}
	crows, err := tx.Query(ctx, `SELECT id::text, canonical FROM whitetower.audit_events WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return 0, err
	}
	for crows.Next() {
		var id string
		var raw []byte
		if err := crows.Scan(&id, &raw); err != nil {
			crows.Close()
			return 0, err
		}
		canon[id] = raw
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return 0, err
	}

	var sealedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&sealedAt); err != nil {
		return 0, err
	}
	lap(&steps.Fetch)
	leaves := make([][]any, 0, len(batch))
	var hashes [][]any
	n := s.size
	for _, p := range batch {
		raw, ok := canon[p.id]
		if !ok {
			return 0, fmt.Errorf("event %s is queued but not stored", p.id)
		}
		leaf := tlog.RecordHash(raw)
		stored, err := tlog.StoredHashesForRecordHash(n, leaf, s.store)
		if err != nil {
			return 0, err
		}
		base := tlog.StoredHashIndex(0, n)
		for i, h := range stored {
			s.store.put(base+int64(i), h)
			hashes = append(hashes, []any{base + int64(i), h[:]})
		}
		leaves = append(leaves, []any{n, p.id, p.at, leaf[:], sealedAt})
		n++
	}
	lap(&steps.Hash)
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"whitetower", "audit_leaves"},
		[]string{"leaf_index", "audit_id", "ingested_at", "leaf_hash", "sealed_at"}, pgx.CopyFromRows(leaves)); err != nil {
		return 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"whitetower", "audit_tree_hashes"},
		[]string{"hash_index", "hash"}, pgx.CopyFromRows(hashes)); err != nil {
		return 0, err
	}
	lap(&steps.Write)
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	lap(&steps.Commit)
	took := time.Since(start)
	if took > time.Second {
		log.Printf("sealer: %d events took %v: %+v", len(batch), took.Round(time.Millisecond), steps)
	}
	s.mu.Lock()
	s.txTimes = append(s.txTimes, took)
	s.txSizes = append(s.txSizes, len(batch))
	s.txSteps = append(s.txSteps, steps)
	s.mu.Unlock()
	s.size = n
	s.store.keepRightEdge(n)
	s.sealed.Add(int64(len(batch)))
	s.batches.Add(1)
	if int64(len(batch)) > s.biggest.Load() {
		s.biggest.Store(int64(len(batch)))
	}
	return len(batch), nil
}

// checkpoint signs the current tree as a C2SP tlog-checkpoint signed note and
// stores it.
func (s *sealer) checkpoint(ctx context.Context) (tlog.Tree, error) {
	if s.size == 0 {
		return tlog.Tree{}, errors.New("empty tree")
	}
	start := time.Now()
	defer func() {
		s.mu.Lock()
		s.cpTimes = append(s.cpTimes, time.Since(start))
		s.mu.Unlock()
	}()
	root, err := tlog.TreeHash(s.size, s.store)
	if err != nil {
		return tlog.Tree{}, err
	}
	text := fmt.Sprintf("%s\n%d\n%s\n", s.origin, s.size, base64.StdEncoding.EncodeToString(root[:]))
	signed, err := note.Sign(&note.Note{Text: text}, s.signer)
	if err != nil {
		return tlog.Tree{}, err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO whitetower.audit_checkpoints (tree_size, root_hash, signed_note, key_id)
	                           VALUES ($1, $2, $3, $4) ON CONFLICT (tree_size) DO NOTHING`, s.size, root[:], string(signed), s.keyID)
	return tlog.Tree{N: s.size, Hash: root}, err
}

// run seals continuously and signs a checkpoint at each interval, until ctx
// ends. It returns the checkpoints it signed.
func (s *sealer) run(ctx context.Context, every, checkpointEvery time.Duration, trees chan<- tlog.Tree) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	lastCheckpoint := time.Now()
	for {
		// Drain the queue, then wait for the next round.
		for {
			sealed, err := s.sealBatch(ctx)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("sealer: %v", err)
				}
				break
			}
			if sealed < s.batch {
				break
			}
		}
		if time.Since(lastCheckpoint) >= checkpointEvery && s.size > 0 {
			if t, err := s.checkpoint(context.WithoutCancel(ctx)); err == nil {
				trees <- t
			} else {
				log.Printf("checkpoint: %v", err)
			}
			lastCheckpoint = time.Now()
		}
		var queued int64
		_ = s.pool.QueryRow(context.WithoutCancel(ctx), `SELECT count(*) FROM whitetower.audit_unsealed`).Scan(&queued)
		s.mu.Lock()
		s.backlogs = append(s.backlogs, queued)
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
