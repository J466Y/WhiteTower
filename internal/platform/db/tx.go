package db

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Tx is a transaction that InTx runs. It runs statements but cannot end the
// transaction: InTx commits it or rolls it back.
type Tx struct {
	tx           pgx.Tx
	beforeCommit []func(context.Context) error
	afterCommit  []func(context.Context)
}

// Exec runs a statement in the transaction.
func (t *Tx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}

// Query runs a query in the transaction.
func (t *Tx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.tx.Query(ctx, sql, args...)
}

// QueryRow runs a query that returns at most one row, in the transaction.
func (t *Tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}

// CopyFrom inserts rows in bulk, in the transaction.
func (t *Tx) CopyFrom(ctx context.Context, table pgx.Identifier, columns []string, rows pgx.CopyFromSource) (int64, error) {
	return t.tx.CopyFrom(ctx, table, columns, rows)
}

// SendBatch sends a batch of statements, in the transaction.
func (t *Tx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return t.tx.SendBatch(ctx, b)
}

// BeforeCommit registers fn to run in the transaction, after the work and
// just before the commit; an error rolls the whole transaction back. It
// serves what must be done, or checked, once the transaction's work is
// complete.
func (t *Tx) BeforeCommit(fn func(ctx context.Context) error) {
	t.beforeCommit = append(t.beforeCommit, fn)
}

// AfterCommit registers fn to run once the transaction has committed, for
// what must never happen for a change that rolled back and cannot take part
// in the transaction, such as work outside the database. fn gets a context
// that the caller's cancellation does not end, and handles its own failures:
// the change is already made. Notifications to the other replicas need no
// hook: notify.Bus sends them in the transaction itself.
func (t *Tx) AfterCommit(fn func(ctx context.Context)) {
	t.afterCommit = append(t.afterCommit, fn)
}

// maxAttempts bounds how often InTx runs a transaction that loses a
// serialization conflict or a deadlock.
const maxAttempts = 3

// InTx runs fn in a transaction of the runtime role, then the BeforeCommit
// hooks; then it commits and runs the AfterCommit hooks. An error from fn or
// from a BeforeCommit hook, or a panic, rolls everything back, and no
// AfterCommit hook runs. A transaction that loses a serialization conflict or
// a deadlock runs again, up to three times in all: fn must have no effect
// outside the transaction except through its hooks.
func (db *DB) InTx(ctx context.Context, fn func(ctx context.Context, tx *Tx) error) error {
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err = db.runTx(ctx, fn); err == nil || !retryable(err) {
			return err
		}
		// A short pause, varied so that the same transactions do not collide again.
		pause := time.Duration(attempt*10+rand.IntN(20)) * time.Millisecond //nolint:gosec // G404: jitter, not a secret
		select {
		case <-ctx.Done():
			return err
		case <-time.After(pause):
		}
	}
	return err
}

func (db *DB) runTx(ctx context.Context, fn func(context.Context, *Tx) error) error {
	ptx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	// After a commit, Rollback does nothing; after a failure or a panic, it
	// ends the transaction.
	defer func() { _ = ptx.Rollback(ctx) }()

	tx := &Tx{tx: ptx}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	for i := 0; i < len(tx.beforeCommit); i++ { // a hook may register another
		if err := tx.beforeCommit[i](ctx); err != nil {
			return err
		}
	}
	if err := ptx.Commit(ctx); err != nil {
		return err
	}
	committed := context.WithoutCancel(ctx)
	for _, fn := range tx.afterCommit {
		fn(committed)
	}
	return nil
}

// retryable reports a serialization failure or a deadlock, which the same
// transaction may pass when it runs again.
func retryable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40001" || pgErr.Code == "40P01")
}
