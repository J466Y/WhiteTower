package govstate

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/notify"
)

var (
	discard     = slog.New(slog.DiscardHandler)
	errRollBack = errors.New("roll back")
)

// announcement is a notification sent once committed, with the head's
// version that a read outside the transaction saw as it was sent.
type announcement struct {
	channel, payload string
	head             int64
}

// announcements is a bus that records what is published once committed, and
// then fails with err when it is set. Nothing else of the bus is used.
type announcements struct {
	notify.Bus
	pool *db.DB
	err  error
	sent []announcement
}

func (a *announcements) PublishCommitted(ctx context.Context, channel, payload string) error {
	var committed int64
	if err := a.pool.QueryRow(ctx, "SELECT version FROM whitetower.governance_head").Scan(&committed); err != nil {
		return err
	}
	a.sent = append(a.sent, announcement{channel: channel, payload: payload, head: committed})
	return a.err
}

// head returns the head's committed version.
func head(t *testing.T, pool *db.DB) int64 {
	t.Helper()
	var v int64
	if err := pool.QueryRow(context.Background(), "SELECT version FROM whitetower.governance_head").Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// take runs a transaction that takes a version, then commits or, with an
// error, rolls back, and returns the version.
func take(t *testing.T, pool *db.DB, versions *Versions, end error) int64 {
	t.Helper()
	var v int64
	if err := pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) (err error) {
		if v, err = versions.Next(ctx, tx); err != nil {
			return err
		}
		return end
	}); !errors.Is(err, end) {
		t.Fatal(err)
	}
	return v
}

// The criterion of the design of the halt path, section 2: a transaction
// takes one version, however often it asks, in Go or in SQL, and the next
// transaction the version after it. A version that a transaction took before
// it rolled back is handed out again: nothing ever saw it.
func TestATransactionTakesOneVersionFromTheHead(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t).Open(t)
	versions := NewVersions(notify.NewMemory(), discard)

	// The migration started the head from the sequence, whose last number
	// went to the fleet's record.
	var fleet int64
	if err := pool.QueryRow(ctx, "SELECT state_version FROM whitetower.fleet_state").Scan(&fleet); err != nil {
		t.Fatal(err)
	}
	if start := head(t, pool); start != fleet {
		t.Fatalf("the head starts at %d, want the sequence's last number, %d", start, fleet)
	}
	var first, again, inSQL int64
	if err := pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) (err error) {
		if first, err = versions.Next(ctx, tx); err != nil {
			return err
		}
		if again, err = versions.Next(ctx, tx); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT whitetower.next_governance_version()").Scan(&inSQL)
	}); err != nil {
		t.Fatal(err)
	}
	if first != fleet+1 || again != first || inSQL != first || head(t, pool) != first {
		t.Fatalf("versions %d, %d and %d, head %d: want %d each time, and the head at it", first, again, inSQL, head(t, pool), fleet+1)
	}
	if lost := take(t, pool, versions, errRollBack); lost != first+1 || head(t, pool) != first {
		t.Fatalf("a rollback at version %d left the head at %d, want %d and %d", lost, head(t, pool), first+1, first)
	}
	if next := take(t, pool, versions, nil); next != first+1 {
		t.Errorf("version %d after a rollback, want %d again", next, first+1)
	}
}

// Commit order is version order: a transaction that took its version holds
// the head until it ends, and the next one takes the version after it only
// then.
func TestTheNextTransactionWaitsForTheHeadUntilTheFirstEnds(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t).Open(t)
	versions := NewVersions(notify.NewMemory(), discard)

	held, release, first := make(chan int64, 1), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free) // so that a failure never leaves the pool waiting for the transaction
	go func() {
		first <- pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			v, err := versions.Next(ctx, tx)
			if err == nil {
				held <- v
				<-release
			}
			return err
		})
	}()
	var v int64
	select {
	case v = <-held:
	case err := <-first:
		t.Fatal(err)
	}
	var next int64
	second := make(chan error, 1)
	go func() {
		second <- pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) (err error) {
			next, err = versions.Next(ctx, tx)
			return err
		})
	}()
	for deadline := time.Now().Add(10 * time.Second); lockWaits(t, pool) < 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the second transaction never waited for the head")
		}
	}
	free()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil || next != v+1 {
		t.Errorf("the second transaction took version %d (%v), want %d", next, err, v+1)
	}
}

// lockWaits counts the sessions of the test's database that wait for a lock.
func lockWaits(t *testing.T, pool *db.DB) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A change is announced to the replicas once, however often its transaction
// takes its version, and only after it commits: a read outside the
// transaction already sees the head at that version. A change that rolls back
// is never announced. An announcement that fails only asks the replicas to
// read later, within a second: the change stays committed, and the failure is
// logged.
func TestAChangeIsAnnouncedOnceItCommits(t *testing.T) {
	pool := dbtest.New(t).Open(t)
	var logs bytes.Buffer
	bus := &announcements{pool: pool}
	versions := NewVersions(bus, slog.New(slog.NewJSONHandler(&logs, nil)))

	var v int64
	if err := pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) (err error) {
		for range 3 {
			if v, err = versions.Next(ctx, tx); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	take(t, pool, versions, errRollBack)
	want := announcement{channel: "governance", payload: strconv.FormatInt(v, 10), head: v}
	if len(bus.sent) != 1 || bus.sent[0] != want {
		t.Fatalf("announced %+v, want only %+v", bus.sent, want)
	}

	bus.err = errors.New("the notification queue is full")
	failed := take(t, pool, versions, nil)
	if head(t, pool) != failed || !strings.Contains(logs.String(), `"state_version":`+strconv.FormatInt(failed, 10)) ||
		!strings.Contains(logs.String(), "the notification queue is full") {
		t.Errorf("head %d after version %d; logs %s", head(t, pool), failed, logs.String())
	}
}

// A pooled connection keeps the setting that holds the version, empty once
// its transaction ended: the next transaction takes a version of its own,
// and a write without one is refused for that, not for the empty setting.
func TestEachTransactionOfAConnectionTakesItsOwnVersion(t *testing.T) {
	ctx := context.Background()
	cfg := dbtest.New(t).Config
	cfg.MaxConnections = 1
	pool, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	versions := NewVersions(notify.NewMemory(), discard)

	first := take(t, pool, versions, nil)
	var setting *string
	if err := pool.QueryRow(ctx, "SELECT current_setting('whitetower.governance_version', true)").Scan(&setting); err != nil {
		t.Fatal(err)
	}
	if setting == nil || *setting != "" {
		t.Fatalf("the connection's setting is %v, want an empty string", setting)
	}
	err = pool.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE whitetower.fleet_state SET updated_at = now()")
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23000" {
		t.Errorf("a write without a version: %v, want SQLSTATE 23000", err)
	}
	if next := take(t, pool, versions, nil); next != first+1 {
		t.Errorf("version %d after %d", next, first)
	}
}

// After a version regression, the head moves forward past every version an
// instance applied, never back, and the versions that follow are above it
// (the design of the halt path, section 10).
func TestTheHeadAdvancesButNeverMovesBack(t *testing.T) {
	pool := dbtest.New(t).Open(t)
	versions := NewVersions(notify.NewMemory(), discard)
	advance := func(target int64) int64 {
		t.Helper()
		var v int64
		if err := pool.QueryRow(context.Background(), "SELECT whitetower.advance_governance_version($1)", target).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	start := head(t, pool)
	if v := advance(start + 1000); v != start+1000 || head(t, pool) != start+1000 {
		t.Fatalf("advanced to %d, head %d: want %d", v, head(t, pool), start+1000)
	}
	if v := advance(start); v != start+1000 || head(t, pool) != start+1000 {
		t.Fatalf("advancing to %d moved the head back to %d", start, head(t, pool))
	}
	if v := take(t, pool, versions, nil); v != start+1001 {
		t.Errorf("version %d after the advance, want %d", v, start+1001)
	}
}
