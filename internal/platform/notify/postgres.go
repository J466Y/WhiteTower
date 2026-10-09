package notify

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// channelPrefix sets White Tower's channels apart from any others in the
// database.
const channelPrefix = "whitetower."

// Defaults of the options.
const (
	DefaultCheckInterval = 10 * time.Second
	DefaultIdleTimeout   = time.Minute
)

// Bounds of the wait before the listener reconnects. The wait doubles after
// each failure, and starts again from the lower bound after a session that
// lasted.
const (
	minRetry = 100 * time.Millisecond
	maxRetry = 5 * time.Second
)

// checkTimeout bounds a check-in on the listening session.
const checkTimeout = 5 * time.Second

// PostgresOptions are what the PostgreSQL bus needs from the rest of the
// server.
type PostgresOptions struct {
	// DB opens the listening session.
	DB      *db.DB
	Logger  *slog.Logger
	Metrics *metrics.Notify
	// CheckInterval is how often the listener checks in on its session.
	CheckInterval time.Duration
	// IdleTimeout is how long the database keeps the session of a replica
	// that stopped checking in; at least three check intervals. A session
	// that the database keeps holds back the notifications it has not
	// read, and PostgreSQL makes every notifying transaction fail once its
	// queue of notifications is full.
	IdleTimeout time.Duration
}

// Postgres is the bus of a deployment. A change publishes its notification
// in its own transaction, with NOTIFY, which PostgreSQL delivers when the
// transaction commits. Each replica listens on one session of its own, and
// passes what it receives to its subscribers; when the session fails, it
// reconnects and tells every subscriber to resynchronize.
type Postgres struct {
	opts PostgresOptions

	mu   sync.Mutex
	subs subscriptions
	// dirty tells the listener that the subscriptions changed.
	dirty bool
	// interrupt ends the listener's wait for notifications, while it waits.
	interrupt context.CancelFunc
	// failing is the listener's: whether its last session failed.
	failing bool
}

var _ Bus = (*Postgres)(nil)

// NewPostgres returns a bus that listens once Run runs.
func NewPostgres(opts PostgresOptions) *Postgres {
	opts.CheckInterval = cmp.Or(opts.CheckInterval, DefaultCheckInterval)
	opts.IdleTimeout = max(cmp.Or(opts.IdleTimeout, DefaultIdleTimeout), 3*opts.CheckInterval)
	return &Postgres{opts: opts, subs: subscriptions{}}
}

// Publish implements Bus.
func (b *Postgres) Publish(ctx context.Context, tx *db.Tx, channel, payload string) error {
	if err := errors.Join(checkChannel(channel), checkPayload(payload)); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", channelPrefix+channel, payload)
	return err
}

// Subscribe implements Bus. The subscriber is told to resynchronize once the
// bus listens on the channel.
func (b *Postgres) Subscribe(channel string, s Subscriber) (func(), error) {
	if err := checkChannel(channel); err != nil {
		return nil, err
	}
	sub := newSubscription(channel, s, b.opts.Logger, b.opts.Metrics.Resynced)
	b.mu.Lock()
	b.subs.add(sub)
	b.changed()
	b.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			b.subs.remove(sub)
			b.changed()
			b.mu.Unlock()
			sub.stop()
		})
	}, nil
}

// changed tells the listener that the subscriptions changed. b.mu is held.
func (b *Postgres) changed() {
	b.dirty = true
	if b.interrupt != nil {
		b.interrupt()
	}
}

// Run listens until ctx ends, and reconnects whenever the session fails. It
// logs a warning when the listener starts failing and a message when it
// listens again; the attempts between them are logged at the debug level.
func (b *Postgres) Run(ctx context.Context) {
	retry := minRetry
	for {
		began := time.Now()
		err := b.listen(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(began) > maxRetry {
			retry = minRetry
		}
		level := slog.LevelDebug
		if !b.failing {
			b.failing, level = true, slog.LevelWarn
		}
		b.opts.Logger.Log(ctx, level, "notifications: the listening session failed; reconnecting",
			"error", err.Error(), "retry_in", retry.String())
		t := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		retry = min(2*retry, maxRetry)
	}
}

// listen holds one listening session until it fails or ctx ends; it returns
// an error unless ctx ended.
func (b *Postgres) listen(ctx context.Context) error {
	conn, err := b.opts.DB.Connect(ctx, "notify", b.opts.IdleTimeout)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	if b.failing {
		b.failing = false
		b.opts.Logger.InfoContext(ctx, "notifications: listening again; subscribers resynchronize")
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = conn.Close(cctx)
	}()

	// A new session listens on nothing yet: every subscriber will need to
	// resynchronize.
	b.mu.Lock()
	for _, subs := range b.subs {
		for sub := range subs {
			sub.covered = false
		}
	}
	b.dirty = true
	b.mu.Unlock()

	listening := map[string]bool{}
	b.opts.Metrics.Connected(true)
	defer b.opts.Metrics.Connected(false)
	checkIn := time.Now().Add(b.opts.CheckInterval)
	for {
		b.mu.Lock()
		dirty := b.dirty
		b.dirty = false
		b.mu.Unlock()
		if dirty {
			if err := b.update(ctx, conn, listening); err != nil {
				return err
			}
		}

		wait, cancel := context.WithDeadline(ctx, checkIn)
		b.mu.Lock()
		if b.dirty {
			b.mu.Unlock()
			cancel()
			continue
		}
		b.interrupt = cancel
		b.mu.Unlock()
		n, err := conn.WaitForNotification(wait)
		b.mu.Lock()
		b.interrupt = nil
		b.mu.Unlock()
		cancel()

		switch {
		case ctx.Err() != nil:
			return nil
		case err == nil:
			b.dispatch(n)
		case !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !pgconn.Timeout(err):
			return fmt.Errorf("waiting for notifications: %w", err)
		}
		// The wait ended with a notification, a change of subscriptions, or
		// the time to check in, which a busy channel must not put off: the
		// database counts a session that receives but runs nothing as idle.
		if !time.Now().Before(checkIn) {
			pctx, cancel := context.WithTimeout(ctx, checkTimeout)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return fmt.Errorf("checking in: %w", err)
			}
			checkIn = time.Now().Add(b.opts.CheckInterval)
		}
	}
}

// update makes the session listen on the channels that have subscribers, and
// on no others; then it tells the subscribers it newly covers to
// resynchronize. From then on, they miss nothing until the session fails.
func (b *Postgres) update(ctx context.Context, conn *pgx.Conn, listening map[string]bool) error {
	b.mu.Lock()
	want := make(map[string]bool, len(b.subs))
	for channel := range b.subs {
		want[channel] = true
	}
	b.mu.Unlock()
	for channel := range want {
		if !listening[channel] {
			if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channelPrefix + channel}.Sanitize()); err != nil {
				return fmt.Errorf("listening on %s: %w", channel, err)
			}
			listening[channel] = true
		}
	}
	for channel := range listening {
		if !want[channel] {
			if _, err := conn.Exec(ctx, "UNLISTEN "+pgx.Identifier{channelPrefix + channel}.Sanitize()); err != nil {
				return fmt.Errorf("unlistening on %s: %w", channel, err)
			}
			delete(listening, channel)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for channel, subs := range b.subs {
		if !listening[channel] {
			continue
		}
		for sub := range subs {
			if !sub.covered {
				sub.covered = true
				sub.resynchronize(reasonListening)
			}
		}
	}
	return nil
}

// dispatch passes a notification to the subscribers of its channel, without
// waiting for any of them.
func (b *Postgres) dispatch(n *pgconn.Notification) {
	channel, ok := strings.CutPrefix(n.Channel, channelPrefix)
	if !ok {
		return
	}
	b.opts.Metrics.Received(channel)
	b.mu.Lock()
	defer b.mu.Unlock()
	for sub := range b.subs[channel] {
		sub.push(n.Payload)
	}
}
