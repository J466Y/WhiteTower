package notify

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/db/dbtest"
	"github.com/J466Y/WhiteTower/internal/platform/metrics"
)

// listener is a replica's bus, listening until the test ends.
type listener struct {
	*Postgres
	pool     *db.DB
	registry *prometheus.Registry
}

func listen(t *testing.T, d *dbtest.Database, replica string, opts PostgresOptions) *listener {
	t.Helper()
	pool := d.OpenReplica(t, replica)
	reg := prometheus.NewRegistry()
	opts.DB, opts.Logger, opts.Metrics = pool, slog.New(slog.DiscardHandler), metrics.NewNotify(reg)
	b := NewPostgres(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &listener{Postgres: b, pool: pool, registry: reg}
}

var errRollBack = errors.New("roll back")

// publish publishes payload on channel in a transaction of the replica,
// which commits or rolls back.
func (l *listener) publish(t *testing.T, channel, payload string, commit bool) {
	t.Helper()
	err := l.pool.InTx(context.Background(), func(ctx context.Context, tx *db.Tx) error {
		if err := l.Publish(ctx, tx, channel, payload); err != nil {
			return err
		}
		if !commit {
			return errRollBack
		}
		return nil
	})
	if commit && err != nil || !commit && !errors.Is(err, errRollBack) {
		t.Fatal(err)
	}
}

// metric returns the value of one of the replica's series: the one whose
// label has the value, or the first one when label is "".
func (l *listener) metric(t *testing.T, name, label, value string) float64 {
	t.Helper()
	families, err := l.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			matched := label == ""
			for _, p := range m.GetLabel() {
				matched = matched || p.GetName() == label && p.GetValue() == value
			}
			if matched {
				return m.GetGauge().GetValue() + m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// The criterion of plan P1-01, step 8: a change committed on one replica
// reaches the listeners of the others, and its own; a change rolled back
// reaches none.
func TestNotificationsReachEveryReplica(t *testing.T) {
	d := dbtest.New(t)
	a := listen(t, d, "replica-a", PostgresOptions{})
	b := listen(t, d, "replica-b", PostgresOptions{})
	onA, onB := newRecorder(), newRecorder()
	subscribe(t, a, "governance", onA)
	subscribe(t, b, "governance", onB)
	onA.expect(t, "resync")
	onB.expect(t, "resync")

	a.publish(t, "governance", "41", false)
	a.publish(t, "governance", "42", true)
	b.publish(t, "governance", "43", true)
	for _, r := range []*recorder{onA, onB} {
		r.expect(t, "42", "43")
		r.quiet(t)
	}
	if got := b.metric(t, "whitetower_notify_received_total", "channel", "governance"); got != 2 {
		t.Errorf("%v notifications counted on b, want 2", got)
	}
}

// Notifications arrive in the order their transactions commit.
func TestNotificationsKeepTheCommitOrder(t *testing.T) {
	d := dbtest.New(t)
	a := listen(t, d, "replica-a", PostgresOptions{})
	b := listen(t, d, "replica-b", PostgresOptions{})
	r := newRecorder()
	subscribe(t, b, "governance", r)
	r.expect(t, "resync")
	var want []string
	for i := range 50 {
		a.publish(t, "governance", strconv.Itoa(i), true)
		want = append(want, strconv.Itoa(i))
	}
	r.expect(t, want...)
}

// The criterion of plan P1-01, step 8: a lost listening session makes every
// subscriber resynchronize, once the replica listens again.
func TestALostSessionResynchronizes(t *testing.T) {
	d := dbtest.New(t)
	a := listen(t, d, "replica-a", PostgresOptions{})
	b := listen(t, d, "replica-b", PostgresOptions{})
	r := newRecorder()
	subscribe(t, b, "governance", r)
	r.expect(t, "resync")

	if n := d.Terminate(t, "replica-b notify"); n != 1 {
		t.Fatalf("ended %d sessions, want 1", n)
	}
	r.expect(t, "resync")
	a.publish(t, "governance", "44", true)
	r.expect(t, "44")
	if got := b.metric(t, "whitetower_notify_resyncs_total", "reason", "listening"); got != 2 {
		t.Errorf("%v resynchronizations counted, want 2", got)
	}
	if got := b.metric(t, "whitetower_notify_listener_connected", "", ""); got != 1 {
		t.Errorf("listener_connected %v", got)
	}
}

// A subscription that comes later, on a channel nobody listened to, takes
// effect at once; one that ends receives nothing more.
func TestSubscriptionsComeAndGo(t *testing.T) {
	d := dbtest.New(t)
	a := listen(t, d, "replica-a", PostgresOptions{})
	b := listen(t, d, "replica-b", PostgresOptions{})
	first := newRecorder()
	subscribe(t, b, "governance", first)
	first.expect(t, "resync")

	later := newRecorder()
	cancel := subscribe(t, b, "policy", later)
	later.expect(t, "resync")
	a.publish(t, "policy", "7", true)
	later.expect(t, "7")
	first.quiet(t)

	cancel()
	a.publish(t, "policy", "8", true)
	a.publish(t, "governance", "9", true)
	first.expect(t, "9")
	later.quiet(t)
}

// The listener checks in on time even while notifications keep coming: the
// database counts a session that receives but runs nothing as idle.
func TestABusyChannelDoesNotLookIdle(t *testing.T) {
	d := dbtest.New(t)
	a := listen(t, d, "replica-a", PostgresOptions{})
	b := listen(t, d, "replica-b", PostgresOptions{CheckInterval: 200 * time.Millisecond, IdleTimeout: time.Second})
	r := newRecorder()
	subscribe(t, b, "governance", r)
	r.expect(t, "resync")
	for i := 0; i < 60; i++ {
		a.publish(t, "governance", strconv.Itoa(i), true)
		r.expect(t, strconv.Itoa(i))
		time.Sleep(50 * time.Millisecond)
	}
	if got := b.metric(t, "whitetower_notify_resyncs_total", "reason", "listening"); got != 1 {
		t.Errorf("the session was lost: %v resynchronizations", got)
	}
}

func TestPublishChecksItsInput(t *testing.T) {
	b := NewPostgres(PostgresOptions{})
	for _, tt := range []struct{ channel, payload, want string }{
		{"Governance", "1", "invalid channel"},
		{"governance", strings.Repeat("x", MaxPayload+1), "exceeds"},
		{"governance", "a\x00b", "without NUL"},
	} {
		// The input is refused before the transaction is used.
		if err := b.Publish(context.Background(), nil, tt.channel, tt.payload); err == nil ||
			!strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: got %v, want %q", tt.channel, err, tt.want)
		}
	}
	if _, err := b.Subscribe("has-hyphen", newRecorder()); err == nil {
		t.Error("subscribed to an invalid channel")
	}
}
