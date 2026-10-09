// Package clocktest gives tests a clock whose time moves only when they move
// it.
package clocktest

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/clock"
)

// Fake is a clock.Clock whose time moves only with Advance. Its timers fire
// when Advance moves the time past them, in the order they are due.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	pending []*timer
	// changed is closed, and replaced, whenever a timer is armed.
	changed chan struct{}
}

var _ clock.Clock = (*Fake)(nil)

// New returns a fake clock set to now.
func New(now time.Time) *Fake {
	return &Fake{now: now, changed: make(chan struct{})}
}

// Now implements clock.Clock.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// NewTimer implements clock.Clock. A timer for no time at all fires at once.
func (f *Fake) NewTimer(d time.Duration) clock.Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &timer{f: f, at: f.now.Add(d), c: make(chan time.Time, 1)}
	if d <= 0 {
		t.c <- f.now
		return t
	}
	f.pending = append(f.pending, t)
	close(f.changed)
	f.changed = make(chan struct{})
	return t
}

// Advance moves the time forward by d, and fires the timers that are then
// due.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	slices.SortStableFunc(f.pending, func(a, b *timer) int { return a.at.Compare(b.at) })
	for len(f.pending) > 0 && !f.pending[0].at.After(f.now) {
		f.pending[0].c <- f.pending[0].at
		f.pending = f.pending[1:]
	}
}

// WaitTimers waits until at least n timers are armed and have not fired: the
// goroutines under test have then reached the point where they wait. It
// fails the test after ten seconds.
func (f *Fake) WaitTimers(t testing.TB, n int) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		armed, changed := len(f.pending), f.changed
		f.mu.Unlock()
		if armed >= n {
			return
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("%d timers armed after ten seconds, want %d", armed, n)
		}
	}
}

type timer struct {
	f  *Fake
	at time.Time
	c  chan time.Time
}

func (t *timer) C() <-chan time.Time { return t.c }

func (t *timer) Stop() bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	i := slices.Index(t.f.pending, t)
	if i < 0 {
		return false
	}
	t.f.pending = slices.Delete(t.f.pending, i, i+1)
	return true
}
