package clocktest

import (
	"testing"
	"time"
)

var epoch = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func fired(c <-chan time.Time) (time.Time, bool) {
	select {
	case at := <-c:
		return at, true
	default:
		return time.Time{}, false
	}
}

func TestTimersFireWhenTheTimeReachesThem(t *testing.T) {
	f := New(epoch)
	late, early := f.NewTimer(2*time.Minute), f.NewTimer(time.Minute)
	f.Advance(59 * time.Second)
	if _, ok := fired(early.C()); ok {
		t.Fatal("fired early")
	}
	f.Advance(time.Second)
	if at, ok := fired(early.C()); !ok || !at.Equal(epoch.Add(time.Minute)) {
		t.Fatalf("fired %v at %v, want at %v", ok, at, epoch.Add(time.Minute))
	}
	if _, ok := fired(late.C()); ok {
		t.Fatal("the later timer fired too")
	}
	f.Advance(time.Hour)
	if at, ok := fired(late.C()); !ok || !at.Equal(epoch.Add(2*time.Minute)) {
		t.Fatalf("fired %v at %v", ok, at)
	}
	if !f.Now().Equal(epoch.Add(time.Hour + time.Minute)) {
		t.Fatalf("now %v", f.Now())
	}
}

func TestStoppedTimersDoNotFire(t *testing.T) {
	f := New(epoch)
	timer := f.NewTimer(time.Minute)
	if !timer.Stop() || timer.Stop() {
		t.Fatal("Stop should report true once, then false")
	}
	f.Advance(time.Hour)
	if _, ok := fired(timer.C()); ok {
		t.Fatal("a stopped timer fired")
	}
	now := f.NewTimer(0)
	if at, ok := fired(now.C()); !ok || !at.Equal(f.Now()) || now.Stop() {
		t.Fatal("a timer for no time should fire at once, and have nothing to stop")
	}
}

func TestWaitTimersWaitsForGoroutines(t *testing.T) {
	f := New(epoch)
	woke := make(chan time.Time)
	go func() { woke <- <-f.NewTimer(time.Second).C() }()
	f.WaitTimers(t, 1)
	f.Advance(time.Second)
	if at := <-woke; !at.Equal(epoch.Add(time.Second)) {
		t.Fatalf("woke at %v", at)
	}
}
