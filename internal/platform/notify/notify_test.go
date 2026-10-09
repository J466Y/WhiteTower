package notify

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a subscriber that reports what it receives.
type recorder struct {
	events chan string
}

func newRecorder() *recorder { return &recorder{events: make(chan string, 4*maxPending)} }

func (r *recorder) Receive(payload string) { r.events <- payload }

func (r *recorder) Resync() { r.events <- "resync" }

// next waits for the subscriber's next event.
func (r *recorder) next(t *testing.T) string {
	t.Helper()
	select {
	case e := <-r.events:
		return e
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
		return ""
	}
}

// expect waits for the subscriber's next events.
func (r *recorder) expect(t *testing.T, want ...string) {
	t.Helper()
	for _, w := range want {
		if got := r.next(t); got != w {
			t.Fatalf("got %q, want %q", got, w)
		}
	}
}

func (r *recorder) quiet(t *testing.T) {
	t.Helper()
	select {
	case e := <-r.events:
		t.Fatalf("unexpected %q", e)
	case <-time.After(20 * time.Millisecond):
	}
}

func subscribe(t *testing.T, b Bus, channel string, s Subscriber) func() {
	t.Helper()
	cancel, err := b.Subscribe(channel, s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	return cancel
}

func TestSubscribersResyncThenReceiveInOrder(t *testing.T) {
	m := NewMemory()
	r := newRecorder()
	subscribe(t, m, "governance", r)
	r.expect(t, "resync")
	for i := range 5 {
		m.Send("governance", strconv.Itoa(i))
	}
	m.Send("other", "not for this subscriber")
	r.expect(t, "0", "1", "2", "3", "4")
	m.Interrupt()
	m.Send("governance", "5")
	r.expect(t, "resync", "5")
	r.quiet(t)
}

// held is a subscriber whose first Receive waits until release is closed.
type held struct {
	*recorder
	entered, release chan struct{}
	once             sync.Once
}

func (h *held) Receive(payload string) {
	h.once.Do(func() {
		close(h.entered)
		<-h.release
	})
	h.recorder.Receive(payload)
}

// A subscriber that falls behind is told to resynchronize instead of being
// kept waiting, and holds up no other subscriber.
func TestASlowSubscriberResynchronizes(t *testing.T) {
	m := NewMemory()
	slow := &held{recorder: newRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	fast := newRecorder()
	subscribe(t, m, "governance", slow)
	subscribe(t, m, "governance", fast)
	slow.expect(t, "resync")
	fast.expect(t, "resync")

	m.Send("governance", "first")
	<-slow.entered // the slow subscriber is held, taking the first notification
	fast.expect(t, "first")
	for i := range maxPending + 1 {
		m.Send("governance", strconv.Itoa(i))
		fast.expect(t, strconv.Itoa(i))
	}
	m.Send("governance", "last")
	fast.expect(t, "last")

	// The slow subscriber missed too many: it resynchronizes, then gets what
	// came after.
	close(slow.release)
	slow.expect(t, "first", "resync", "last")
	slow.quiet(t)
}

type panicky struct{ resyncs chan struct{} }

func (panicky) Receive(string) { panic("the hub has a bug") }

func (p panicky) Resync() { p.resyncs <- struct{}{} }

func TestAPanickingSubscriberKeepsItsSubscription(t *testing.T) {
	m := NewMemory()
	p := panicky{resyncs: make(chan struct{}, 2)}
	subscribe(t, m, "governance", p)
	<-p.resyncs
	m.Send("governance", "1")
	m.Interrupt()
	select {
	case <-p.resyncs:
	case <-time.After(10 * time.Second):
		t.Fatal("the subscription stopped after a panic")
	}
}

func TestCancelStopsDelivery(t *testing.T) {
	m := NewMemory()
	r := newRecorder()
	cancel := subscribe(t, m, "governance", r)
	r.expect(t, "resync")
	cancel()
	cancel() // a second call does nothing
	m.Send("governance", "1")
	m.Interrupt()
	r.quiet(t)
}

func TestChannelsAndPayloadsAreChecked(t *testing.T) {
	m := NewMemory()
	for _, channel := range []string{"", "Governance", "1st", "has-hyphen", "has.dot", strings.Repeat("a", 41)} {
		if _, err := m.Subscribe(channel, newRecorder()); err == nil {
			t.Errorf("subscribed to %q", channel)
		}
		if err := checkChannel(channel); err == nil {
			t.Errorf("%q passed", channel)
		}
	}
	for _, payload := range []string{strings.Repeat("x", MaxPayload+1), "a\x00b", "\xff"} {
		if err := checkPayload(payload); err == nil {
			t.Errorf("%q passed", payload)
		}
	}
	if err := checkPayload(strings.Repeat("x", MaxPayload)); err != nil {
		t.Error(err)
	}
}

// Many goroutines may publish and subscribe at once.
func TestTheMemoryBusIsSafeForConcurrentUse(t *testing.T) {
	m := NewMemory()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			r := newRecorder()
			cancel, err := m.Subscribe("governance", r)
			if err != nil {
				t.Error(err)
				return
			}
			for j := range 20 {
				m.Send("governance", strconv.Itoa(i*100+j))
			}
			cancel()
		})
	}
	wg.Wait()
}
