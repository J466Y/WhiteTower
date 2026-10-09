// Package notify tells the replicas of the core about the changes that one of
// them commits (plan P1-01, step 8; ADR-0003). A notification is a hint, not
// the change: its payload carries identifiers and versions only, and each
// replica re-reads what changed from the database. PostgreSQL keeps no
// notification for a listener that is away, so subscribers are also told to
// re-read everything they follow whenever they may have missed some.
//
// Notifications are cheap to receive but not to send in numbers: a
// transaction that notifies takes a database-wide lock as it commits, so such
// transactions commit one at a time. Notify once per transaction, with the
// version that sums up the change: a halt of the whole fleet is one
// notification, whatever the number of agents. Never notify per row, nor
// from a busy flow such as the audit events.
//
// Any role that connects to the database may listen and notify on any
// channel: a notification is a reason to re-read, never data to trust.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/J466Y/WhiteTower/internal/platform/db"
	"github.com/J466Y/WhiteTower/internal/platform/logging"
)

// MaxPayload bounds the payload of a notification. Identifiers and versions
// fit in far less; PostgreSQL refuses 8,000 bytes.
const MaxPayload = 1024

// Bus carries notifications across the replicas.
type Bus interface {
	// Publish sends payload on channel if, and once, tx commits: never for a
	// change that rolls back, and in the order the transactions commit.
	Publish(ctx context.Context, tx *db.Tx, channel, payload string) error
	// Subscribe passes the notifications of channel to s, until the
	// returned function cancels the subscription. That function waits for
	// s's methods to return, so they must not call it.
	Subscribe(channel string, s Subscriber) (cancel func(), err error)
}

// Subscriber receives the notifications of a channel. Its methods run one at
// a time, in order, on a goroutine of their own, so that a slow subscriber
// holds up no one else. A subscriber that falls far behind is told to
// resynchronize instead of being kept waiting.
type Subscriber interface {
	// Receive gets the payload of a notification.
	Receive(payload string)
	// Resync tells the subscriber that it may have missed notifications:
	// once the bus listens for it, again whenever the bus reconnects, and
	// when it falls behind. Every notification after a Resync reaches
	// Receive, until the next Resync. The subscriber re-reads what it
	// follows.
	Resync()
}

// Reasons to resynchronize.
const (
	// reasonListening: the bus started listening for the subscriber, when
	// it subscribed or when the bus reconnected.
	reasonListening = "listening"
	// reasonOverflow: the subscriber fell behind.
	reasonOverflow = "overflow"
)

var channelPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

func checkChannel(channel string) error {
	if !channelPattern.MatchString(channel) {
		return fmt.Errorf("notify: invalid channel %q: up to 40 lowercase letters, digits and underscores, "+
			"starting with a letter", channel)
	}
	return nil
}

func checkPayload(payload string) error {
	switch {
	case len(payload) > MaxPayload:
		return fmt.Errorf("notify: a %d-byte payload exceeds %d bytes: carry identifiers and versions only",
			len(payload), MaxPayload)
	case !utf8.ValidString(payload) || strings.ContainsRune(payload, 0):
		return errors.New("notify: the payload must be UTF-8 text without NUL")
	}
	return nil
}

// maxPending bounds the notifications that wait for a subscriber; past it,
// the subscriber is told to resynchronize instead.
const maxPending = 256

// subscription delivers notifications to a subscriber, on a goroutine of its
// own.
type subscription struct {
	channel  string
	s        Subscriber
	logger   *slog.Logger
	resynced func(reason string) // counts resynchronizations; may be nil

	mu      sync.Mutex
	pending []string
	resync  string // the reason of a pending resynchronization, or ""
	wake    chan struct{}
	quit    chan struct{}
	done    chan struct{}

	// covered belongs to the bus, under its lock: whether the subscriber
	// was told to resynchronize since the bus last started listening.
	covered bool
}

func newSubscription(channel string, s Subscriber, logger *slog.Logger, resynced func(string)) *subscription {
	sub := &subscription{
		channel: channel, s: s, logger: logger, resynced: resynced,
		wake: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{}),
	}
	go sub.deliver()
	return sub
}

// push queues a payload; to a subscriber too far behind, it sends a
// resynchronization instead.
func (sub *subscription) push(payload string) {
	sub.mu.Lock()
	if len(sub.pending) < maxPending {
		sub.pending = append(sub.pending, payload)
	} else {
		sub.pending, sub.resync = nil, reasonOverflow
	}
	sub.mu.Unlock()
	sub.signal()
}

// resynchronize tells the subscriber to re-read what it follows, which makes
// the notifications that wait for it moot.
func (sub *subscription) resynchronize(reason string) {
	sub.mu.Lock()
	sub.pending, sub.resync = nil, reason
	sub.mu.Unlock()
	sub.signal()
}

func (sub *subscription) signal() {
	select {
	case sub.wake <- struct{}{}:
	default:
	}
}

func (sub *subscription) deliver() {
	defer close(sub.done)
	for {
		select {
		case <-sub.quit:
			return
		case <-sub.wake:
		}
		for {
			sub.mu.Lock()
			reason, pending := sub.resync, sub.pending
			sub.resync, sub.pending = "", nil
			sub.mu.Unlock()
			if reason == "" && len(pending) == 0 {
				break
			}
			if reason != "" {
				if sub.resynced != nil {
					sub.resynced(reason)
				}
				sub.call(sub.s.Resync)
			}
			for _, p := range pending {
				select {
				case <-sub.quit:
					return
				default:
				}
				sub.call(func() { sub.s.Receive(p) })
			}
		}
	}
}

// call runs a method of the subscriber. A panic is logged with its stack, and
// delivery goes on.
func (sub *subscription) call(method func()) {
	defer func() {
		if p := recover(); p != nil {
			sub.logger.Error("panic in a notification subscriber", "channel", sub.channel,
				"panic", logging.Sanitize(fmt.Sprint(p)), "stack", string(debug.Stack()))
		}
	}()
	method()
}

// stop ends the delivery, once the method running, if any, has returned.
func (sub *subscription) stop() {
	close(sub.quit)
	<-sub.done
}

// subscriptions are the subscriptions of a bus, by channel.
type subscriptions map[string]map[*subscription]struct{}

func (ss subscriptions) add(sub *subscription) {
	if ss[sub.channel] == nil {
		ss[sub.channel] = map[*subscription]struct{}{}
	}
	ss[sub.channel][sub] = struct{}{}
}

func (ss subscriptions) remove(sub *subscription) {
	delete(ss[sub.channel], sub)
	if len(ss[sub.channel]) == 0 {
		delete(ss, sub.channel)
	}
}
