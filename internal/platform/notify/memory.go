package notify

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/J466Y/WhiteTower/internal/platform/db"
)

// Memory is a bus within one process, for unit tests. Publish delivers once
// the transaction commits, as PostgreSQL does; Send delivers at once, as if
// another replica had committed; and Interrupt plays a lost session, after
// which every subscriber resynchronizes.
type Memory struct {
	mu   sync.Mutex
	subs subscriptions
}

var _ Bus = (*Memory)(nil)

// NewMemory returns an empty bus.
func NewMemory() *Memory { return &Memory{subs: subscriptions{}} }

// Publish implements Bus.
func (m *Memory) Publish(_ context.Context, tx *db.Tx, channel, payload string) error {
	if err := errors.Join(checkChannel(channel), checkPayload(payload)); err != nil {
		return err
	}
	tx.AfterCommit(func(context.Context) { m.Send(channel, payload) })
	return nil
}

// Subscribe implements Bus. The subscriber is told to resynchronize at once.
func (m *Memory) Subscribe(channel string, s Subscriber) (func(), error) {
	if err := checkChannel(channel); err != nil {
		return nil, err
	}
	sub := newSubscription(channel, s, slog.Default(), nil)
	m.mu.Lock()
	m.subs.add(sub)
	sub.resynchronize(reasonListening)
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			m.subs.remove(sub)
			m.mu.Unlock()
			sub.stop()
		})
	}, nil
}

// Send delivers a notification at once.
func (m *Memory) Send(channel, payload string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for sub := range m.subs[channel] {
		sub.push(payload)
	}
}

// Interrupt tells every subscriber to resynchronize, as after a lost session.
func (m *Memory) Interrupt() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, subs := range m.subs {
		for sub := range subs {
			sub.resynchronize(reasonListening)
		}
	}
}
