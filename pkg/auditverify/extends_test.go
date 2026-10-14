package auditverify_test

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

// A log extends the checkpoints it signed, and a log rolled back, or
// rewritten and signed again, does not extend those kept outside it.
func TestExtends(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name   string
		change func(*testing.T, *memLog)
		want   error
	}{
		{"untouched", func(*testing.T, *memLog) {}, nil},
		{"grown", func(t *testing.T, m *memLog) {
			events := make([][]byte, 60)
			for i := range int64(60) {
				events[i] = event(i)
			}
			m.build(t, newSigner(t), events, 10)
		}, nil},
		{"rolled back", func(_ *testing.T, m *memLog) {
			for i := int64(25); i < 40; i++ {
				delete(m.leaves, i)
			}
			m.checkpoints = m.checkpoints[:2]
		}, auditverify.ErrShorter},
		{"rewritten and signed again", func(t *testing.T, m *memLog) {
			events := make([][]byte, 40)
			for i := range int64(40) {
				events[i] = m.leaves[i].event
			}
			events[3] = event(99)
			m.build(t, newSigner(t), events, 10)
		}, auditverify.ErrForked},
		{"a tree hash removed", func(_ *testing.T, m *memLog) {
			delete(m.hashes, tlog.StoredHashIndex(5, 0))
		}, auditverify.ErrForked},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigner(t)
			m := newLog(t, s, 40, 10)
			kept := m.opened(t, s.keys(t), 40)
			tt.change(t, m)
			if err := auditverify.Extends(ctx, m, kept); !errors.Is(err, tt.want) || (tt.want == nil) != (err == nil) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

// A source that fails is not taken for a log that was changed.
func TestExtendsReturnsTheSourcesErrors(t *testing.T) {
	s := newSigner(t)
	m := newLog(t, s, 20, 10)
	kept := m.opened(t, s.keys(t), 20)
	m.err = errors.New("the database is down")
	err := auditverify.Extends(context.Background(), m, kept)
	if !errors.Is(err, m.err) || errors.Is(err, auditverify.ErrForked) || errors.Is(err, auditverify.ErrShorter) {
		t.Fatal(err)
	}
}
