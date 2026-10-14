package auditverify_test

import (
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

func TestCheckInclusion(t *testing.T) {
	s := newSigner(t)
	m := newLog(t, s, 37, 37)
	cp := m.opened(t, s.keys(t), 37)
	proof, err := tlog.ProveRecord(37, 5, m.reader())
	if err != nil {
		t.Fatal(err)
	}
	if err := auditverify.CheckInclusion(proof, cp, 5, event(5)); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() error{
		"another event":     func() error { return auditverify.CheckInclusion(proof, cp, 5, event(6)) },
		"another index":     func() error { return auditverify.CheckInclusion(proof, cp, 6, event(5)) },
		"beyond the tree":   func() error { return auditverify.CheckInclusion(proof, cp, 37, event(5)) },
		"a negative index":  func() error { return auditverify.CheckInclusion(proof, cp, -1, event(5)) },
		"a truncated proof": func() error { return auditverify.CheckInclusion(proof[1:], cp, 5, event(5)) },
	} {
		if check() == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

func TestCheckConsistency(t *testing.T) {
	s := newSigner(t)
	m := newLog(t, s, 37, 1)
	older, newer := m.opened(t, s.keys(t), 10), m.opened(t, s.keys(t), 37)
	proof, err := tlog.ProveTree(37, 10, m.reader())
	if err != nil {
		t.Fatal(err)
	}
	if err := auditverify.CheckConsistency(proof, older, newer); err != nil {
		t.Fatal(err)
	}
	same, err := tlog.ProveTree(37, 37, m.reader())
	if err != nil {
		t.Fatal(err)
	}
	if err := auditverify.CheckConsistency(same, newer, newer); err != nil {
		t.Fatalf("a checkpoint and itself: %v", err)
	}

	// The first 10 events of the log, with the fourth changed.
	events := make([][]byte, 10)
	for i := range int64(10) {
		events[i] = event(i)
	}
	events[3] = event(99)
	forked := &memLog{}
	forked.build(t, s, events, 10)
	other := forked.opened(t, s.keys(t), 10)
	otherLog := newer
	otherLog.Origin = "whitetower.test/other"
	for name, check := range map[string]func() error{
		"a fork":            func() error { return auditverify.CheckConsistency(proof, other, newer) },
		"swapped":           func() error { return auditverify.CheckConsistency(proof, newer, older) },
		"another log":       func() error { return auditverify.CheckConsistency(proof, older, otherLog) },
		"a truncated proof": func() error { return auditverify.CheckConsistency(proof[1:], older, newer) },
	} {
		if check() == nil {
			t.Errorf("%s: consistent", name)
		}
	}
}
