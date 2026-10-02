package ratelimit

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

func TestBurstThenRate(t *testing.T) {
	l := New(2, 3) // 2 per second, 3 at once
	for i := range 3 {
		if ok, _ := l.Allow("a", t0); !ok {
			t.Fatalf("request %d of the burst refused", i+1)
		}
	}
	ok, wait := l.Allow("a", t0)
	if ok || wait != 500*time.Millisecond {
		t.Fatalf("over the burst: allowed %v, wait %s, want refused and 500ms", ok, wait)
	}
	if ok, _ := l.Allow("b", t0); !ok {
		t.Fatal("another key shares the first key's bucket")
	}
	if ok, _ := l.Allow("a", t0.Add(500*time.Millisecond)); !ok {
		t.Fatal("no token after the wait")
	}
}

func TestIdleBucketsAreDropped(t *testing.T) {
	l := New(1, 1)
	l.Allow("a", t0)
	l.Allow("b", t0.Add(30*time.Second))
	l.Allow("c", t0.Add(sweepEvery+time.Second)) // sweeps: a is idle, b is not
	if _, ok := l.buckets["a"]; ok {
		t.Error("an idle bucket was kept")
	}
	if _, ok := l.buckets["b"]; !ok {
		t.Error("a bucket in use was dropped")
	}
}

func TestDistinctKeysCannotExhaustMemory(t *testing.T) {
	l := New(1000, 1000)
	for i := range MaxKeys + 500 {
		l.Allow(fmt.Sprint("key-", i), t0)
	}
	if n := len(l.buckets); n > MaxKeys+1 {
		t.Fatalf("%d buckets, want at most %d", n, MaxKeys+1)
	}
	if _, ok := l.buckets[overflow]; !ok {
		t.Fatal("keys beyond the bound do not share the overflow bucket")
	}
}

func TestAddressKey(t *testing.T) {
	for _, tt := range []struct{ addr, want string }{
		{"192.0.2.10", "192.0.2.10"},
		{"::ffff:192.0.2.10", "192.0.2.10"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::ffff", "2001:db8:1:2::/64"},
	} {
		if got := AddressKey(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("AddressKey(%s) = %s, want %s", tt.addr, got, tt.want)
		}
	}
}
