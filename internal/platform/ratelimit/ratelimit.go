// Package ratelimit limits how fast each client may call the core, with a
// token bucket per key, such as a principal or a client address, so that one
// client flooding the API cannot make it unusable for the others (threat
// model, T-11).
package ratelimit

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// MaxKeys bounds the memory a flood of distinct keys can take: beyond it, new
// keys share one bucket until idle ones are dropped.
const MaxKeys = 100_000

// sweepEvery is how often idle buckets are dropped; a bucket idle that long
// has refilled, and is no different from a new one.
const sweepEvery = time.Minute

const overflow = "overflow"

// Limiter applies one token bucket per key.
type Limiter struct {
	limit rate.Limit
	burst int

	mu      sync.Mutex
	buckets map[string]*bucket
	swept   time.Time
}

type bucket struct {
	limiter *rate.Limiter
	used    time.Time
}

// New returns a limiter that allows each key perSecond requests per second
// on average, and burst at once.
func New(perSecond float64, burst int) *Limiter {
	return &Limiter{limit: rate.Limit(perSecond), burst: burst, buckets: map[string]*bucket{}}
}

// Allow takes a token from the key's bucket at now. When there is none, it
// returns false and how long until one is free.
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	if now.Sub(l.swept) >= sweepEvery {
		for k, b := range l.buckets {
			if now.Sub(b.used) >= sweepEvery {
				delete(l.buckets, k)
			}
		}
		l.swept = now
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= MaxKeys {
			key = overflow
			b = l.buckets[key]
		}
		if b == nil {
			b = &bucket{limiter: rate.NewLimiter(l.limit, l.burst)}
			l.buckets[key] = b
		}
	}
	b.used = now
	l.mu.Unlock()

	r := b.limiter.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Second
	}
	if wait := r.DelayFrom(now); wait > 0 {
		r.CancelAt(now)
		return false, wait
	}
	return true, 0
}

// AddressKey returns the key of a client address: the address itself for
// IPv4, and its /64 network for IPv6, where one client often holds a whole
// /64 and could otherwise get a bucket per address.
func AddressKey(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}
