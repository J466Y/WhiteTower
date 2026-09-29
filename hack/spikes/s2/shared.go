package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/metrics"
	"slices"
	"time"
)

// procStats is what every process reports about itself.
type procStats struct {
	Streams    int64   `json:"streams"`
	HeapLive   uint64  `json:"heap_live_bytes"`
	MemTotal   uint64  `json:"memory_total_bytes"`
	Goroutines uint64  `json:"goroutines"`
	CPUSeconds float64 `json:"cpu_seconds"`
}

func readProcStats() procStats {
	samples := []metrics.Sample{
		{Name: "/gc/heap/live:bytes"},
		{Name: "/memory/classes/total:bytes"},
		{Name: "/sched/goroutines:goroutines"},
	}
	metrics.Read(samples)
	return procStats{
		HeapLive:   samples[0].Value.Uint64(),
		MemTotal:   samples[1].Value.Uint64(),
		Goroutines: samples[2].Value.Uint64(),
		CPUSeconds: processCPU().Seconds(),
	}
}

// summary is a latency distribution in milliseconds.
type summary struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

func summarize(ds []time.Duration) summary {
	if len(ds) == 0 {
		return summary{}
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	at := func(q float64) float64 {
		i := int(q*float64(len(s))+0.5) - 1
		i = max(0, min(i, len(s)-1))
		return float64(s[i].Microseconds()) / 1000
	}
	return summary{N: len(s), P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: float64(s[len(s)-1].Microseconds()) / 1000}
}

func (s summary) String() string {
	return fmt.Sprintf("%d | %.0f | %.0f | %.0f | %.0f", s.N, s.P50, s.P95, s.P99, s.Max)
}

// newUUID returns a random UUID (version 4).
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// call sends a request to an admin endpoint and decodes its JSON answer.
func call(ctx context.Context, method, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, bytes.TrimSpace(body))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
