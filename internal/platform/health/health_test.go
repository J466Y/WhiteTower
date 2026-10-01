package health_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/health"
)

func TestFailing(t *testing.T) {
	var buf bytes.Buffer
	r := health.NewReadiness(slog.New(slog.NewJSONHandler(&buf, nil)))
	if got := r.Failing(context.Background()); len(got) != 0 {
		t.Fatalf("no check: failing %v", got)
	}

	var databaseDown atomic.Bool
	databaseDown.Store(true)
	r.Add("database", func(context.Context) error {
		if databaseDown.Load() {
			return errors.New("connection refused")
		}
		return nil
	})
	r.Add("signing keys", func(context.Context) error { return nil })
	r.Add("migrations", func(ctx context.Context) error {
		<-ctx.Done() // too slow: the timeout fails it
		return ctx.Err()
	})

	start := time.Now()
	if got := r.Failing(context.Background()); !slices.Equal(got, []string{"database", "migrations"}) {
		t.Fatalf("failing %v", got)
	}
	if took := time.Since(start); took > health.CheckTimeout+time.Second {
		t.Fatalf("checks took %s: they must run at once, each within %s", took, health.CheckTimeout)
	}

	// A failure is logged when it starts, not on every probe.
	_ = r.Failing(context.Background())
	if n := strings.Count(buf.String(), `"check":"database"`); n != 1 {
		t.Fatalf("the database failure was logged %d times, want once:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "connection refused") {
		t.Fatalf("the log lacks the error:\n%s", buf.String())
	}

	databaseDown.Store(false)
	if got := r.Failing(context.Background()); !slices.Equal(got, []string{"migrations"}) {
		t.Fatalf("failing %v", got)
	}
	if !strings.Contains(buf.String(), "readiness check passing again") {
		t.Fatalf("the recovery was not logged:\n%s", buf.String())
	}
}
