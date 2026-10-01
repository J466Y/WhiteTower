// Package health holds the readiness checks behind /readyz. Each component
// that must work before the server takes traffic adds one: the database and
// its schema (plan P1-01, step 4), the signing keys.
package health

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// CheckTimeout bounds each check: Kubernetes gives a probe one second by
// default.
const CheckTimeout = time.Second

// Check returns an error when what it checks does not work.
type Check func(ctx context.Context) error

// Readiness runs the registered checks.
type Readiness struct {
	logger *slog.Logger

	mu     sync.Mutex
	checks []*check
}

type check struct {
	name string
	fn   Check

	mu      sync.Mutex
	failing bool
}

// NewReadiness returns a readiness with no check: ready.
func NewReadiness(logger *slog.Logger) *Readiness {
	return &Readiness{logger: logger}
}

// Add registers a check under a name, which /readyz shows when it fails.
func (r *Readiness) Add(name string, fn Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks = append(r.checks, &check{name: name, fn: fn})
}

// Failing runs every check at once, each within CheckTimeout, and returns
// the names of those that fail, in the order they were added. A check that
// starts or stops failing is logged, its error included; /readyz shows only
// the names.
func (r *Readiness) Failing(ctx context.Context) []string {
	r.mu.Lock()
	checks := slices.Clone(r.checks)
	r.mu.Unlock()

	failed := make([]bool, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
			defer cancel()
			err := c.fn(ctx)
			failed[i] = err != nil
			r.record(ctx, c, err)
		})
	}
	wg.Wait()

	var names []string
	for i, c := range checks {
		if failed[i] {
			names = append(names, c.name)
		}
	}
	return names
}

func (r *Readiness) record(ctx context.Context, c *check, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err != nil && !c.failing:
		r.logger.WarnContext(ctx, "readiness check failing", "check", c.name, "error", err.Error())
	case err == nil && c.failing:
		r.logger.InfoContext(ctx, "readiness check passing again", "check", c.name)
	}
	c.failing = err != nil
}
