package kit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/test/conformance/bundle"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
)

// Fixture is what a scenario needs: the agent the module serves, a bundle for
// it, and a request the bundle permits.
type Fixture struct {
	Agent     *modulev1alpha1.AgentState
	Bundle    *bundle.Bundle
	Ref       bundle.Ref
	Permitted DecideRequest
}

// poll is how often scenarios look at the module under test.
const poll = 20 * time.Millisecond

// StartClosed is scenario S-01, for obligation EP-1: the module allows nothing
// until it has registered, received a complete state and a lease, and
// activated a verified bundle; then it allows what the bundle permits, and
// acknowledges the activation.
func StartClosed(ctx context.Context, core *Core, driver *Driver, fx Fixture) error {
	if err := waitFor(ctx, func() bool { return core.Watchers() > 0 }); err != nil {
		return fmt.Errorf("the module never opened a watch: %w", err)
	}

	// 1. Connected, but no state yet.
	if err := expectFor(ctx, driver, fx.Permitted, 200*time.Millisecond, profile.ReasonNoState); err != nil {
		return fmt.Errorf("before any state: %w", err)
	}

	// 2. State and a lease, but no bundle.
	agent := fx.Agent
	agent.Bundle = nil
	core.SetAgent(agent)
	core.Release()
	if err := eventually(ctx, driver, fx.Permitted, false, profile.ReasonNoBundle); err != nil {
		return fmt.Errorf("with state but no bundle: %w", err)
	}

	// 3. A verified bundle: the permitted request is allowed.
	if err := core.PublishBundle(agent.GetAgentId(), fx.Bundle, fx.Ref); err != nil {
		return err
	}
	if err := eventually(ctx, driver, fx.Permitted, true, profile.ReasonPermit); err != nil {
		return fmt.Errorf("with a verified bundle: %w", err)
	}

	// 4. The activation was acknowledged.
	return waitFor(ctx, func() bool {
		return slices.ContainsFunc(core.Acks(), func(a *modulev1alpha1.Acknowledgement) bool {
			b := a.GetBundle()
			return b != nil && b.GetVersion() == fx.Ref.Version && b.GetManifestSha256() == fx.Ref.ManifestSHA256 &&
				b.GetOutcome() == modulev1alpha1.BundleOutcome_BUNDLE_OUTCOME_ACTIVATED
		})
	})
}

// staleBy is how old the stale renewals of scenario S-17 claim to be: far
// beyond the contract's default tolerance of 5 seconds.
const staleBy = time.Minute

// StaleRenewals is scenario S-17, for obligation EP-3 and section 5.3: a lease
// renewal older than the tolerance, or without the core's time, renews
// nothing, so a stream held back on its way cannot keep a lease alive. The
// lease runs out within its TTL, and a fresh renewal renews it again. The
// fixture's lease TTL sets how long the scenario takes.
func StaleRenewals(ctx context.Context, core *Core, driver *Driver, fx Fixture) error {
	if err := waitFor(ctx, func() bool { return core.Watchers() > 0 }); err != nil {
		return fmt.Errorf("the module never opened a watch: %w", err)
	}
	ttl := fx.Agent.GetLeaseTtl().AsDuration()

	// 1. Governed, as at the end of S-01.
	core.SetAgent(fx.Agent)
	core.Release()
	if err := core.PublishBundle(fx.Agent.GetAgentId(), fx.Bundle, fx.Ref); err != nil {
		return err
	}
	if err := eventually(ctx, driver, fx.Permitted, true, profile.ReasonPermit); err != nil {
		return fmt.Errorf("before the stale renewals: %w", err)
	}

	// 2. A last fresh renewal, then only stale ones at the usual pace: some a
	// minute old, some without the core's time.
	core.RenewLeases()
	lastFresh := time.Now()
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(ttl / 3)
		defer tick.Stop()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if i%2 == 0 {
				core.RenewLeasesAt(timestamppb.New(time.Now().Add(-staleBy)))
			} else {
				core.RenewLeasesAt(nil)
			}
		}
	}()
	// 3. The lease runs out within its TTL, whatever the stale renewals say.
	err := leaseRunsOut(ctx, driver, fx.Permitted, lastFresh.Add(ttl+time.Second))
	close(stop)
	<-stopped
	if err != nil {
		return err
	}

	// 4. A renewal one second old is fresh, and renews the lease again.
	core.RenewLeasesAt(timestamppb.New(time.Now().Add(-time.Second)))
	if err := eventually(ctx, driver, fx.Permitted, true, profile.ReasonPermit); err != nil {
		return fmt.Errorf("after a fresh renewal: %w", err)
	}
	return nil
}

// leaseRunsOut is step 3 of S-17: the gate closes because the lease expired,
// no later than the deadline, and for no other reason.
func leaseRunsOut(ctx context.Context, driver *Driver, req DecideRequest, deadline time.Time) error {
	for {
		got, err := driver.Decide(ctx, req)
		if err != nil {
			return err
		}
		switch {
		case !got.Decision && got.Context.Reason == profile.ReasonLeaseExpired:
			return nil
		case !got.Decision:
			return fmt.Errorf("denied with reason %s while stale renewals arrived, want %s", got.Context.Reason, profile.ReasonLeaseExpired)
		case time.Now().After(deadline):
			return errors.New("still allowed after its lease should have run out: a stale renewal renewed it")
		}
		if err := sleep(ctx); err != nil {
			return err
		}
	}
}

// expectFor requires the same denial for the whole duration.
func expectFor(ctx context.Context, driver *Driver, req DecideRequest, d time.Duration, reason string) error {
	deadline := time.Now().Add(d)
	for {
		got, err := driver.Decide(ctx, req)
		if err != nil {
			return err
		}
		if got.Decision || got.Context.Reason != reason {
			return fmt.Errorf("got decision %v with reason %s, want a denial with reason %s", got.Decision, got.Context.Reason, reason)
		}
		if time.Now().After(deadline) {
			return nil
		}
		if err := sleep(ctx); err != nil {
			return err
		}
	}
}

// eventually waits for a decision. While it waits, the module must not allow
// anything the scenario does not expect it to allow.
func eventually(ctx context.Context, driver *Driver, req DecideRequest, decision bool, reason string) error {
	for {
		got, err := driver.Decide(ctx, req)
		if err != nil {
			return err
		}
		if got.Decision == decision && got.Context.Reason == reason {
			return nil
		}
		if got.Decision && !decision {
			return fmt.Errorf("allowed (reason %s) while it must deny", got.Context.Reason)
		}
		if err := sleep(ctx); err != nil {
			return fmt.Errorf("last decision %v with reason %s, want %v with reason %s: %w",
				got.Decision, got.Context.Reason, decision, reason, err)
		}
	}
}

func waitFor(ctx context.Context, cond func() bool) error {
	for !cond() {
		if err := sleep(ctx); err != nil {
			return err
		}
	}
	return nil
}

// sleep waits one poll interval, or until ctx ends.
func sleep(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return errors.Join(errors.New("timed out"), ctx.Err())
	case <-time.After(poll):
		return nil
	}
}
