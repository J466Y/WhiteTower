package stubep

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
	"github.com/J466Y/WhiteTower/test/conformance/kit"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
)

// These tests hand the stub the messages of a watch stream one by one, as its
// session does, so that they can send what the kit's fake core does not send
// yet: versions below the one applied, values out of range and malformed
// snapshots. The tests of refusals run the stub's session against the kit's
// fake core, wrapped so that it refuses registrations and ends watches with
// the codes it cannot send yet.

const agentID = "0192f1c2-7a3b-7c4d-8e5f-000000000001"

// TestTheVersionAppliedNeverGoesBack checks section 5.2: the stub ignores a
// change or a snapshot below the version it applied, so an older message
// never undoes a halt, and a fresh renewal raises that version but never
// lowers it.
func TestTheVersionAppliedNeverGoesBack(t *testing.T) {
	e := New(Config{AgentID: agentID})
	running, halted := agentState(durationpb.New(time.Minute)), haltedAgentState()

	feed(t, e, snapshot(5, halted), renewal(5, timestamppb.Now()))
	expectReason(t, e, profile.ReasonHalted)

	// A change and a snapshot below version 5 would release the agent: both
	// are ignored.
	feed(t, e, change(4, running), snapshot(3, running))
	expectReason(t, e, profile.ReasonHalted)
	expectApplied(t, e, 5)

	// A fresh renewal may pass versions that carried nothing for the stream.
	// A lower one, or a stale one, leaves the version as it is.
	feed(t, e, renewal(9, timestamppb.Now()))
	expectApplied(t, e, 9)
	feed(t, e, renewal(7, timestamppb.Now()), renewal(12, nil))
	expectApplied(t, e, 9)

	// A change above the version applied is applied, even when the agent's
	// state in it carries an older version of its own.
	older := agentState(durationpb.New(time.Minute))
	older.Version = 2
	feed(t, e, change(10, older))
	expectReason(t, e, profile.ReasonNoBundle)
	expectApplied(t, e, 10)

	// A snapshot at the version applied replaces the state.
	feed(t, e, snapshot(10, halted))
	expectReason(t, e, profile.ReasonHalted)
}

// TestARenewalBeforeAnySnapshotLeavesTheVersionApplied checks the stub's
// reading of CORE-6: a fresh renewal raises the version applied only once a
// complete snapshot has been applied. One that comes first leaves that
// version at 0, so the stub neither resumes past a snapshot it never applied
// nor ignores that snapshot when it arrives at a lower version.
func TestARenewalBeforeAnySnapshotLeavesTheVersionApplied(t *testing.T) {
	e := New(Config{AgentID: agentID})

	feed(t, e, renewal(9, timestamppb.Now()))
	expectApplied(t, e, 0)
	expectReason(t, e, profile.ReasonNoState)

	feed(t, e, snapshot(5, haltedAgentState()), renewal(5, timestamppb.Now()))
	expectApplied(t, e, 5)
	expectReason(t, e, profile.ReasonHalted)
}

// TestOnlyAFreshRenewalRenewsTheLease checks section 5.3: a renewal without
// the core's time, or whose time is more than the tolerance before or after
// the stub's clock, renews nothing. The tolerance is 5 seconds by default,
// and never more than 30, whatever the configuration says.
func TestOnlyAFreshRenewalRenewsTheLease(t *testing.T) {
	cases := []struct {
		name      string
		tolerance time.Duration
		// The renewal's time, from the stub's clock, unless it carries none.
		offset time.Duration
		noTime bool
		renews bool
	}{
		{name: "a second old", offset: -time.Second, renews: true},
		{name: "a second in the future", offset: time.Second, renews: true},
		{name: "older than the default tolerance", offset: -6 * time.Second},
		{name: "further in the future than the default tolerance", offset: 6 * time.Second},
		{name: "a minute old", offset: -time.Minute},
		{name: "a minute in the future", offset: time.Minute},
		{name: "without the core's time", noTime: true},
		{name: "within a configured tolerance", tolerance: 20 * time.Second, offset: 15 * time.Second, renews: true},
		{name: "older than the largest tolerance", tolerance: time.Minute, offset: -40 * time.Second},
		{name: "further in the future than the largest tolerance", tolerance: time.Minute, offset: 40 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(Config{AgentID: agentID, RenewalTolerance: tc.tolerance})
			var serverTime *timestamppb.Timestamp
			if !tc.noTime {
				serverTime = timestamppb.New(time.Now().Add(tc.offset))
			}
			feed(t, e, snapshot(1, agentState(durationpb.New(time.Minute))), renewal(1, serverTime))
			want := profile.ReasonLeaseExpired
			if tc.renews {
				want = profile.ReasonNoBundle
			}
			expectReason(t, e, want)
		})
	}
}

// TestTheStubBoundsTheLeaseTTL checks section 5.3: a lease TTL above 300
// seconds lasts 300, one under 10 seconds is applied as it is, and one that
// is zero, negative or absent renews nothing, so the lease in force runs on.
func TestTheStubBoundsTheLeaseTTL(t *testing.T) {
	cases := []struct {
		name string
		ttl  *durationpb.Duration
		// How long the lease lasts after the renewal; zero when the renewal
		// renews nothing.
		lasts time.Duration
	}{
		{name: "an hour", ttl: durationpb.New(time.Hour), lasts: 300 * time.Second},
		{name: "thirty seconds", ttl: durationpb.New(30 * time.Second), lasts: 30 * time.Second},
		{name: "two seconds", ttl: durationpb.New(2 * time.Second), lasts: 2 * time.Second},
		{name: "zero", ttl: durationpb.New(0)},
		{name: "negative", ttl: durationpb.New(-time.Minute)},
		{name: "absent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(Config{AgentID: agentID})
			feed(t, e, snapshot(1, agentState(durationpb.New(time.Minute))), renewal(1, timestamppb.Now()))
			inForce := leaseDeadline(e)

			before := time.Now()
			feed(t, e, change(2, agentState(tc.ttl)), renewal(2, timestamppb.Now()))
			after := time.Now()
			got := leaseDeadline(e)
			if tc.lasts == 0 {
				if !got.Equal(inForce) {
					t.Errorf("the renewal moved the lease's end by %v, want it unchanged", got.Sub(inForce))
				}
				expectReason(t, e, profile.ReasonNoBundle)
				return
			}
			if got.Before(before.Add(tc.lasts)) || got.After(after.Add(tc.lasts)) {
				t.Errorf("the lease lasts %v after the renewal, want %v", got.Sub(before), tc.lasts)
			}
		})
	}
}

// TestASnapshotWithoutTheFleetStateIsRefused checks section 5.2: a snapshot
// whose first part lacks the fleet state ends the stream, so that the stub
// reconnects, and leaves the state as it was. At start there is none, and the
// gate stays closed with gate.no_state.
func TestASnapshotWithoutTheFleetStateIsRefused(t *testing.T) {
	e := New(Config{AgentID: agentID})
	running, halted := agentState(durationpb.New(time.Minute)), haltedAgentState()

	malformed := snapshot(3, running)
	malformed.GetSnapshotPart().Fleet = nil
	if _, err := e.receive(t.Context(), malformed, nil); !errors.Is(err, errSnapshotWithoutFleet) {
		t.Fatalf("receive returned %v, want %v", err, errSnapshotWithoutFleet)
	}
	expectReason(t, e, profile.ReasonNoState)

	feed(t, e, snapshot(5, halted), renewal(5, timestamppb.Now()))
	malformed = snapshot(6, running)
	malformed.GetSnapshotPart().Fleet = nil
	if _, err := e.receive(t.Context(), malformed, nil); !errors.Is(err, errSnapshotWithoutFleet) {
		t.Fatalf("receive returned %v, want %v", err, errSnapshotWithoutFleet)
	}
	expectReason(t, e, profile.ReasonHalted)
	expectApplied(t, e, 5)
}

// TestTheStubDeactivatesItsBundleWhenTheStateNamesNone checks EP-7: a state
// that stops naming a bundle closes the gate with gate.no_bundle, and the
// deactivated bundle's version stays the floor of V6, so an older bundle is
// rejected while the same bundle, named again, is activated again. The kit's
// fake core serves the bundles of the bundle vectors and records the
// acknowledgements.
func TestTheStubDeactivatesItsBundleWhenTheStateNamesNone(t *testing.T) {
	vectors := os.DirFS("../vectors/bundles")
	keys, err := kit.LoadKeys(vectors)
	if err != nil {
		t.Fatal(err)
	}
	core := kit.NewCore(keys)
	core.SetAgent(agentState(durationpb.New(time.Minute)))
	refs := map[string]*modulev1alpha1.BundleRef{}
	for _, name := range []string{"valid", "older-version"} {
		b, ref, err := kit.LoadBundle(vectors, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := core.PublishBundle(agentID, b, ref); err != nil {
			t.Fatal(err)
		}
		refs[name] = &modulev1alpha1.BundleRef{Version: ref.Version, ManifestSha256: ref.ManifestSHA256, SizeBytes: ref.SizeBytes}
	}
	server := httptest.NewServer(core.Handler())
	t.Cleanup(server.Close)
	e := New(Config{AgentID: agentID, Trusted: keys, CoreURL: server.URL, HTTPClient: server.Client()})
	naming := func(ref *modulev1alpha1.BundleRef) *modulev1alpha1.AgentState {
		state := agentState(durationpb.New(time.Minute))
		state.Bundle = ref
		return state
	}

	feed(t, e, snapshot(1, naming(refs["valid"])), renewal(1, timestamppb.Now()))
	expectReason(t, e, profile.ReasonPermit)

	feed(t, e, change(2, naming(nil)))
	expectReason(t, e, profile.ReasonNoBundle)

	feed(t, e, change(3, naming(refs["older-version"])))
	expectReason(t, e, profile.ReasonNoBundle)
	if got, want := bundleAcks(core, refs["older-version"].GetVersion()), []bundleAck{{modulev1alpha1.BundleOutcome_BUNDLE_OUTCOME_REJECTED, "older_version"}}; !slices.Equal(got, want) {
		t.Errorf("acknowledged %v for the older bundle, want %v", got, want)
	}

	feed(t, e, change(4, naming(refs["valid"])))
	expectReason(t, e, profile.ReasonPermit)
	activated := bundleAck{modulev1alpha1.BundleOutcome_BUNDLE_OUTCOME_ACTIVATED, ""}
	if got, want := bundleAcks(core, refs["valid"].GetVersion()), []bundleAck{activated, activated}; !slices.Equal(got, want) {
		t.Errorf("acknowledged %v for the valid bundle, want %v", got, want)
	}
}

// TestAnAgentThatLeavesTheScopeLosesItsStateAndItsLease checks I-11: an agent
// that a change lists as removed, or that a snapshot does not carry, loses its
// state and its lease at once. The gate closes with gate.no_state, a renewal
// renews nothing while the agent is out, and once a change brings it back, the
// gate stays closed until the next fresh renewal.
func TestAnAgentThatLeavesTheScopeLosesItsStateAndItsLease(t *testing.T) {
	cases := []struct {
		name  string
		leave *modulev1alpha1.WatchResponse
	}{
		{name: "a change lists it as removed", leave: removal(2)},
		{name: "a snapshot does not carry it", leave: snapshot(2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(Config{AgentID: agentID})
			feed(t, e, snapshot(1, agentState(durationpb.New(time.Minute))), renewal(1, timestamppb.Now()))
			expectReason(t, e, profile.ReasonNoBundle)

			feed(t, e, tc.leave, renewal(2, timestamppb.Now()))
			expectReason(t, e, profile.ReasonNoState)

			feed(t, e, change(3, agentState(durationpb.New(time.Minute))))
			expectReason(t, e, profile.ReasonLeaseExpired)
			feed(t, e, renewal(3, timestamppb.Now()))
			expectReason(t, e, profile.ReasonNoBundle)
		})
	}
}

// TestARefusalEndsTheLeaseAtOnce checks section 4.6 through the stub's
// session, against the kit's fake core: PERMISSION_DENIED from Watch, on an
// established stream, and PERMISSION_DENIED or FAILED_PRECONDITION from
// RegisterInstance end the lease at once, while any other end of a watch or
// refusal of a registration leaves it running. Either way, the stub registers
// again with backoff until the core accepts it, and the renewal that follows
// renews its lease.
func TestARefusalEndsTheLeaseAtOnce(t *testing.T) {
	cases := []struct {
		name string
		// The code that ends the established watch, and the one that refuses
		// the next registration.
		watchEnd, refusal connect.Code
		want              string
	}{
		{name: "PERMISSION_DENIED ends the watch", watchEnd: connect.CodePermissionDenied, refusal: connect.CodeUnavailable, want: profile.ReasonLeaseExpired},
		{name: "PERMISSION_DENIED refuses the registration", watchEnd: connect.CodeUnavailable, refusal: connect.CodePermissionDenied, want: profile.ReasonLeaseExpired},
		{name: "FAILED_PRECONDITION refuses the registration", watchEnd: connect.CodeUnavailable, refusal: connect.CodeFailedPrecondition, want: profile.ReasonLeaseExpired},
		{name: "FAILED_PRECONDITION ends the watch", watchEnd: connect.CodeFailedPrecondition, refusal: connect.CodeUnavailable, want: profile.ReasonNoBundle},
		{name: "UNAVAILABLE ends the watch and refuses the registration", watchEnd: connect.CodeUnavailable, refusal: connect.CodeUnavailable, want: profile.ReasonNoBundle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			core, e := startRefusingCore(ctx, t)
			core.answer(ctx, t, accept)
			waitForReason(ctx, t, e, profile.ReasonNoBundle)

			core.end(ctx, t, tc.watchEnd)
			core.answer(ctx, t, tc.refusal)
			// The stub has handled the refusal once it registers again, and
			// without a watch it gets no renewal meanwhile.
			core.answer(ctx, t, connect.CodeUnavailable)
			expectReason(t, e, tc.want)

			core.answer(ctx, t, accept)
			waitForReason(ctx, t, e, profile.ReasonNoBundle)
			if n := len(core.Instances()); n != 2 {
				t.Errorf("the core accepted %d registrations, want 2", n)
			}
		})
	}
}

// feed hands messages to the stub one by one, as its session does with a
// watch stream.
func feed(t *testing.T, e *EP, msgs ...*modulev1alpha1.WatchResponse) {
	t.Helper()
	var pending *modulev1alpha1.SnapshotPart
	for _, msg := range msgs {
		var err error
		if pending, err = e.receive(t.Context(), msg, pending); err != nil {
			t.Fatalf("the message at version %d: %v", msg.GetVersion(), err)
		}
	}
}

// expectReason checks the reason of the stub's decision on a call that the
// valid bundle of the bundle vectors permits.
func expectReason(t *testing.T, e *EP, want string) {
	t.Helper()
	if got := decide(e); got.Context.Reason != want {
		t.Fatalf("decision %v with reason %s, want reason %s", got.Decision, got.Context.Reason, want)
	}
}

// waitForReason waits until the stub's decision has the reason given, while
// its session applies what the core sends.
func waitForReason(ctx context.Context, t *testing.T, e *EP, want string) {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		got := decide(e)
		if got.Context.Reason == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("decision %v with reason %s, want reason %s: %v", got.Decision, got.Context.Reason, want, ctx.Err())
		case <-tick.C:
		}
	}
}

// decide asks the stub to decide on a call that the valid bundle of the
// bundle vectors permits.
func decide(e *EP) profile.Response {
	return e.Decide(
		profile.Action{Name: "tool.invoke"},
		profile.Resource{Type: "tool", ID: "read_invoice", Properties: map[string]any{"kind": "function"}},
		profile.Context{Time: "2026-09-29T10:00:00.000Z"},
	)
}

// expectApplied checks the version the stub applied, from which it resumes
// when it reconnects.
func expectApplied(t *testing.T, e *EP, want uint64) {
	t.Helper()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.applied != want {
		t.Errorf("version applied %d, want %d", e.applied, want)
	}
}

func leaseDeadline(e *EP) time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leaseDeadline
}

// bundleAck is what an acknowledgement says of a bundle.
type bundleAck struct {
	outcome modulev1alpha1.BundleOutcome
	reason  string
}

// bundleAcks returns, in order, what the core was told of a bundle version.
func bundleAcks(core *kit.Core, version uint64) []bundleAck {
	var acks []bundleAck
	for _, a := range core.Acks() {
		if b := a.GetBundle(); b != nil && b.GetVersion() == version {
			acks = append(acks, bundleAck{b.GetOutcome(), b.GetReason()})
		}
	}
	return acks
}

// agentState returns a state of the stub's agent: active, not halted, with
// no bundle, and the lease TTL given.
func agentState(ttl *durationpb.Duration) *modulev1alpha1.AgentState {
	return &modulev1alpha1.AgentState{
		AgentId:        agentID,
		Slug:           "invoice-triage",
		LifecycleState: modulev1alpha1.LifecycleState_LIFECYCLE_STATE_ACTIVE,
		LeaseTtl:       ttl,
		HaltMode:       modulev1alpha1.HaltMode_HALT_MODE_INTERRUPT,
		Attributes: &modulev1alpha1.AgentAttributes{
			Kind: "in_house", RiskTier: "high", DataCategories: []string{"customer data"},
			Labels: map[string]string{"team": "finance"}, OwnerId: "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
		},
	}
}

// haltedAgentState returns a state of the stub's agent under an agent halt.
func haltedAgentState() *modulev1alpha1.AgentState {
	state := agentState(durationpb.New(time.Minute))
	state.Halts = []*modulev1alpha1.Halt{{HaltId: "0192f1c3-0d4e-7a10-9b2c-000000000040", Scope: modulev1alpha1.HaltScope_HALT_SCOPE_AGENT}}
	return state
}

// snapshot returns a complete snapshot in one part, with no fleet halt.
func snapshot(version uint64, agents ...*modulev1alpha1.AgentState) *modulev1alpha1.WatchResponse {
	return &modulev1alpha1.WatchResponse{Version: version, Message: &modulev1alpha1.WatchResponse_SnapshotPart{
		SnapshotPart: &modulev1alpha1.SnapshotPart{First: true, Last: true, Fleet: &modulev1alpha1.FleetState{}, Agents: agents},
	}}
}

// change returns a change that carries one agent's new state.
func change(version uint64, agent *modulev1alpha1.AgentState) *modulev1alpha1.WatchResponse {
	return &modulev1alpha1.WatchResponse{Version: version, Message: &modulev1alpha1.WatchResponse_Change{
		Change: &modulev1alpha1.StateChange{Agents: []*modulev1alpha1.AgentState{agent}},
	}}
}

// removal returns a change that lists the stub's agent as removed from the
// scope.
func removal(version uint64) *modulev1alpha1.WatchResponse {
	return &modulev1alpha1.WatchResponse{Version: version, Message: &modulev1alpha1.WatchResponse_Change{
		Change: &modulev1alpha1.StateChange{RemovedAgentIds: []string{agentID}},
	}}
}

// renewal returns a lease renewal that carries serverTime, or none when it is
// nil.
func renewal(version uint64, serverTime *timestamppb.Timestamp) *modulev1alpha1.WatchResponse {
	return &modulev1alpha1.WatchResponse{Version: version, Message: &modulev1alpha1.WatchResponse_LeaseRenewal{
		LeaseRenewal: &modulev1alpha1.LeaseRenewal{ServerTime: serverTime},
	}}
}

// accept is the answer that accepts a registration (refusingCore.answer).
const accept connect.Code = 0

// refusingCore is the kit's fake core with the refusals it cannot script
// yet, which plan P1-07.2 adds to it for S-12: the test answers each
// registration in turn, accepting it or refusing it with a code, and ends the
// open watch with a code.
type refusingCore struct {
	*kit.Core
	answers chan connect.Code
	ends    chan connect.Code
}

// startRefusingCore serves a refusingCore over HTTP/2 with TLS, as the kit's
// own tests do, to a stub that runs until the test ends. The agent is in the
// state, with a lease of a minute and no bundle, and every watch gets a
// snapshot and a renewal at once.
func startRefusingCore(ctx context.Context, t *testing.T) (*refusingCore, *EP) {
	t.Helper()
	core := &refusingCore{Core: kit.NewCore(nil), answers: make(chan connect.Code), ends: make(chan connect.Code)}
	core.SetAgent(agentState(durationpb.New(time.Minute)))
	core.Release()
	mux := http.NewServeMux()
	mux.Handle(modulev1alpha1connect.NewRegistryServiceHandler(core))
	mux.Handle(modulev1alpha1connect.NewGovernanceServiceHandler(core))
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	e := New(Config{AgentID: agentID, CoreURL: server.URL, HTTPClient: server.Client()})
	ctx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		e.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	return core, e
}

// RegisterInstance waits for the test's answer, then accepts the
// registration or refuses it.
func (c *refusingCore) RegisterInstance(ctx context.Context, req *connect.Request[modulev1alpha1.RegisterInstanceRequest]) (*connect.Response[modulev1alpha1.RegisterInstanceResponse], error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case code := <-c.answers:
		if code != accept {
			return nil, connect.NewError(code, errors.New("refused by the test"))
		}
		return c.Core.RegisterInstance(ctx, req)
	}
}

// Watch serves the kit's watch until the test ends it with a code.
func (c *refusingCore) Watch(ctx context.Context, req *connect.Request[modulev1alpha1.WatchRequest], stream *connect.ServerStream[modulev1alpha1.WatchResponse]) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- c.Core.Watch(ctx, req, stream) }()
	select {
	case err := <-served:
		return err
	case code := <-c.ends:
		cancel()
		<-served // the kit's watch sends nothing once it has returned
		return connect.NewError(code, errors.New("ended by the test"))
	}
}

// answer gives the stub's next registration its answer. It returns once the
// registration has it, so the stub has handled every earlier answer.
func (c *refusingCore) answer(ctx context.Context, t *testing.T, code connect.Code) {
	t.Helper()
	select {
	case c.answers <- code:
	case <-ctx.Done():
		t.Fatalf("the stub did not register again: %v", ctx.Err())
	}
}

// end ends the stub's open watch with a code.
func (c *refusingCore) end(ctx context.Context, t *testing.T, code connect.Code) {
	t.Helper()
	select {
	case c.ends <- code:
	case <-ctx.Done():
		t.Fatalf("the stub holds no watch: %v", ctx.Err())
	}
}
