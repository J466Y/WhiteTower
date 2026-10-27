// Package stubep is a minimal enforcement point in Go: just enough to run the
// conformance scenarios end to end against the kit's fake core. It keeps no
// evidence and handles one agent. It is not a product: plan P1-09 builds the
// real enforcement point, in Python.
package stubep

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
	"github.com/J466Y/WhiteTower/test/conformance/bundle"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
)

// Config configures the stub.
type Config struct {
	// The agent it serves.
	AgentID string
	// The environment of its credential: "production" or "non_production".
	Environment string
	// Its trust root for bundles.
	Trusted []bundle.Key
	// How it reaches the core.
	CoreURL    string
	HTTPClient connect.HTTPClient
	// How far a lease renewal's time may be from the stub's clock, before or
	// after, for the renewal to renew the lease. Zero means
	// DefaultRenewalTolerance, and a tolerance above MaxRenewalTolerance
	// counts as MaxRenewalTolerance.
	RenewalTolerance time.Duration
}

const (
	// DefaultRenewalTolerance is the contract's default for how far a lease
	// renewal's time may be from the instance's clock (section 5.3).
	DefaultRenewalTolerance = 5 * time.Second
	// MaxRenewalTolerance is the largest tolerance the contract lets an
	// instance configure (section 5.3).
	MaxRenewalTolerance = 30 * time.Second
	// maxLeaseTTL is the longest lease the stub applies: a longer TTL from
	// the core counts as this one (section 5.3).
	maxLeaseTTL = 300 * time.Second
)

// errSnapshotWithoutFleet ends a stream whose snapshot is malformed because
// its first part lacks the fleet state (section 5.2).
var errSnapshotWithoutFleet = errors.New("malformed snapshot: its first part lacks the fleet state")

// EP is the stub enforcement point.
type EP struct {
	cfg        Config
	registry   modulev1alpha1connect.RegistryServiceClient
	governance modulev1alpha1connect.GovernanceServiceClient
	policy     modulev1alpha1connect.PolicyServiceClient

	mu         sync.RWMutex
	instanceID string
	// applied is the highest state version applied. It never goes back
	// (section 5.2).
	applied       uint64
	stateReceived bool
	agent         *modulev1alpha1.AgentState
	fleet         *modulev1alpha1.FleetState
	leaseDeadline time.Time
	// engine evaluates the active bundle; nil while no bundle is active.
	engine *profile.Engine
	// active is the bundle activated last. Once the state stops naming a
	// bundle, that bundle is no longer active, but its version stays the
	// floor of V6 for the next one (EP-7).
	active   bundle.Ref
	rejected bundle.Ref
}

// New returns a stub that has not connected yet: its gate is closed.
func New(cfg Config) *EP {
	return &EP{
		cfg:        cfg,
		registry:   modulev1alpha1connect.NewRegistryServiceClient(cfg.HTTPClient, cfg.CoreURL),
		governance: modulev1alpha1connect.NewGovernanceServiceClient(cfg.HTTPClient, cfg.CoreURL),
		policy:     modulev1alpha1connect.NewPolicyServiceClient(cfg.HTTPClient, cfg.CoreURL),
	}
}

// Run registers and watches until ctx ends, reconnecting with jittered
// exponential backoff (obligation EP-9).
func (e *EP) Run(ctx context.Context) {
	backoff := 50 * time.Millisecond
	for ctx.Err() == nil {
		started := time.Now()
		_ = e.session(ctx)
		if time.Since(started) > time.Minute {
			backoff = 50 * time.Millisecond
		}
		select {
		case <-ctx.Done():
		case <-time.After(mathrand.N(backoff)): //nolint:gosec // G404: backoff jitter needs no cryptographic randomness
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

func (e *EP) session(ctx context.Context) error {
	reg, err := e.registry.RegisterInstance(ctx, connect.NewRequest(&modulev1alpha1.RegisterInstanceRequest{
		Module:           "conformance-stub",
		ModuleVersion:    "0.0.0",
		InstanceKey:      "stub-" + e.cfg.AgentID,
		ContractVersions: []string{"v1alpha1"},
		AgentIds:         []string{e.cfg.AgentID},
	}))
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.instanceID = reg.Msg.GetInstanceId()
	since := e.applied
	e.mu.Unlock()

	stream, err := e.governance.Watch(ctx, connect.NewRequest(&modulev1alpha1.WatchRequest{
		InstanceId: reg.Msg.GetInstanceId(), SinceVersion: since,
	}))
	if err != nil {
		return err
	}
	defer stream.Close()
	var pending *modulev1alpha1.SnapshotPart
	for stream.Receive() {
		if pending, err = e.receive(ctx, stream.Msg(), pending); err != nil {
			return err
		}
	}
	return stream.Err()
}

// receive applies one message of a watch stream, then syncs the bundle.
// pending holds the parts of a snapshot received so far on the stream, nil
// between snapshots, and receive returns it updated. A snapshot whose first
// part lacks the fleet state is malformed: receive returns an error, which
// ends the stream, and the stub keeps its current state and reconnects with
// backoff (section 5.2).
func (e *EP) receive(ctx context.Context, msg *modulev1alpha1.WatchResponse, pending *modulev1alpha1.SnapshotPart) (*modulev1alpha1.SnapshotPart, error) {
	switch m := msg.GetMessage().(type) {
	case *modulev1alpha1.WatchResponse_SnapshotPart:
		part := m.SnapshotPart
		if part.GetFirst() {
			if part.GetFleet() == nil {
				return nil, errSnapshotWithoutFleet
			}
			pending = &modulev1alpha1.SnapshotPart{Fleet: part.GetFleet()}
		}
		if pending == nil {
			return nil, nil // a part without its first part: wait for the next snapshot
		}
		pending.Agents = append(pending.Agents, part.GetAgents()...)
		if part.GetLast() {
			e.applySnapshot(pending, msg.GetVersion())
			pending = nil
		}
	case *modulev1alpha1.WatchResponse_Change:
		e.applyChange(m.Change, msg.GetVersion())
	case *modulev1alpha1.WatchResponse_LeaseRenewal:
		e.renewLease(m.LeaseRenewal, msg.GetVersion())
	}
	e.syncBundle(ctx)
	return pending, nil
}

// applySnapshot replaces the state with a complete snapshot, unless the
// snapshot is below the version applied (section 5.2).
func (e *EP) applySnapshot(s *modulev1alpha1.SnapshotPart, version uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if version < e.applied {
		return
	}
	e.stateReceived = true
	e.applied = version
	e.fleet = s.GetFleet()
	e.agent = nil
	for _, a := range s.GetAgents() {
		if a.GetAgentId() == e.cfg.AgentID {
			e.agent = a
		}
	}
	e.deactivateUnnamedBundleLocked()
}

// applyChange applies a change, unless the change is below the version
// applied. The agent's state in it is applied whatever that state's own
// version (section 5.2).
func (e *EP) applyChange(c *modulev1alpha1.StateChange, version uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if version < e.applied {
		return
	}
	e.applied = version
	if c.GetFleet() != nil {
		e.fleet = c.GetFleet()
	}
	for _, a := range c.GetAgents() {
		if a.GetAgentId() == e.cfg.AgentID {
			e.agent = a
		}
	}
	for _, id := range c.GetRemovedAgentIds() {
		if id == e.cfg.AgentID {
			e.agent = nil
		}
	}
	e.deactivateUnnamedBundleLocked()
}

// deactivateUnnamedBundleLocked deactivates the active bundle when the
// agent's state names none, so that the gate closes with gate.no_bundle as
// soon as that state is applied. e.active keeps the bundle's reference, the
// floor of V6 for the next one (EP-7). Callers hold e.mu.
func (e *EP) deactivateUnnamedBundleLocked() {
	if e.agent != nil && e.agent.GetBundle() == nil {
		e.engine = nil
	}
}

// renewLease starts a new lease on the monotonic clock (obligation EP-3), if
// the renewal is fresh. A fresh renewal also raises the version applied to
// its own, which may pass versions that carried nothing for the stream, but
// never lowers it (section 5.2, CORE-6).
func (e *EP) renewLease(r *modulev1alpha1.LeaseRenewal, version uint64) {
	if !e.fresh(r) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.stateReceived {
		return
	}
	e.applied = max(e.applied, version)
	if e.agent == nil {
		return
	}
	if ttl, ok := leaseTTL(e.agent.GetLeaseTtl()); ok {
		e.leaseDeadline = time.Now().Add(ttl)
	}
}

// fresh reports whether a lease renewal counts: it carries the core's time,
// no more than the tolerance before or after the stub's clock. A renewal from
// the future is stale too (section 5.3).
func (e *EP) fresh(r *modulev1alpha1.LeaseRenewal) bool {
	if r.GetServerTime() == nil {
		return false
	}
	tolerance := e.cfg.RenewalTolerance
	if tolerance == 0 {
		tolerance = DefaultRenewalTolerance
	}
	tolerance = min(tolerance, MaxRenewalTolerance)
	offset := time.Since(r.GetServerTime().AsTime())
	return -tolerance <= offset && offset <= tolerance
}

// leaseTTL bounds the lease TTL that the core sends (section 5.3): a TTL
// above 300 seconds counts as 300, and one under 10 seconds is applied as it
// is. A TTL that is zero, negative or absent renews nothing: ok is false.
func leaseTTL(d *durationpb.Duration) (ttl time.Duration, ok bool) {
	ttl = d.AsDuration()
	if ttl <= 0 {
		return 0, false
	}
	return min(ttl, maxLeaseTTL), true
}

// syncBundle fetches, verifies and activates the bundle the state refers to
// (obligation EP-7).
func (e *EP) syncBundle(ctx context.Context) {
	e.mu.RLock()
	agent, engine, active, rejected, instanceID := e.agent, e.engine, e.active, e.rejected, e.instanceID
	e.mu.RUnlock()
	ref := agent.GetBundle()
	if ref == nil {
		return
	}
	want := bundle.Ref{Version: ref.GetVersion(), ManifestSHA256: ref.GetManifestSha256(), SizeBytes: ref.GetSizeBytes()}
	// Nothing to do for the active bundle, and a rejected one is never
	// retried. Once deactivated, even the same bundle is fetched and verified
	// again, and V6 lets it through.
	if engine != nil && want.Version == active.Version && want.ManifestSHA256 == active.ManifestSHA256 || want == rejected {
		return
	}
	outcome, reason := modulev1alpha1.BundleOutcome_BUNDLE_OUTCOME_ACTIVATED, ""
	engine, err := e.fetchAndVerify(ctx, want, active)
	if err != nil {
		outcome, reason = modulev1alpha1.BundleOutcome_BUNDLE_OUTCOME_REJECTED, bundle.Reason(err)
		if reason == "" {
			return // not a verdict on the bundle, for example the core was unreachable
		}
		e.mu.Lock()
		e.rejected = want
		e.mu.Unlock()
	} else {
		e.mu.Lock()
		e.engine, e.active = engine, want
		e.mu.Unlock()
	}
	_, _ = e.governance.Acknowledge(ctx, connect.NewRequest(&modulev1alpha1.AcknowledgeRequest{
		InstanceId: instanceID,
		Acknowledgements: []*modulev1alpha1.Acknowledgement{{
			AcknowledgementId: newID(),
			AgentId:           e.cfg.AgentID,
			Kind: &modulev1alpha1.Acknowledgement_Bundle{Bundle: &modulev1alpha1.BundleAcknowledgement{
				Version: want.Version, ManifestSha256: want.ManifestSHA256, Outcome: outcome, Reason: reason,
			}},
		}},
	}))
}

func (e *EP) fetchAndVerify(ctx context.Context, want, active bundle.Ref) (*profile.Engine, error) {
	resp, err := e.policy.GetBundle(ctx, connect.NewRequest(&modulev1alpha1.GetBundleRequest{
		AgentId: e.cfg.AgentID, Version: want.Version,
	}))
	if err != nil {
		return nil, err
	}
	b := &bundle.Bundle{Manifest: resp.Msg.GetBundle().GetManifest(), Signature: resp.Msg.GetBundle().GetSignature(), Files: map[string][]byte{}}
	for _, f := range resp.Msg.GetBundle().GetFiles() {
		b.Files[f.GetPath()] = f.GetContent()
	}
	m, err := bundle.Verify(b, e.cfg.Trusted, bundle.Expectation{
		AgentID: e.cfg.AgentID, Ref: want, ActiveVersion: active.Version, ActiveSHA256: active.ManifestSHA256,
		Languages: []string{"cedar"},
	})
	if err != nil {
		return nil, err
	}
	policies := make([]profile.Policy, 0, len(m.Policies))
	for _, p := range m.Policies {
		policies = append(policies, profile.Policy{ID: p.ID, Text: string(b.Files[p.Path])})
	}
	engine, err := profile.NewEngine(e.cfg.AgentID, m.Version, policies)
	if err != nil {
		return nil, &bundle.RejectError{Reason: bundle.ReasonParseError, Detail: err.Error()}
	}
	return engine, nil
}

// Decide runs the gate, then the policies (obligation EP-2). The request has
// no subject: the enforcement point builds it from its state and credential.
func (e *EP) Decide(action profile.Action, resource profile.Resource, ctx profile.Context) profile.Response {
	e.mu.RLock()
	defer e.mu.RUnlock()
	gate := profile.GateState{
		StateReceived:  e.stateReceived && e.agent != nil,
		LeaseValid:     !e.leaseDeadline.IsZero() && time.Now().Before(e.leaseDeadline),
		AgentHalted:    len(e.agent.GetHalts()) > 0,
		FleetHalted:    len(e.fleet.GetHalts()) > 0,
		LifecycleState: lifecycleName(e.agent.GetLifecycleState()),
		BundleActive:   e.engine != nil,
	}
	if reason := profile.GateReason(gate); reason != "" {
		return profile.Deny(reason)
	}
	attrs := e.agent.GetAttributes()
	if ctx.Time == "" {
		ctx.Time = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return e.engine.Evaluate(profile.Request{
		Subject: profile.Subject{Type: "agent", ID: e.cfg.AgentID, Properties: profile.SubjectProperties{
			Slug: e.agent.GetSlug(), Kind: attrs.GetKind(), RiskTier: attrs.GetRiskTier(), Environment: e.cfg.Environment,
			DataCategories: attrs.GetDataCategories(), Owner: attrs.GetOwnerId(), Labels: attrs.GetLabels(),
		}},
		Action:   action,
		Resource: resource,
		Context:  ctx,
	})
}

// lifecycleName maps the enumeration to the profile's lower-case names;
// unknown values become "unspecified", which keeps the gate closed.
func lifecycleName(s modulev1alpha1.LifecycleState) string {
	name, ok := strings.CutPrefix(s.String(), "LIFECYCLE_STATE_")
	if !ok || s == modulev1alpha1.LifecycleState_LIFECYCLE_STATE_UNSPECIFIED {
		return "unspecified"
	}
	return strings.ToLower(name)
}

// DecideRequest is the body of the driver's decide call: an AuthZEN request
// without its subject (test/conformance/driver-protocol.md).
type DecideRequest struct {
	Action   profile.Action   `json:"action"`
	Resource profile.Resource `json:"resource"`
	Context  profile.Context  `json:"context"`
}

// DriverHandler serves the driver protocol the kit uses to exercise the stub.
func (e *EP) DriverHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/decide", func(w http.ResponseWriter, r *http.Request) {
		var req DecideRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(e.Decide(req.Action, req.Resource, req.Context))
	})
	return mux
}

// newID returns a random UUID (version 4) for idempotency keys.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
