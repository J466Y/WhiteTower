// Package stubep is a minimal enforcement point in Go: just enough to run the
// conformance scenarios end to end against the kit's fake core. It keeps no
// evidence and handles one agent. It is not a product: plan P1-09 builds the
// real enforcement point, in Python.
package stubep

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

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
}

// EP is the stub enforcement point.
type EP struct {
	cfg        Config
	registry   modulev1alpha1connect.RegistryServiceClient
	governance modulev1alpha1connect.GovernanceServiceClient
	policy     modulev1alpha1connect.PolicyServiceClient

	mu            sync.RWMutex
	instanceID    string
	applied       uint64
	stateReceived bool
	agent         *modulev1alpha1.AgentState
	fleet         *modulev1alpha1.FleetState
	leaseDeadline time.Time
	engine        *profile.Engine
	active        bundle.Ref
	rejected      bundle.Ref
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
		msg := stream.Msg()
		switch m := msg.GetMessage().(type) {
		case *modulev1alpha1.WatchResponse_SnapshotPart:
			part := m.SnapshotPart
			if part.GetFirst() {
				pending = &modulev1alpha1.SnapshotPart{Fleet: part.GetFleet()}
			}
			if pending == nil {
				continue // a part without its first part: wait for the next snapshot
			}
			pending.Agents = append(pending.Agents, part.GetAgents()...)
			if part.GetLast() {
				e.applySnapshot(pending, msg.GetVersion())
				pending = nil
			}
		case *modulev1alpha1.WatchResponse_Change:
			e.applyChange(m.Change, msg.GetVersion())
		case *modulev1alpha1.WatchResponse_LeaseRenewal:
			e.renewLease()
		}
		e.syncBundle(ctx)
	}
	return stream.Err()
}

func (e *EP) applySnapshot(s *modulev1alpha1.SnapshotPart, version uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stateReceived = true
	e.applied = version
	e.fleet = s.GetFleet()
	e.agent = nil
	for _, a := range s.GetAgents() {
		if a.GetAgentId() == e.cfg.AgentID {
			e.agent = a
		}
	}
}

func (e *EP) applyChange(c *modulev1alpha1.StateChange, version uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
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
}

// renewLease starts a new lease on the monotonic clock (obligation EP-3).
func (e *EP) renewLease() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stateReceived && e.agent != nil {
		e.leaseDeadline = time.Now().Add(e.agent.GetLeaseTtl().AsDuration())
	}
}

// syncBundle fetches, verifies and activates the bundle the state refers to
// (obligation EP-7).
func (e *EP) syncBundle(ctx context.Context) {
	e.mu.RLock()
	agent, active, rejected, instanceID := e.agent, e.active, e.rejected, e.instanceID
	e.mu.RUnlock()
	ref := agent.GetBundle()
	if ref == nil {
		return
	}
	want := bundle.Ref{Version: ref.GetVersion(), ManifestSHA256: ref.GetManifestSha256(), SizeBytes: ref.GetSizeBytes()}
	// Nothing to do for the active bundle, and a rejected one is never retried.
	if want.Version == active.Version && want.ManifestSHA256 == active.ManifestSHA256 || want == rejected {
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
