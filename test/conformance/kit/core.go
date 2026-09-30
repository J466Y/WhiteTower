// Package kit is the skeleton of the conformance kit (plan P0-03, step 8): a
// fake core that speaks the module API, the driver protocol that tells a
// module under test what to do, and the scenarios that check the contract's
// obligations. Plan P1-07 turns it into the full kit.
package kit

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	modulev1alpha1 "github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1"
	"github.com/J466Y/WhiteTower/pkg/moduleapi/whitetower/module/v1alpha1/modulev1alpha1connect"
	"github.com/J466Y/WhiteTower/test/conformance/bundle"
)

// Core plays the White Tower core for the module under test. A scenario sets
// the governance state, publishes bundles and renews leases through its
// methods, and reads back what the module registered, acknowledged and
// published.
//
// The skeleton does not authenticate callers: the full kit adds a fake token
// endpoint and checks the tokens (contract, section 4.2).
type Core struct {
	mu        sync.Mutex
	version   uint64
	withheld  bool
	agents    map[string]*modulev1alpha1.AgentState
	fleet     *modulev1alpha1.FleetState
	bundles   map[string]*bundle.Bundle
	keys      []*modulev1alpha1.BundleKey
	watchers  map[int]chan *modulev1alpha1.WatchResponse
	nextWatch int
	instances []*modulev1alpha1.RegisterInstanceRequest
	acks      []*modulev1alpha1.Acknowledgement
	events    [][]byte
}

var (
	_ modulev1alpha1connect.RegistryServiceHandler   = (*Core)(nil)
	_ modulev1alpha1connect.GovernanceServiceHandler = (*Core)(nil)
	_ modulev1alpha1connect.PolicyServiceHandler     = (*Core)(nil)
	_ modulev1alpha1connect.EventServiceHandler      = (*Core)(nil)
)

// NewCore returns a core with no agents that withholds the snapshot until
// Release is called, so a scenario can observe a module that has no state.
func NewCore(keys []bundle.Key) *Core {
	c := &Core{
		withheld: true,
		agents:   map[string]*modulev1alpha1.AgentState{},
		fleet:    &modulev1alpha1.FleetState{},
		bundles:  map[string]*bundle.Bundle{},
		watchers: map[int]chan *modulev1alpha1.WatchResponse{},
	}
	for _, k := range keys {
		c.keys = append(c.keys, &modulev1alpha1.BundleKey{
			KeyId: k.ID, Algorithm: bundle.Algorithm, PublicKey: k.Public,
			Status: modulev1alpha1.BundleKeyStatus_BUNDLE_KEY_STATUS_ACTIVE,
		})
	}
	return c
}

// Handler serves the module API.
func (c *Core) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(modulev1alpha1connect.NewRegistryServiceHandler(c))
	mux.Handle(modulev1alpha1connect.NewGovernanceServiceHandler(c))
	mux.Handle(modulev1alpha1connect.NewPolicyServiceHandler(c))
	mux.Handle(modulev1alpha1connect.NewEventServiceHandler(c))
	return mux
}

// SetAgent publishes an agent's new state as a change.
func (c *Core) SetAgent(state *modulev1alpha1.AgentState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version++
	state.Version = c.version
	c.agents[state.GetAgentId()] = state
	c.broadcast(&modulev1alpha1.WatchResponse{
		Version: c.version,
		Message: &modulev1alpha1.WatchResponse_Change{Change: &modulev1alpha1.StateChange{Agents: []*modulev1alpha1.AgentState{state}}},
	})
}

// PublishBundle stores a bundle and points the agent's state at it.
func (c *Core) PublishBundle(agentID string, b *bundle.Bundle, ref bundle.Ref) error {
	c.mu.Lock()
	state, ok := c.agents[agentID]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown agent %s", agentID)
	}
	c.bundles[bundleKey(agentID, ref.Version)] = b
	next := proto.Clone(state).(*modulev1alpha1.AgentState)
	c.mu.Unlock()
	next.Bundle = &modulev1alpha1.BundleRef{Version: ref.Version, ManifestSha256: ref.ManifestSHA256, SizeBytes: ref.SizeBytes}
	c.SetAgent(next)
	return nil
}

// Release sends the snapshot to every open watch, then renews the leases.
func (c *Core) Release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.withheld = false
	for id := range c.watchers {
		for _, msg := range c.snapshotLocked() {
			c.sendLocked(id, msg)
		}
	}
}

// RenewLeases renews the lease of every agent on every open watch.
func (c *Core) RenewLeases() {
	c.RenewLeasesAt(timestamppb.Now())
}

// RenewLeasesAt sends a renewal carrying the given server time, or none when
// it is nil. A scenario uses it to play a stream held back on its way, whose
// renewals arrive late.
func (c *Core) RenewLeasesAt(serverTime *timestamppb.Timestamp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.broadcast(&modulev1alpha1.WatchResponse{
		Version: c.version,
		Message: &modulev1alpha1.WatchResponse_LeaseRenewal{LeaseRenewal: &modulev1alpha1.LeaseRenewal{ServerTime: serverTime}},
	})
}

// Watchers returns the number of open watch streams.
func (c *Core) Watchers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.watchers)
}

// Instances returns the registrations received so far.
func (c *Core) Instances() []*modulev1alpha1.RegisterInstanceRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.instances)
}

// Acks returns the acknowledgements received so far.
func (c *Core) Acks() []*modulev1alpha1.Acknowledgement {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.acks)
}

// broadcast sends a message to every watch unless the snapshot is withheld.
// Callers hold c.mu.
func (c *Core) broadcast(msg *modulev1alpha1.WatchResponse) {
	if c.withheld {
		return
	}
	for id := range c.watchers {
		c.sendLocked(id, msg)
	}
}

// sendLocked queues a message for one watch. A watch that cannot keep up is
// disconnected, as the real core does. Callers hold c.mu.
func (c *Core) sendLocked(id int, msg *modulev1alpha1.WatchResponse) {
	ch := c.watchers[id]
	select {
	case ch <- msg:
	default:
		delete(c.watchers, id)
		close(ch)
	}
}

// snapshotLocked returns a one-part snapshot followed by a lease renewal.
// Callers hold c.mu.
func (c *Core) snapshotLocked() []*modulev1alpha1.WatchResponse {
	part := &modulev1alpha1.SnapshotPart{First: true, Last: true, Fleet: c.fleet}
	for _, id := range slices.Sorted(maps.Keys(c.agents)) {
		part.Agents = append(part.Agents, c.agents[id])
	}
	return []*modulev1alpha1.WatchResponse{
		{Version: c.version, Message: &modulev1alpha1.WatchResponse_SnapshotPart{SnapshotPart: part}},
		c.renewalLocked(),
	}
}

func (c *Core) renewalLocked() *modulev1alpha1.WatchResponse {
	return &modulev1alpha1.WatchResponse{
		Version: c.version,
		Message: &modulev1alpha1.WatchResponse_LeaseRenewal{LeaseRenewal: &modulev1alpha1.LeaseRenewal{ServerTime: timestamppb.Now()}},
	}
}

// RegisterInstance records the registration and selects v1alpha1.
func (c *Core) RegisterInstance(_ context.Context, req *connect.Request[modulev1alpha1.RegisterInstanceRequest]) (*connect.Response[modulev1alpha1.RegisterInstanceResponse], error) {
	if !slices.Contains(req.Msg.GetContractVersions(), "v1alpha1") {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no common contract version: the server supports v1alpha1"))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.instances = append(c.instances, req.Msg)
	return connect.NewResponse(&modulev1alpha1.RegisterInstanceResponse{
		InstanceId:        fmt.Sprintf("00000000-0000-7000-8000-%012d", len(c.instances)),
		ContractVersion:   "v1alpha1",
		HeartbeatInterval: durationpb.New(30 * time.Second),
	}), nil
}

// Heartbeat accepts every heartbeat.
func (c *Core) Heartbeat(context.Context, *connect.Request[modulev1alpha1.HeartbeatRequest]) (*connect.Response[modulev1alpha1.HeartbeatResponse], error) {
	return connect.NewResponse(&modulev1alpha1.HeartbeatResponse{HeartbeatInterval: durationpb.New(30 * time.Second)}), nil
}

// DeregisterInstance accepts every deregistration.
func (c *Core) DeregisterInstance(context.Context, *connect.Request[modulev1alpha1.DeregisterInstanceRequest]) (*connect.Response[modulev1alpha1.DeregisterInstanceResponse], error) {
	return connect.NewResponse(&modulev1alpha1.DeregisterInstanceResponse{}), nil
}

// Watch streams the snapshot, once released, then changes and renewals.
func (c *Core) Watch(ctx context.Context, _ *connect.Request[modulev1alpha1.WatchRequest], stream *connect.ServerStream[modulev1alpha1.WatchResponse]) error {
	ch := make(chan *modulev1alpha1.WatchResponse, 64)
	c.mu.Lock()
	id := c.nextWatch
	c.nextWatch++
	c.watchers[id] = ch
	if !c.withheld {
		for _, msg := range c.snapshotLocked() {
			c.sendLocked(id, msg)
		}
	}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.watchers, id)
		c.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-ch:
			if !ok {
				return connect.NewError(connect.CodeResourceExhausted, errors.New("watcher too slow"))
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

// Acknowledge records the acknowledgements.
func (c *Core) Acknowledge(_ context.Context, req *connect.Request[modulev1alpha1.AcknowledgeRequest]) (*connect.Response[modulev1alpha1.AcknowledgeResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acks = append(c.acks, req.Msg.GetAcknowledgements()...)
	return connect.NewResponse(&modulev1alpha1.AcknowledgeResponse{}), nil
}

// GetBundle serves the bundles published by the scenario.
func (c *Core) GetBundle(_ context.Context, req *connect.Request[modulev1alpha1.GetBundleRequest]) (*connect.Response[modulev1alpha1.GetBundleResponse], error) {
	c.mu.Lock()
	b, ok := c.bundles[bundleKey(req.Msg.GetAgentId(), req.Msg.GetVersion())]
	c.mu.Unlock()
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such bundle"))
	}
	resp := &modulev1alpha1.Bundle{Manifest: b.Manifest, Signature: b.Signature}
	for _, path := range slices.Sorted(maps.Keys(b.Files)) {
		resp.Files = append(resp.Files, &modulev1alpha1.BundleFile{Path: path, Content: b.Files[path]})
	}
	return connect.NewResponse(&modulev1alpha1.GetBundleResponse{Bundle: resp}), nil
}

// GetBundleKeys returns the keys the core was created with.
func (c *Core) GetBundleKeys(context.Context, *connect.Request[modulev1alpha1.GetBundleKeysRequest]) (*connect.Response[modulev1alpha1.GetBundleKeysResponse], error) {
	return connect.NewResponse(&modulev1alpha1.GetBundleKeysResponse{Keys: c.keys}), nil
}

// Publish accepts every event.
func (c *Core) Publish(_ context.Context, req *connect.Request[modulev1alpha1.PublishRequest]) (*connect.Response[modulev1alpha1.PublishResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp := &modulev1alpha1.PublishResponse{}
	for _, e := range req.Msg.GetEvents() {
		c.events = append(c.events, e)
		resp.Results = append(resp.Results, &modulev1alpha1.EventResult{Status: modulev1alpha1.EventStatus_EVENT_STATUS_ACCEPTED})
	}
	return connect.NewResponse(resp), nil
}

func bundleKey(agentID string, version uint64) string { return fmt.Sprintf("%s@%d", agentID, version) }
