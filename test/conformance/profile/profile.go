// Package profile implements the White Tower decision profile v1alpha1 for
// Cedar: it maps an AuthZEN evaluation request to a Cedar request, applies the
// contract's rules on top of Cedar's, and computes the gate
// (docs/contracts/module-contract-v0.1.md, sections 5 and 6).
//
// It is the reference the conformance vectors are checked against, and a
// starting point for enforcement points written in Go.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Reason codes of decisions (contract, section 6.6).
const (
	ReasonPermit          = "policy.permit"
	ReasonForbid          = "policy.forbid"
	ReasonNoPermit        = "policy.no_permit"
	ReasonNoState         = "gate.no_state"
	ReasonLeaseExpired    = "gate.lease_expired"
	ReasonHalted          = "gate.halted"
	ReasonFleetHalted     = "gate.fleet_halted"
	ReasonLifecycle       = "gate.lifecycle"
	ReasonNoBundle        = "gate.no_bundle"
	ReasonEvidenceFull    = "gate.evidence_full"
	ReasonEvaluationError = "error.evaluation"
	ReasonTimeout         = "error.timeout"
	ReasonUnknownAgent    = "error.unknown_agent"
	ReasonInvalidRequest  = "error.invalid_request"
)

// Request is an AuthZEN evaluation request of the profile.
type Request struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
	Context  Context  `json:"context"`
}

// Subject is the agent making the request.
type Subject struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Properties SubjectProperties `json:"properties"`
}

// SubjectProperties are the agent's attributes (section 6.2).
type SubjectProperties struct {
	Slug           string            `json:"slug"`
	Kind           string            `json:"kind"`
	RiskTier       string            `json:"risk_tier"`
	Environment    string            `json:"environment"`
	DataCategories []string          `json:"data_categories"`
	Owner          string            `json:"owner"`
	Labels         map[string]string `json:"labels"`
}

// Action is the intervention point.
type Action struct {
	Name string `json:"name"`
}

// Resource is what the action applies to.
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Context is the request's context.
type Context struct {
	Time       string         `json:"time"`
	TaskID     string         `json:"task_id,omitempty"`
	TraceID    string         `json:"trace_id,omitempty"`
	OnBehalfOf string         `json:"on_behalf_of,omitempty"`
	Args       map[string]any `json:"args,omitempty"`
}

// Response is an AuthZEN evaluation response of the profile.
type Response struct {
	Decision bool            `json:"decision"`
	Context  ResponseContext `json:"context"`
}

// ResponseContext explains the decision.
type ResponseContext struct {
	Reason        string   `json:"reason"`
	Policies      []string `json:"policies"`
	BundleVersion uint64   `json:"bundle_version,omitempty"`
}

// Deny returns a denial with a reason and no determining policies.
func Deny(reason string) Response {
	return Response{Context: ResponseContext{Reason: reason, Policies: []string{}}}
}

// Policy is one White Tower policy: its ID and its Cedar text, which may hold
// several Cedar statements.
type Policy struct {
	ID   string
	Text string
}

// Engine evaluates the requests of one agent against one bundle's policies.
type Engine struct {
	agentID       string
	bundleVersion uint64
	set           *cedar.PolicySet
	owners        map[cedar.PolicyID]string
}

// NewEngine parses the policies of a bundle. A policy that does not parse
// rejects the whole bundle: an enforcement point never runs part of a bundle.
func NewEngine(agentID string, bundleVersion uint64, policies []Policy) (*Engine, error) {
	e := &Engine{
		agentID:       agentID,
		bundleVersion: bundleVersion,
		set:           cedar.NewPolicySet(),
		owners:        map[cedar.PolicyID]string{},
	}
	for _, p := range policies {
		list, err := cedar.NewPolicyListFromBytes(p.ID, []byte(p.Text))
		if err != nil {
			return nil, fmt.Errorf("policy %s does not parse: %w", p.ID, err)
		}
		for i, statement := range list {
			id := cedar.PolicyID(fmt.Sprintf("%s#%d", p.ID, i))
			e.set.Add(id, statement)
			e.owners[id] = p.ID
		}
	}
	return e, nil
}

// Evaluate decides one request with the combining algorithm
// wt-deny-overrides-v1 (section 6.5). The gate is not part of the engine:
// callers check it first.
func (e *Engine) Evaluate(req Request) Response {
	if req.Subject.Type != "agent" || req.Subject.ID != e.agentID {
		return Deny(ReasonUnknownAgent)
	}
	creq, entities, err := ToCedar(req)
	if err != nil {
		return Deny(ReasonInvalidRequest)
	}
	decision, diag := cedar.Authorize(e.set, entities, creq)
	resp := Response{Context: ResponseContext{Policies: []string{}, BundleVersion: e.bundleVersion}}
	switch {
	case len(diag.Errors) > 0:
		// Cedar skips a policy that fails and decides with the others. The
		// contract does not: any error is a denial (rule 4 of section 6.5).
		resp.Context.Reason = ReasonEvaluationError
		for _, d := range diag.Errors {
			resp.Context.Policies = append(resp.Context.Policies, e.owners[d.PolicyID])
		}
	case decision == cedar.Allow:
		resp.Decision = true
		resp.Context.Reason = ReasonPermit
		for _, d := range diag.Reasons {
			resp.Context.Policies = append(resp.Context.Policies, e.owners[d.PolicyID])
		}
	case len(diag.Reasons) > 0:
		resp.Context.Reason = ReasonForbid
		for _, d := range diag.Reasons {
			resp.Context.Policies = append(resp.Context.Policies, e.owners[d.PolicyID])
		}
	default:
		resp.Context.Reason = ReasonNoPermit
	}
	slices.Sort(resp.Context.Policies)
	resp.Context.Policies = slices.Compact(resp.Context.Policies)
	return resp
}

// actionResource maps each action of the profile to the resource type it
// applies to (section 6.3).
var actionResource = map[string]string{
	"agent.start":   "agent",
	"input.receive": "agent",
	"model.invoke":  "model",
	"model.result":  "model",
	"tool.invoke":   "tool",
	"tool.result":   "tool",
	"output.emit":   "agent",
	"agent.stop":    "agent",
}

// resourceTypes maps the profile's resource types to Cedar entity types.
var resourceTypes = map[string]types.EntityType{
	"agent":      "WhiteTower::Agent",
	"tool":       "WhiteTower::Tool",
	"model":      "WhiteTower::Model",
	"mcp_server": "WhiteTower::McpServer",
	"dataset":    "WhiteTower::Dataset",
	"skill":      "WhiteTower::Skill",
	"url":        "WhiteTower::Url",
}

// ToCedar maps a request of the profile to a Cedar request and the entities it
// needs (section 6.7).
func ToCedar(req Request) (cedar.Request, cedar.EntityMap, error) {
	want, ok := actionResource[req.Action.Name]
	if !ok {
		return cedar.Request{}, nil, fmt.Errorf("unknown action %q", req.Action.Name)
	}
	if req.Resource.Type != want {
		return cedar.Request{}, nil, fmt.Errorf("action %s applies to %s, not %s", req.Action.Name, want, req.Resource.Type)
	}
	if req.Resource.ID == "" {
		return cedar.Request{}, nil, errors.New("resource without an ID")
	}
	at, err := time.Parse(time.RFC3339Nano, req.Context.Time)
	if err != nil {
		return cedar.Request{}, nil, fmt.Errorf("context.time: %w", err)
	}

	p := req.Subject.Properties
	principalUID := types.NewEntityUID("WhiteTower::Agent", types.String(req.Subject.ID))
	tags := types.RecordMap{}
	for k, v := range p.Labels {
		tags[types.String(k)] = types.String(v)
	}
	categories := make([]types.Value, 0, len(p.DataCategories))
	for _, c := range p.DataCategories {
		categories = append(categories, types.String(c))
	}
	entities := cedar.EntityMap{
		principalUID: {
			UID: principalUID,
			Attributes: types.NewRecord(types.RecordMap{
				"slug":            types.String(p.Slug),
				"kind":            types.String(p.Kind),
				"risk_tier":       types.String(p.RiskTier),
				"environment":     types.String(p.Environment),
				"data_categories": types.NewSet(categories...),
				"owner":           types.String(p.Owner),
			}),
			Tags: types.NewRecord(tags),
		},
	}

	resourceUID := types.NewEntityUID(resourceTypes[req.Resource.Type], types.String(req.Resource.ID))
	attrs := types.RecordMap{}
	switch req.Resource.Type {
	case "agent":
		// The agent actions concern the agent itself.
		if req.Resource.ID != req.Subject.ID {
			return cedar.Request{}, nil, errors.New("an agent action must concern the requesting agent")
		}
	case "tool":
		kind, _ := req.Resource.Properties["kind"].(string)
		if !slices.Contains([]string{"function", "mcp", "http", "other"}, kind) {
			return cedar.Request{}, nil, fmt.Errorf("tool kind %q", kind)
		}
		attrs["kind"] = types.String(kind)
		if server, ok := req.Resource.Properties["server"].(string); ok {
			attrs["server"] = types.String(server)
		}
	case "model":
		if provider, ok := req.Resource.Properties["provider"].(string); ok {
			attrs["provider"] = types.String(provider)
		}
	}
	if req.Resource.Type != "agent" {
		entities[resourceUID] = types.Entity{UID: resourceUID, Attributes: types.NewRecord(attrs)}
	}

	ctx := types.RecordMap{"time": types.NewDatetime(at.UTC())}
	if req.Context.TaskID != "" {
		ctx["task_id"] = types.String(req.Context.TaskID)
	}
	if req.Context.TraceID != "" {
		ctx["trace_id"] = types.String(req.Context.TraceID)
	}
	if req.Context.OnBehalfOf != "" {
		ctx["on_behalf_of"] = types.String(req.Context.OnBehalfOf)
	}
	if req.Context.Args != nil {
		if want != "tool" {
			return cedar.Request{}, nil, errors.New("args are allowed on tool actions only")
		}
		args, err := toValue(req.Context.Args)
		if err != nil {
			return cedar.Request{}, nil, fmt.Errorf("context.args: %w", err)
		}
		ctx["args"] = args
	}

	return cedar.Request{
		Principal: principalUID,
		Action:    types.NewEntityUID("WhiteTower::Action", types.String(req.Action.Name)),
		Resource:  resourceUID,
		Context:   types.NewRecord(ctx),
	}, entities, nil
}

// toValue converts a decoded JSON value to a Cedar value. Numbers must be
// integers: the profile has no decimal attributes.
func toValue(v any) (types.Value, error) {
	switch x := v.(type) {
	case string:
		return types.String(x), nil
	case bool:
		return types.Boolean(x), nil
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			return nil, fmt.Errorf("number %s is not an integer", x)
		}
		return types.Long(n), nil
	case float64:
		if x != math.Trunc(x) || x > math.MaxInt64 || x < math.MinInt64 {
			return nil, fmt.Errorf("number %v is not an integer", x)
		}
		return types.Long(int64(x)), nil
	case []any:
		items := make([]types.Value, 0, len(x))
		for _, item := range x {
			cv, err := toValue(item)
			if err != nil {
				return nil, err
			}
			items = append(items, cv)
		}
		return types.NewSet(items...), nil
	case map[string]any:
		rec := types.RecordMap{}
		for k, item := range x {
			cv, err := toValue(item)
			if err != nil {
				return nil, err
			}
			rec[types.String(k)] = cv
		}
		return types.NewRecord(rec), nil
	default:
		return nil, fmt.Errorf("unsupported JSON value %v", v)
	}
}

// GateState is what an enforcement point's gate looks at for one agent
// (section 5.4).
type GateState struct {
	// A complete snapshot has been applied since the instance started.
	StateReceived bool `json:"state_received"`
	// The agent's lease has not expired.
	LeaseValid bool `json:"lease_valid"`
	// An agent or selector halt covers the agent.
	AgentHalted bool `json:"agent_halted"`
	// A fleet halt is active.
	FleetHalted bool `json:"fleet_halted"`
	// The lifecycle state, in lower case ("active", "suspended" and so on).
	LifecycleState string `json:"lifecycle_state"`
	// A verified bundle is active for the agent.
	BundleActive bool `json:"bundle_active"`
	// The evidence buffer cannot accept another event.
	EvidenceBufferFull bool `json:"evidence_buffer_full"`
}

// GateReason returns why the gate is closed, or "" when it is open. When
// several conditions hold, the first one in the contract's order is reported
// (section 5.4).
func GateReason(s GateState) string {
	switch {
	case !s.StateReceived:
		return ReasonNoState
	case !s.LeaseValid:
		return ReasonLeaseExpired
	case s.AgentHalted:
		return ReasonHalted
	case s.FleetHalted:
		return ReasonFleetHalted
	case !GateOpensIn(s.LifecycleState):
		return ReasonLifecycle
	case !s.BundleActive:
		return ReasonNoBundle
	case s.EvidenceBufferFull:
		return ReasonEvidenceFull
	default:
		return ""
	}
}

// GateOpensIn reports whether a lifecycle state lets the gate open. Unknown
// states keep it closed.
func GateOpensIn(lifecycleState string) bool {
	switch lifecycleState {
	case "validated", "ready", "active":
		return true
	default:
		return false
	}
}
