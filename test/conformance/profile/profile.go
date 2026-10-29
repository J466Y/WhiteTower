// Package profile implements the White Tower decision profile v1alpha1 for
// Cedar: it checks that an AuthZEN evaluation request is inside the profile,
// maps it to a Cedar request, applies the contract's rules on top of Cedar's,
// and computes the gate (docs/contracts/module-contract-v0.1.md, sections 5
// and 6).
//
// It is the reference the conformance vectors are checked against, and a
// starting point for enforcement points written in Go.
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/J466Y/WhiteTower/api/policy"
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

// Context is the request's context. It has no on_behalf_of: a v1alpha1
// request never carries it (section 6.4).
type Context struct {
	Time    string         `json:"time"`
	TaskID  string         `json:"task_id,omitempty"`
	TraceID string         `json:"trace_id,omitempty"`
	Args    map[string]any `json:"args,omitempty"`
}

// TimeLayout is the form of the context's time: RFC 3339, in UTC, with
// milliseconds (section 1).
const TimeLayout = "2006-01-02T15:04:05.000Z"

// The rules of the profile that decision-request.schema.json does not state
// (section 6.6, "Requests outside the profile"). ToCedar refuses a request
// that breaks one with an error that wraps it, and Evaluate denies that
// request with error.invalid_request, as it denies one that does not match the
// schema.
var (
	// ErrAnotherAgent refuses an agent action whose resource is not the
	// requesting agent (section 6.3).
	ErrAnotherAgent = errors.New("an agent action names another agent (section 6.3)")
	// ErrNotAnInteger refuses a number of the arguments that is not a signed
	// 64-bit integer written without a fraction or an exponent (sections 6.4
	// and 6.7).
	ErrNotAnInteger = errors.New("a number is not a signed 64-bit integer written without a fraction or an exponent (sections 6.4 and 6.7)")
	// ErrTime refuses a time that is not in the form of section 1, or that
	// does not exist, such as February 29 of a year that is not a leap year:
	// the schema's pattern checks the form only.
	ErrTime = errors.New("the time is not an existing time of RFC 3339, in UTC, with milliseconds (section 1)")
)

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
	// schema is decision-request.schema.json, compiled.
	schema *jsonschema.Schema
}

// requestSchemaURL places the embedded request schema at a URL, from which
// the compiler resolves its references. Nothing is fetched from it.
const requestSchemaURL = "file:///whitetower/policy/decision-request.schema.json"

// NewEngine parses the policies of a bundle. A policy that does not parse
// rejects the whole bundle: an enforcement point never runs part of a bundle.
func NewEngine(agentID string, bundleVersion uint64, policies []Policy) (*Engine, error) {
	schema, err := compileRequestSchema()
	if err != nil {
		return nil, fmt.Errorf("decision-request.schema.json: %w", err)
	}
	e := &Engine{
		agentID:       agentID,
		bundleVersion: bundleVersion,
		set:           cedar.NewPolicySet(),
		owners:        map[cedar.PolicyID]string{},
		schema:        schema,
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

// compileRequestSchema compiles the request schema that api/policy embeds.
func compileRequestSchema() (*jsonschema.Schema, error) {
	data, err := policy.Files.ReadFile("decision-request.schema.json")
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(requestSchemaURL, doc); err != nil {
		return nil, err
	}
	return compiler.Compile(requestSchemaURL)
}

// Evaluate decides one request, given as its JSON text, with the combining
// algorithm wt-deny-overrides-v1 (section 6.5). The gate is not part of the
// engine: callers check it first. Then come, in the order of section 6.6:
// error.unknown_agent, for a request whose subject is not the bundle's agent
// or cannot be read; error.invalid_request, for a request outside the
// profile, which does not match decision-request.schema.json or breaks a rule
// that the schema does not state; then rules 1 to 4.
func (e *Engine) Evaluate(data []byte) Response {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil || !e.isFor(doc) {
		return Deny(ReasonUnknownAgent)
	}
	if err := e.schema.Validate(doc); err != nil {
		return Deny(ReasonInvalidRequest)
	}
	req, err := DecodeRequest(data)
	if err != nil {
		return Deny(ReasonInvalidRequest)
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

// isFor reports whether a request, decoded as jsonschema.UnmarshalJSON
// decodes it, is for the bundle's agent: its subject is an agent with the
// bundle's agent ID (section 6.6). It reads the subject alone, before the
// request is checked against the profile, so that a request for another agent
// is refused as such even when it is outside the profile too.
func (e *Engine) isFor(doc any) bool {
	req, _ := doc.(map[string]any)
	subject, _ := req["subject"].(map[string]any)
	return subject["type"] == "agent" && subject["id"] == e.agentID
}

// DecodeRequest decodes a request from its JSON text, every number as a
// json.Number, so that no integer passes through a float (section 6.4). It
// does not check that the request is inside the profile: Evaluate does.
func DecodeRequest(data []byte) (Request, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, err
	}
	return req, nil
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
// needs (section 6.7). It refuses a request that breaks a rule the schema does
// not state with an error that wraps the rule: ErrAnotherAgent,
// ErrNotAnInteger or ErrTime.
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
	at, err := time.Parse(TimeLayout, req.Context.Time)
	if err != nil {
		return cedar.Request{}, nil, fmt.Errorf("context.time: %w: %w", ErrTime, err)
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
			return cedar.Request{}, nil, ErrAnotherAgent
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

// toValue converts a JSON value that DecodeRequest decoded to a Cedar value.
// A number is a json.Number, which keeps the number's text: it must be a
// signed 64-bit integer, Cedar's Long, written without a fraction or an
// exponent (sections 6.4 and 6.7). Any other number, a float64 included,
// makes the request invalid.
func toValue(v any) (types.Value, error) {
	switch x := v.(type) {
	case string:
		return types.String(x), nil
	case bool:
		return types.Boolean(x), nil
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrNotAnInteger, x)
		}
		return types.Long(n), nil
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
	// The agent is in the state applied: it has not left the instance's
	// scope since a snapshot or a change brought it in (I-11).
	AgentInState bool `json:"agent_in_state"`
	// The agent's lease has not expired.
	LeaseValid bool `json:"lease_valid"`
	// An agent or selector halt covers the agent.
	AgentHalted bool `json:"agent_halted"`
	// A fleet halt is active.
	FleetHalted bool `json:"fleet_halted"`
	// The lifecycle state, in lower case ("active", "suspended" and so on).
	LifecycleState string `json:"lifecycle_state"`
	// The environment that the registration returned: "production" or
	// "non_production" (section 6.2).
	Environment string `json:"environment"`
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
	case !s.StateReceived || !s.AgentInState:
		return ReasonNoState
	case !s.LeaseValid:
		return ReasonLeaseExpired
	case s.AgentHalted:
		return ReasonHalted
	case s.FleetHalted:
		return ReasonFleetHalted
	case !GateOpensIn(s.LifecycleState, s.Environment):
		return ReasonLifecycle
	case !s.BundleActive:
		return ReasonNoBundle
	case s.EvidenceBufferFull:
		return ReasonEvidenceFull
	default:
		return ""
	}
}

// GateOpensIn reports whether a lifecycle state lets the gate open, for an
// enforcement point whose registration returned the environment given (row 5
// of section 5.4, EP-6). The active state opens with either environment, and
// validated and ready only with non_production, so that no decision is
// labeled production for an agent that is not active. An unknown state, or an
// environment that is neither, keeps the gate closed (EP-10).
func GateOpensIn(lifecycleState, environment string) bool {
	switch {
	case environment != "production" && environment != "non_production":
		return false
	case lifecycleState == "active":
		return true
	case lifecycleState == "validated", lifecycleState == "ready":
		return environment == "non_production"
	default:
		return false
	}
}
