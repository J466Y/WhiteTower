package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/J466Y/WhiteTower/test/conformance/tooling"
)

// The reasons of the catalog check (section 6.9).
const (
	ReasonBlocked           = "catalog.blocked"
	ReasonUnknown           = "catalog.unknown"
	ReasonNotApproved       = "catalog.not_approved"
	ReasonNotEnabled        = "catalog.not_enabled"
	ReasonDefinitionChanged = "catalog.definition_changed"
	ReasonDigestMismatch    = "catalog.digest_mismatch"
)

// Block is an active block, as an enforcement point holds it from the blocks
// record of its watch stream (section 5.10).
type Block struct {
	ID string
	// Kind is server, tool, model, provider or endpoint. A block of any other
	// kind covers every tool and every model (EP-10, EP-15).
	Kind string
	// CoveredSHA256 is the lowercase hexadecimal SHA-256 of the UTF-8 bytes
	// of the string form of what the block covers.
	CoveredSHA256 string
}

// blockKinds are the kinds of blocks that section 5.10 names.
var blockKinds = []string{"server", "tool", "model", "provider", "endpoint"}

// Tooling is the tool or the model of a call as an enforcement point has it
// at the time of the call. The enforcement point computes its strings when
// the agent's tool list or model changes, never on each call, with the
// redaction rules of the bundle's catalog (sections 4.10 and 5.10).
type Tooling struct {
	// Name is the tool's name as the agent sees it, or the model's name as
	// requested: the resource's ID when the catalog does not list it (section
	// 6.3).
	Name string
	// Reference is the string form of its reference, empty when it makes none
	// (section 4.10).
	Reference string
	// Server is the reference of an MCP tool's server, empty for any other
	// tool, or when the server makes none.
	Server string
	// Provider is a model's provider, and Endpoint the base URL of its
	// endpoint, normalized and redacted, empty when it makes none.
	Provider string
	Endpoint string
	// Origin is who runs a tool at the time of the call: agent or provider.
	// It can differ from the origin that the catalog records, which stays
	// the resource's property (section 6.3).
	Origin string
	// Definition is the hash of a tool's definition as the agent has it now,
	// empty when it has none.
	Definition string
	// Digest is the digest of a model's weights as the runtime reports it,
	// empty when it reports none.
	Digest string
}

// Call is a tool or model action as an enforcement point has it once its gate
// is open (section 5.4).
type Call struct {
	// Subject is the agent, as the enforcement point builds it from its state
	// and its registration (section 6.2).
	Subject Subject
	// Action is tool.expose, tool.invoke, tool.result, model.invoke or
	// model.result.
	Action string
	// Time is the request's time, in the form of section 1.
	Time    string
	Tooling Tooling
	// Arguments are a tool call's arguments as JSON text, nil when the call
	// has none (EP-19).
	Arguments []byte
	// Approval says whether the model provider submits each call of a
	// provider-run tool to the agent for approval (EP-18).
	Approval bool
}

// Decision is the decision on a Call, with what its event names of the tool or
// the model (sections 8.3 and 8.5).
type Decision struct {
	Response
	// ResourceID is the resource's ID, once the decision reached the catalog
	// check: the entry's key or, for tooling that the catalog does not list,
	// its name.
	ResourceID string
	// ReferenceSHA256 is the SHA-256 of the reference of tooling that the
	// catalog does not list, empty when it makes none (EP-16).
	ReferenceSHA256 string
	// BlockIDs are the active blocks that cover the call, in their order. A
	// catalog.blocked decision names any one of them (EP-16).
	BlockIDs []string
	// Request is the request that Evaluate decided, nil when the decision
	// came before it.
	Request *Request
	// Rules are the usage rules that a policy.forbid decision names (section
	// 6.11).
	Rules []NamedRule
}

// Decide decides a tool or model action once the gate is open, in the order
// of section 6.6: error.unknown_agent, for a subject that is not the bundle's
// agent; the catalog check of section 6.9, on the bundle's catalog, nil when
// the bundle has none, which reads as an empty catalog, and the active blocks;
// for tool.invoke and tool.result, EP-19's record of the call's arguments,
// error.invalid_request when the arguments do not fit their declarations;
// then Evaluate, on the request whose resource is the catalog's entry (section
// 6.3) and whose context carries the record, calls_decided on tool.expose and
// the runtime's digest on model.invoke.
func (e *Engine) Decide(catalog *tooling.Catalog, blocks []Block, call Call) Decision {
	if call.Subject.Type != "agent" || call.Subject.ID != e.agentID {
		return Decision{Response: Deny(ReasonUnknownAgent)}
	}
	resourceType := actionResource[call.Action]
	if resourceType != "tool" && resourceType != "model" {
		return Decision{Response: Deny(ReasonInvalidRequest)}
	}
	if catalog == nil {
		catalog = &tooling.Catalog{}
	}
	t := call.Tooling
	d := Decision{BlockIDs: covering(blocks, resourceType, t)}
	// Tooling that the catalog does not list is named by its name.
	resource := Resource{Type: resourceType, ID: t.Name}
	var declared []tooling.Argument
	var reason string
	var tool *tooling.CatalogTool
	var model *tooling.CatalogModel
	if resourceType == "tool" {
		tool = findTool(catalog, t.Reference)
	} else {
		model = findModel(catalog, t.Reference)
	}
	switch {
	case tool != nil:
		resource.ID, resource.Properties, declared = tool.Key, ToolProperties(catalog, tool), tool.Args
		reason = entryReason(tool.Status, tool.Enabled)
		// A built-in tool has no definition, in the catalog or as the agent
		// has it, so row 5 never denies it (section 4.10).
		if reason == "" && tool.Definition != t.Definition {
			reason = ReasonDefinitionChanged
		}
	case model != nil:
		resource.ID, resource.Properties = model.Key, ModelProperties(model)
		reason = entryReason(model.Status, model.Enabled)
		if reason == "" && model.Digest != "" && model.Digest != t.Digest {
			reason = ReasonDigestMismatch
		}
	default:
		if t.Reference != "" {
			sum := sha256.Sum256([]byte(t.Reference))
			d.ReferenceSHA256 = hex.EncodeToString(sum[:])
		}
		reason = ReasonUnknown
	}
	d.ResourceID = resource.ID
	switch {
	case len(d.BlockIDs) > 0:
		reason = ReasonBlocked
	case call.Action == "tool.result" || call.Action == "model.result":
		// Only row 1 applies to results: a result of tooling that the
		// catalog does not list has no properties, and the profile refuses
		// its request.
		reason = ""
	}
	if reason != "" {
		d.Response = Response{Context: ResponseContext{Reason: reason, Policies: []string{}, BundleVersion: e.bundleVersion}}
		return d
	}

	req := Request{Subject: call.Subject, Action: Action{Name: call.Action}, Resource: resource, Context: Context{Time: call.Time}}
	switch call.Action {
	case "tool.invoke", "tool.result":
		record, err := tooling.Record(call.Arguments, declared)
		if err != nil {
			d.Response = Deny(ReasonInvalidRequest)
			return d
		}
		req.Context.Args = map[string]any{resource.ID: record}
	case "tool.expose":
		// Every call of the tool is decided when the agent runs it, or
		// while the provider submits each of its calls for approval
		// (section 6.10): who runs it when it is offered decides, never
		// the origin that the catalog records.
		decided := t.Origin == "agent" || call.Approval
		req.Context.CallsDecided = &decided
	case "model.invoke":
		req.Context.Digest = t.Digest
	}
	d.Request = &req
	data, err := json.Marshal(req)
	if err != nil {
		d.Response = Deny(ReasonInvalidRequest)
		return d
	}
	d.Response, d.Rules = e.evaluate(data)
	return d
}

// covering returns the IDs of the blocks that cover a tool or a model, in
// their order: a server block covers an MCP tool's server and a tool block the
// tool; a model block covers the model, and a provider or an endpoint block
// its provider or its endpoint. A block of a kind that section 5.10 does not
// name covers every tool and every model.
func covering(blocks []Block, resourceType string, t Tooling) []string {
	covered := map[string]string{"server": t.Server, "tool": t.Reference}
	if resourceType == "model" {
		covered = map[string]string{"model": t.Reference, "provider": t.Provider, "endpoint": t.Endpoint}
	}
	var ids []string
	for _, b := range blocks {
		s := covered[b.Kind]
		sum := sha256.Sum256([]byte(s))
		if !slices.Contains(blockKinds, b.Kind) || s != "" && hex.EncodeToString(sum[:]) == b.CoveredSHA256 {
			ids = append(ids, b.ID)
		}
	}
	return ids
}

// findTool returns the catalog's tool whose reference is the one given, or
// nil: the tool is resolved by its reference, never by its name alone
// (EP-16), and the catalog never lists two tools with one reference (section
// 7.7). An enforcement point indexes the catalog once per bundle; the
// reference implementation reads it on each call.
func findTool(c *tooling.Catalog, reference string) *tooling.CatalogTool {
	for i := range c.Tools {
		if ref, ok := c.ToolReference(&c.Tools[i]); ok && ref == reference {
			return &c.Tools[i]
		}
	}
	return nil
}

// findModel returns the catalog's model whose reference is the one given, or
// nil.
func findModel(c *tooling.Catalog, reference string) *tooling.CatalogModel {
	for i := range c.Models {
		if ref, err := c.ModelReference(&c.Models[i]); err == nil && ref == reference {
			return &c.Models[i]
		}
	}
	return nil
}

// entryReason returns the reason of rows 3 and 4 of the catalog check for an
// entry that the catalog lists, or "".
func entryReason(status string, enabled bool) string {
	switch {
	case status != "approved":
		return ReasonNotApproved
	case !enabled:
		return ReasonNotEnabled
	}
	return ""
}

// ToolProperties returns the properties that a tool's entry gives the
// resource of a request (section 6.3): its kind, origin, name and
// classification; an MCP tool's server, by its key, and the server's
// transport; and a built-in tool's provider.
func ToolProperties(c *tooling.Catalog, t *tooling.CatalogTool) map[string]any {
	properties := map[string]any{
		"kind": t.Kind, "origin": t.Origin, "name": t.Name,
		"read_only": t.ReadOnly, "destructive": t.Destructive, "open_world": t.OpenWorld,
	}
	switch t.Kind {
	case "mcp":
		properties["server"] = t.Server
		if server := c.Server(t.Server); server != nil {
			properties["transport"] = server.Transport
		}
	case "builtin":
		properties["provider"] = t.Provider
	}
	return properties
}

// ModelProperties returns the properties that a model's entry gives the
// resource of a request: its provider, name and endpoint (section 6.3).
func ModelProperties(m *tooling.CatalogModel) map[string]any {
	return map[string]any{"provider": m.Provider, "name": m.Name, "endpoint": m.Endpoint}
}
