package contracts

import (
	"fmt"
	"strings"
	"testing"
)

// validRequest returns a decision request inside the profile: a tool call
// with the tool's record of arguments, from an agent with labels and data
// categories.
func validRequest() map[string]any {
	return map[string]any{
		"subject": map[string]any{
			"type": "agent",
			"id":   "0192f1c2-7a3b-7c4d-8e5f-000000000001",
			"properties": map[string]any{
				"slug":            "invoice-triage",
				"kind":            "in_house",
				"risk_tier":       "high",
				"environment":     "production",
				"data_categories": []any{"customer data", "financial data"},
				"owner":           "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
				"labels":          map[string]any{"team": "finance"},
			},
		},
		"action":   map[string]any{"name": "tool.invoke"},
		"resource": map[string]any{"type": "tool", "id": "agent/send_email", "properties": functionTool()},
		"context": map[string]any{
			"time": "2026-09-29T10:15:02.118Z",
			"args": map[string]any{"agent/send_email": map[string]any{"to:email_domain": "example.org"}},
		},
	}
}

// functionTool returns the properties of one of the agent's own tools, as the
// catalog gives them (section 6.3).
func functionTool() map[string]any {
	return map[string]any{
		"kind": "function", "origin": "agent", "name": "send_email",
		"read_only": false, "destructive": true, "open_world": true,
	}
}

// mcpTool returns the properties of an MCP tool, with its server and its
// transport.
func mcpTool() map[string]any {
	return map[string]any{
		"kind": "mcp", "origin": "agent", "name": "create_pull_request",
		"read_only": false, "destructive": false, "open_world": true, "server": "github", "transport": "http",
	}
}

// builtinTool returns the properties of a built-in tool, with its provider.
func builtinTool() map[string]any {
	return map[string]any{
		"kind": "builtin", "origin": "provider", "name": "web_search",
		"read_only": true, "destructive": false, "open_world": true, "provider": "openai",
	}
}

func subjectProperties(req map[string]any) map[string]any {
	return req["subject"].(map[string]any)["properties"].(map[string]any)
}

func requestContext(req map[string]any) map[string]any {
	return req["context"].(map[string]any)
}

func resourceProperties(req map[string]any) map[string]any {
	return req["resource"].(map[string]any)["properties"].(map[string]any)
}

// all applies edits in turn.
func all(edits ...func(map[string]any)) func(map[string]any) {
	return func(req map[string]any) {
		for _, edit := range edits {
			edit(req)
		}
	}
}

// withLabels gives the agent n labels.
func withLabels(n int) func(map[string]any) {
	return func(req map[string]any) {
		labels := map[string]any{}
		for i := range n {
			labels[fmt.Sprintf("label-%d", i)] = "value"
		}
		subjectProperties(req)["labels"] = labels
	}
}

// withLabelValue gives the agent's label a value.
func withLabelValue(value string) func(map[string]any) {
	return func(req map[string]any) {
		subjectProperties(req)["labels"] = map[string]any{"team": value}
	}
}

// withCategories gives the agent n data categories.
func withCategories(n int) func(map[string]any) {
	return func(req map[string]any) {
		categories := make([]any, 0, n)
		for i := range n {
			categories = append(categories, fmt.Sprintf("category %d", i))
		}
		subjectProperties(req)["data_categories"] = categories
	}
}

// withCategory gives the agent one data category.
func withCategory(category string) func(map[string]any) {
	return func(req map[string]any) {
		subjectProperties(req)["data_categories"] = []any{category}
	}
}

// withContext sets a member of the request's context.
func withContext(name string, value any) func(map[string]any) {
	return func(req map[string]any) {
		requestContext(req)[name] = value
	}
}

// withoutContext removes a member of the request's context.
func withoutContext(name string) func(map[string]any) {
	return func(req map[string]any) {
		delete(requestContext(req), name)
	}
}

// withAction sets the request's action.
func withAction(name string) func(map[string]any) {
	return func(req map[string]any) {
		req["action"] = map[string]any{"name": name}
	}
}

// withTool makes the request a call of the tool given, with an empty record.
func withTool(id string, properties map[string]any) func(map[string]any) {
	return func(req map[string]any) {
		req["resource"] = map[string]any{"type": "tool", "id": id, "properties": properties}
		requestContext(req)["args"] = map[string]any{id: map[string]any{}}
	}
}

// withProperty sets a property of the request's resource, or removes it when
// the value is nil.
func withProperty(name string, value any) func(map[string]any) {
	return func(req map[string]any) {
		if value == nil {
			delete(resourceProperties(req), name)
			return
		}
		resourceProperties(req)[name] = value
	}
}

// withRecord sets the record of the request's tool.
func withRecord(record map[string]any) func(map[string]any) {
	return func(req map[string]any) {
		requestContext(req)["args"] = map[string]any{"agent/send_email": record}
	}
}

// asModelCall makes the request a model.invoke of a model, as the catalog
// gives it.
func asModelCall(req map[string]any) {
	req["action"] = map[string]any{"name": "model.invoke"}
	req["resource"] = map[string]any{"type": "model", "id": "gpu-01/llama3.1-8b", "properties": map[string]any{
		"provider": "ollama", "name": "llama3.1:8b", "endpoint": "http://gpu-01.internal:11434/",
	}}
	delete(requestContext(req), "args")
}

// asExposure makes the request the offer of the tool to a model, whose calls
// are decided.
func asExposure(req map[string]any) {
	req["action"] = map[string]any{"name": "tool.expose"}
	delete(requestContext(req), "args")
	requestContext(req)["calls_decided"] = true
}

// TestTheDecisionRequestSchemaRefusesRequestsOutsideTheProfile checks the
// rules of sections 6.2 to 6.4 that the request schema states: a resource's
// properties come from the catalog, all of them; each action has the context
// fields of its own; a tool call carries exactly one record of arguments,
// whose values are never null; on_behalf_of is never present; and labels and
// data categories keep the inventory's bounds (CORE-17). Each refusal sits
// next to a request at the bound that the schema accepts.
func TestTheDecisionRequestSchemaRefusesRequestsOutsideTheProfile(t *testing.T) {
	sch := compile(t, api+"/policy/decision-request.schema.json")
	cases := []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{name: "a request inside the profile", edit: func(map[string]any) {}, valid: true},

		{name: "on_behalf_of with a name", edit: withContext("on_behalf_of", "0192f1c2-7a3b-7c4d-8e5f-0000000000a2")},
		{name: "on_behalf_of empty", edit: withContext("on_behalf_of", "")},
		{name: "on_behalf_of null", edit: withContext("on_behalf_of", nil)},

		// A tool's properties come from the catalog, and each kind has its
		// own (section 6.3).
		{name: "an MCP tool with its server and its transport", edit: withTool("github/create_pull_request", mcpTool()), valid: true},
		{name: "a built-in tool with its provider", edit: withTool("provider.openai/web_search", builtinTool()), valid: true},
		{name: "an http tool", edit: all(withTool("agent/fetch", functionTool()), withProperty("kind", "http")), valid: true},
		{name: "a tool of another kind", edit: all(withTool("agent/fetch", functionTool()), withProperty("kind", "other")), valid: true},
		{name: "a tool of an unknown kind", edit: withProperty("kind", "script")},
		{name: "a tool run by its provider", edit: withProperty("origin", "provider"), valid: true},
		{name: "a tool run by someone else", edit: withProperty("origin", "user")},
		{name: "a tool without its kind", edit: withProperty("kind", nil)},
		{name: "a tool without its origin", edit: withProperty("origin", nil)},
		{name: "a tool without its name", edit: withProperty("name", nil)},
		{name: "a tool with an empty name", edit: withProperty("name", "")},
		{name: "a tool without read_only", edit: withProperty("read_only", nil)},
		{name: "a tool without destructive", edit: withProperty("destructive", nil)},
		{name: "a tool without open_world", edit: withProperty("open_world", nil)},
		{name: "a classification that is not a boolean", edit: withProperty("read_only", "false")},
		{name: "a tool with a property the catalog does not give", edit: withProperty("description", "Sends an email")},
		{name: "a tool without its properties", edit: func(req map[string]any) {
			delete(req["resource"].(map[string]any), "properties")
		}},
		{name: "an MCP tool without its server", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("server", nil))},
		{name: "an MCP tool without its transport", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("transport", nil))},
		{name: "an MCP tool with a transport the profile does not have", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("transport", "sse"))},
		{name: "an MCP tool with a provider", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("provider", "openai"))},
		{name: "a server key of 63 characters", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("server", strings.Repeat("s", 63))), valid: true},
		{name: "a server key of 64 characters", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("server", strings.Repeat("s", 64)))},
		{name: "a server key with an uppercase letter", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("server", "GitHub"))},
		{name: "a server key followed by a line break", edit: all(withTool("github/create_pull_request", mcpTool()), withProperty("server", "github\n"))},
		{name: "a built-in tool without its provider", edit: all(withTool("provider.openai/web_search", builtinTool()), withProperty("provider", nil))},
		{name: "a built-in tool with a server", edit: all(withTool("provider.openai/web_search", builtinTool()), withProperty("server", "github"))},
		{name: "a function with a server", edit: withProperty("server", "github")},
		{name: "a function with a transport", edit: withProperty("transport", "stdio")},
		{name: "a function with a provider", edit: withProperty("provider", "openai")},

		// A model's properties, all three from the catalog, and the digest
		// that model.invoke may carry (sections 6.3 and 6.4).
		{name: "a model call", edit: asModelCall, valid: true},
		{name: "a model call with the runtime's digest", edit: all(asModelCall, withContext("digest", "sha256:46e0")), valid: true},
		{name: "a model call with an empty digest", edit: all(asModelCall, withContext("digest", ""))},
		{name: "a model's result with a digest", edit: all(asModelCall, withAction("model.result"), withContext("digest", "sha256:46e0"))},
		{name: "a tool call with a digest", edit: withContext("digest", "sha256:46e0")},
		{name: "a model without its provider", edit: all(asModelCall, withProperty("provider", nil))},
		{name: "a model without its name", edit: all(asModelCall, withProperty("name", nil))},
		{name: "a model without its endpoint", edit: all(asModelCall, withProperty("endpoint", nil))},
		{name: "a model with an empty endpoint", edit: all(asModelCall, withProperty("endpoint", ""))},
		{name: "a model with a property the catalog does not give", edit: all(asModelCall, withProperty("digest", "sha256:46e0"))},
		{name: "a model without its properties", edit: all(asModelCall, func(req map[string]any) {
			delete(req["resource"].(map[string]any), "properties")
		})},

		// The offer of a tool to a model carries calls_decided, and only it
		// (sections 6.4 and 6.10).
		{name: "an exposure whose calls are decided", edit: asExposure, valid: true},
		{name: "an exposure whose calls are not decided", edit: all(asExposure, withContext("calls_decided", false)), valid: true},
		{name: "an exposure without calls_decided", edit: all(asExposure, withoutContext("calls_decided"))},
		{name: "an exposure whose calls_decided is not a boolean", edit: all(asExposure, withContext("calls_decided", "true"))},
		{name: "an exposure with arguments", edit: all(asExposure, withContext("args", map[string]any{"agent/send_email": map[string]any{}}))},
		{name: "an exposure of a model", edit: all(asModelCall, withAction("tool.expose"), withContext("calls_decided", true))},
		{name: "a tool call with calls_decided", edit: withContext("calls_decided", true)},

		// A tool call carries exactly one record, the resource's own, whose
		// values are strings, booleans, integers and sets, never null
		// (sections 6.4 and 6.11). That the record is the resource's own is
		// the profile's rule, outside the schema.
		{name: "a record of each type", valid: true, edit: withRecord(map[string]any{
			"to:email_domain": "example.org", "urgent": false, "retries": 2,
			"cc:email_domain": []any{"example.org", "example.net"}, "line_ids": []any{1, 2}, "attachments": []any{},
		})},
		{name: "a record whose names are paths", valid: true, edit: withRecord(map[string]any{"options.base": "main", "options.url:url_host": "example.org"})},
		{name: "an empty record", edit: withRecord(map[string]any{}), valid: true},
		{name: "a tool's result with its record", edit: withAction("tool.result"), valid: true},
		{name: "a tool call without arguments", edit: withoutContext("args")},
		{name: "a tool's result without arguments", edit: all(withAction("tool.result"), withoutContext("args"))},
		{name: "arguments without a record", edit: withContext("args", map[string]any{})},
		{name: "arguments with two records", edit: withContext("args", map[string]any{
			"agent/send_email": map[string]any{}, "agent/read_invoice": map[string]any{},
		})},
		{name: "a record that is not an object", edit: withContext("args", map[string]any{"agent/send_email": "example.org"})},
		{name: "arguments on an agent action", edit: func(req map[string]any) {
			req["action"] = map[string]any{"name": "agent.start"}
			req["resource"] = map[string]any{"type": "agent", "id": "0192f1c2-7a3b-7c4d-8e5f-000000000001"}
		}},
		{name: "arguments on a model call", edit: all(asModelCall, withContext("args", map[string]any{"gpu-01/llama3.1-8b": map[string]any{}}))},
		{name: "a null argument", edit: withRecord(map[string]any{"to:email_domain": nil})},
		{name: "a null in an argument's array", edit: withRecord(map[string]any{"cc": []any{"a@example.org", nil}})},
		{name: "an object in a record", edit: withRecord(map[string]any{"options": map[string]any{"retries": 2}})},
		{name: "an object in an argument's array", edit: withRecord(map[string]any{"cc": []any{map[string]any{"to": "a@example.org"}}})},
		{name: "an array of strings and integers", edit: withRecord(map[string]any{"ids": []any{"1", 2}})},
		{name: "an array of booleans", edit: withRecord(map[string]any{"flags": []any{true, false}})},
		{name: "a number with a fraction", edit: withRecord(map[string]any{"amount": 2.5})},
		{name: "an argument named with a transform the profile does not have", edit: withRecord(map[string]any{"to:domain": "example.org"})},
		{name: "an argument named with two transforms", edit: withRecord(map[string]any{"to:lowercase:path": "example.org"})},

		{name: "64 labels", edit: withLabels(64), valid: true},
		{name: "65 labels", edit: withLabels(65)},
		{name: "a label value of 255 characters", edit: withLabelValue(strings.Repeat("a", 255)), valid: true},
		{name: "a label value of 256 characters", edit: withLabelValue(strings.Repeat("a", 256))},
		// U+1D49C takes 4 bytes in UTF-8 and 2 code units in UTF-16: the bound
		// counts characters, as the inventory does.
		{name: "a label value of 255 multi-byte characters", edit: withLabelValue(strings.Repeat("\U0001D49C", 255)), valid: true},

		{name: "32 data categories", edit: withCategories(32), valid: true},
		{name: "33 data categories", edit: withCategories(33)},
		{name: "a data category of 63 characters", edit: withCategory(strings.Repeat("c", 63)), valid: true},
		{name: "a data category of 64 characters", edit: withCategory(strings.Repeat("c", 64))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.edit(req)
			err := validate(t, sch, req)
			switch {
			case tc.valid && err != nil:
				t.Errorf("refused, but the request is inside the profile: %v", err)
			case !tc.valid && err == nil:
				t.Error("accepted, but the request is outside the profile")
			}
		})
	}
}
