package contracts

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// validCatalog returns a catalog file of section 7.7: an approved MCP tool
// with an argument, a discovered built-in tool, a discovered function, a
// model with its digest, and redaction rules.
func validCatalog(t *testing.T) map[string]any {
	t.Helper()
	var c map[string]any
	if err := json.Unmarshal([]byte(`{
		"format": "whitetower.catalog.v1",
		"redaction": {"url_prefixes": ["https://mcp.example.net/s/", "http://[::1]:8080/a/b/"], "flags": ["pat"]},
		"servers": [{"key": "github", "reference": "https://api.githubcopilot.com/mcp/", "transport": "http", "status": "approved"}],
		"tools": [
			{"key": "github/create_pull_request", "server": "github", "name": "create_pull_request", "kind": "mcp", "origin": "agent",
			 "status": "approved", "enabled": true, "definition": "4d1c000000000000000000000000000000000000000000000000000000000000",
			 "read_only": false, "destructive": false, "open_world": true,
			 "args": [{"name": "base", "path": ["base"], "type": "String"}]},
			{"key": "provider.openai/web_search", "provider": "openai", "type": "web_search", "name": "web_search", "kind": "builtin",
			 "origin": "provider", "status": "discovered", "enabled": false, "read_only": true, "destructive": false, "open_world": true},
			{"key": "agent/send_email", "name": "send_email", "kind": "function", "origin": "agent",
			 "status": "discovered", "enabled": false, "read_only": false, "destructive": true, "open_world": true}
		],
		"models": [{"key": "gpu-01/llama3.1-8b", "provider": "ollama", "endpoint": "http://gpu-01.internal:11434/",
		            "name": "llama3.1:8b", "status": "approved", "enabled": true, "digest": "46e0"}]
	}`), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// entry returns the i-th entry of one of the catalog's lists.
func entry(c map[string]any, list string, i int) map[string]any {
	return c[list].([]any)[i].(map[string]any)
}

// withArgument declares one argument for the MCP tool.
func withArgument(arg map[string]any) func(map[string]any) {
	return func(c map[string]any) { entry(c, "tools", 0)["args"] = []any{arg} }
}

// withRedaction sets one of the redaction rules to a single value.
func withRedaction(rule, value string) func(map[string]any) {
	return func(c map[string]any) { c["redaction"].(map[string]any)[rule] = []any{value} }
}

// TestTheCatalogSchemaFollowsSection77 checks the rules of section 7.7 that
// catalog.schema.json states: the members each kind of tool carries, the
// definition that approval pins, the five argument types and the transforms
// that apply to strings, and the forms of the redaction rules.
func TestTheCatalogSchemaFollowsSection77(t *testing.T) {
	sch := compile(t, api+"/policy/catalog.schema.json")
	cases := []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{name: "a catalog file of section 7.7", edit: func(map[string]any) {}, valid: true},
		{name: "an empty catalog file", valid: true, edit: func(c map[string]any) {
			c["redaction"] = map[string]any{"url_prefixes": []any{}, "flags": []any{}}
			c["servers"], c["tools"], c["models"] = []any{}, []any{}, []any{}
		}},
		{name: "no redaction rules", edit: func(c map[string]any) { delete(c, "redaction") }},
		{name: "an unknown member", edit: func(c map[string]any) { c["blocks"] = []any{} }},
		{name: "a status of blocked", edit: func(c map[string]any) { entry(c, "servers", 0)["status"] = "blocked" }},
		{name: "a server with enabled", edit: func(c map[string]any) { entry(c, "servers", 0)["enabled"] = true }},
		{name: "a server key in uppercase", edit: func(c map[string]any) { entry(c, "servers", 0)["key"] = "GitHub" }},
		{name: "a model without its endpoint", edit: func(c map[string]any) { delete(entry(c, "models", 0), "endpoint") }},
		{name: "a tool without its classification", edit: func(c map[string]any) { delete(entry(c, "tools", 2), "read_only") }},

		{name: "an MCP tool without its server", edit: func(c map[string]any) { delete(entry(c, "tools", 0), "server") }},
		{name: "an MCP tool with a provider", edit: func(c map[string]any) { entry(c, "tools", 0)["provider"] = "openai" }},
		{name: "an approved MCP tool without its definition", edit: func(c map[string]any) { delete(entry(c, "tools", 0), "definition") }},
		{name: "a built-in tool without its type", edit: func(c map[string]any) { delete(entry(c, "tools", 1), "type") }},
		{name: "a built-in tool with a server", edit: func(c map[string]any) { entry(c, "tools", 1)["server"] = "github" }},
		{name: "a built-in tool with a definition", edit: func(c map[string]any) {
			entry(c, "tools", 1)["definition"] = entry(c, "tools", 0)["definition"]
		}},
		{name: "an approved built-in tool", valid: true, edit: func(c map[string]any) { entry(c, "tools", 1)["status"] = "approved" }},
		{name: "a function with a provider", edit: func(c map[string]any) { entry(c, "tools", 2)["provider"] = "openai" }},
		{name: "an approved function without its definition", edit: func(c map[string]any) { entry(c, "tools", 2)["status"] = "approved" }},

		{name: "an argument of each type", valid: true, edit: func(c map[string]any) {
			entry(c, "tools", 0)["args"] = []any{
				map[string]any{"name": "a", "path": []any{"a"}, "type": "Long"},
				map[string]any{"name": "b.c", "path": []any{"b", "c"}, "type": "Bool"},
				map[string]any{"name": "d", "path": []any{"d"}, "type": "Set<String>"},
				map[string]any{"name": "e", "path": []any{"e"}, "type": "Set<Long>"},
			}
		}},
		{name: "an argument of the type Set<Bool>", edit: withArgument(map[string]any{"name": "a", "path": []any{"a"}, "type": "Set<Bool>"})},
		{name: "a transform of a set of strings", valid: true, edit: withArgument(map[string]any{
			"name": "a:url_host", "path": []any{"a"}, "transform": "url_host", "type": "Set<String>",
		})},
		{name: "a transform of a Long", edit: withArgument(map[string]any{"name": "a:lowercase", "path": []any{"a"}, "transform": "lowercase", "type": "Long"})},
		{name: "an unknown transform", edit: withArgument(map[string]any{"name": "a:upper", "path": []any{"a"}, "transform": "upper", "type": "String"})},
		{name: "a property name with a dot", edit: withArgument(map[string]any{"name": "a.b", "path": []any{"a.b"}, "type": "String"})},
		{name: "a property name with a colon", edit: withArgument(map[string]any{"name": "a", "path": []any{"a:b"}, "type": "String"})},
		{name: "an empty path", edit: withArgument(map[string]any{"name": "a", "path": []any{}, "type": "String"})},

		{name: "a URL prefix without its last slash", edit: withRedaction("url_prefixes", "https://mcp.example.net/s")},
		{name: "a URL prefix with a query", edit: withRedaction("url_prefixes", "https://mcp.example.net/s/?a=1/")},
		{name: "a URL prefix with user information", edit: withRedaction("url_prefixes", "https://u@mcp.example.net/s/")},
		{name: "a URL prefix of another scheme", edit: withRedaction("url_prefixes", "ftp://mcp.example.net/s/")},
		{name: "a URL prefix with a host in uppercase", edit: withRedaction("url_prefixes", "https://MCP.example.net/s/")},
		{name: "a flag with its leading dashes", edit: withRedaction("flags", "--pat")},
		{name: "a flag with =", edit: withRedaction("flags", "pat=")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCatalog(t)
			tc.edit(c)
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			err = sch.Validate(inst)
			switch {
			case tc.valid && err != nil:
				t.Errorf("refused, but section 7.7 allows it: %v", err)
			case !tc.valid && err == nil:
				t.Error("accepted, but section 7.7 refuses it")
			}
		})
	}
}
