package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// validReport returns a report that holds every kind of entry.
func validReport(agent uuid.UUID) Report {
	server := 0
	return Report{
		Agent: agent,
		Servers: []ReportedServer{
			{Reference: "https://api.githubcopilot.com/mcp/", Transport: "http", Origin: "agent", Name: "GitHub", Version: "1.0"},
			{Reference: `stdio:["npx","-y","server-fs"]`, Transport: "stdio", Origin: "agent", Display: "npx -y server-fs"},
			{Reference: "connector:openai/conn_1", Transport: "http", Origin: "provider"},
		},
		Tools: []ReportedTool{
			{Kind: "mcp", Origin: "agent", Server: &server, Name: "create_issue", Definition: strings.Repeat("ab", 32)},
			{Kind: "builtin", Origin: "provider", Provider: "openai", Type: "web_search", Name: "web_search"},
			{Kind: "function", Origin: "agent", Name: "send_email"},
		},
		Models: []ReportedModel{{Provider: "ollama", Endpoint: "http://gpu-01.internal:11434/", Name: "llama3.1:8b", Digest: "46e0"}},
	}
}

func TestAReportWithinItsLimitsIsValid(t *testing.T) {
	r := validReport(uuid.New())
	if err := r.validate(); err != nil {
		t.Fatal(err)
	}
	r.Servers = make([]ReportedServer, MaxReportServers)
	for i := range r.Servers {
		r.Servers[i] = ReportedServer{Reference: "https://s.example.com/" + strings.Repeat("a", maxReference-23), Transport: "http", Origin: "agent"}
	}
	r.Tools = make([]ReportedTool, MaxReportTools)
	for i := range r.Tools {
		r.Tools[i] = ReportedTool{Kind: "other", Origin: "agent", Name: strings.Repeat("é", maxName/2)}
	}
	r.Models = make([]ReportedModel, MaxReportModels)
	for i := range r.Models {
		r.Models[i] = ReportedModel{Provider: strings.Repeat("p", maxShort), Endpoint: "https://m.example.com/", Name: "m", Digest: strings.Repeat("d", maxShort)}
	}
	if err := r.validate(); err != nil {
		t.Fatalf("a report at its limits: %v", err)
	}
}

// A malformed report, or one over a limit, is refused as a whole before the
// catalog reads anything: a catalog without a database refuses it, and the
// detail names the member at fault, never what it holds.
func TestAMalformedReportIsRefusedAsAWholeBeforeAnythingIsRead(t *testing.T) {
	agent := uuid.New()
	other := 1
	for _, tt := range []struct {
		name   string
		edit   func(r *Report)
		detail string
	}{
		{"too many servers", func(r *Report) { r.Servers = make([]ReportedServer, MaxReportServers+1) }, "at most 256 servers"},
		{"too many tools", func(r *Report) { r.Tools = make([]ReportedTool, MaxReportTools+1) }, "at most 4096 tools"},
		{"too many models", func(r *Report) { r.Models = make([]ReportedModel, MaxReportModels+1) }, "at most 256 models"},
		{"a reference over 2 KiB", func(r *Report) { r.Servers[0].Reference += strings.Repeat("a", maxReference) }, "servers[0].reference: longer"},
		{"a server without a reference", func(r *Report) { r.Servers[0].Reference = "" }, "servers[0].reference: required"},
		{"an unknown transport", func(r *Report) { r.Servers[0].Transport = "ws" }, "servers[0].transport"},
		{"an unknown origin", func(r *Report) { r.Servers[0].Origin = "" }, "servers[0].origin"},
		{"a URL over stdio", func(r *Report) { r.Servers[0].Transport = "stdio" }, "servers[0].reference: not a reference"},
		{"a command line over http", func(r *Report) { r.Servers[1].Transport = "http" }, "servers[1].reference: not a reference"},
		{"a command line that is not JSON", func(r *Report) { r.Servers[1].Reference = "stdio:npx server-fs" }, "servers[1].reference"},
		{"an empty command line", func(r *Report) { r.Servers[1].Reference = "stdio:[]" }, "servers[1].reference"},
		{"a NUL in a display form", func(r *Report) { r.Servers[1].Display = "npx\x00" }, "servers[1].display: holds a NUL"},
		{"a noncharacter in a name", func(r *Report) { r.Servers[0].Name = "Git￾Hub" }, "servers[0].name: holds a noncharacter"},
		{"a noncharacter of another plane", func(r *Report) { r.Servers[0].Version = "\U0010FFFF" }, "servers[0].version: holds a noncharacter"},
		{"a lone surrogate", func(r *Report) { r.Servers[0].Name = "a\xed\xa0\x80" }, "servers[0].name: not UTF-8"},
		{"a version over 128 bytes", func(r *Report) { r.Servers[0].Version = strings.Repeat("1", maxShort+1) }, "servers[0].version: longer"},
		{"a tool without a name", func(r *Report) { r.Tools[2].Name = "" }, "tools[2].name: required"},
		{"a tool name over 256 bytes", func(r *Report) { r.Tools[2].Name = strings.Repeat("é", 129) }, "tools[2].name: longer"},
		{"a control character in a tool name", func(r *Report) { r.Tools[2].Name = "send\temail" }, "tools[2].name: holds a control character"},
		{"a DEL in a tool name", func(r *Report) { r.Tools[2].Name = "send\x7f" }, "tools[2].name: holds a control character"},
		{"an unknown kind", func(r *Report) { r.Tools[2].Kind = "skill" }, "tools[2].kind"},
		{"an MCP tool without its server", func(r *Report) { r.Tools[0].Server = nil }, "tools[0].server"},
		{"an MCP tool of no server of the report", func(r *Report) { r.Tools[0].Server = &[]int{3}[0] }, "tools[0].server"},
		{"a function naming a server", func(r *Report) { r.Tools[2].Server = &other }, "tools[2].server"},
		{"a function with a provider", func(r *Report) { r.Tools[2].Provider = "openai" }, "tools[2]: only a built-in tool"},
		{"a built-in tool with a definition", func(r *Report) { r.Tools[1].Definition = strings.Repeat("ab", 32) }, "tools[1].definition"},
		{"a built-in tool without a type", func(r *Report) { r.Tools[1].Type = "" }, "tools[1].type: required"},
		{"a control character in a provider", func(r *Report) { r.Tools[1].Provider = "open\nai" }, "tools[1].provider"},
		{"a definition hash in uppercase", func(r *Report) { r.Tools[0].Definition = strings.Repeat("AB", 32) }, "tools[0].definition"},
		{"a short definition hash", func(r *Report) { r.Tools[0].Definition = "abcd" }, "tools[0].definition"},
		{"a model without a provider", func(r *Report) { r.Models[0].Provider = "" }, "models[0].provider: required"},
		{"a model endpoint that is not a URL", func(r *Report) { r.Models[0].Endpoint = "gpu-01.internal:11434" }, "models[0].endpoint"},
		{"a control character in a model name", func(r *Report) { r.Models[0].Name = "llama\r" }, "models[0].name"},
		{"a control character in a digest", func(r *Report) { r.Models[0].Digest = "46e0\n" }, "models[0].digest"},
		{"a digest over 128 bytes", func(r *Report) { r.Models[0].Digest = strings.Repeat("d", maxShort+1) }, "models[0].digest: longer"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := validReport(agent)
			tt.edit(&r)
			_, err := New(Options{}).RecordReport(context.Background(), ReportCaller{Agents: []uuid.UUID{agent}}, r)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Kind != Invalid || !strings.Contains(refusal.Detail, tt.detail) {
				t.Fatalf("got %v, want a refusal that names %q", err, tt.detail)
			}
		})
	}
}

// A report about an agent outside the reporting instance's scope is refused
// before the catalog reads anything, so it takes no lock.
func TestAReportAboutAnAgentOutsideTheScopeIsRefusedFirst(t *testing.T) {
	r := validReport(uuid.New())
	r.Tools = append(r.Tools, ReportedTool{Kind: "bogus"})
	_, err := New(Options{}).RecordReport(context.Background(), ReportCaller{Instance: uuid.New(), Agents: []uuid.UUID{uuid.New()}}, r)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Kind != Forbidden {
		t.Fatalf("got %v, want forbidden", err)
	}
}
