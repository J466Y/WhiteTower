package catalog

import (
	"slices"
	"testing"
)

func TestLocalServersLaunchedFromUnpinnedPackagesAreFlagged(t *testing.T) {
	for _, tt := range []struct {
		command  []string
		unpinned bool
	}{
		{[]string{"npx", "-y", "@modelcontextprotocol/server-github"}, true},
		{[]string{"npx", "-y", "@modelcontextprotocol/server-github@latest"}, true},
		{[]string{"npx", "-y", "@modelcontextprotocol/server-github@^2025.4.8"}, true},
		{[]string{"npx", "-y", "@modelcontextprotocol/server-github@2025.4.8"}, false},
		{[]string{"npx", "server-fs@1.2.3-beta.1", "/home/alice"}, false},
		{[]string{"npx", "--package=server-fs@1.2.3", "server-fs"}, false},
		{[]string{"npx", "-p", "server-fs", "server-fs@1.2.3"}, true},
		{[]string{"npx", "--registry", "server-fs@1.0.0", "server-fs"}, true},
		{[]string{"npx", "./local-server"}, false},
		{[]string{"npx"}, true},
		{[]string{`C:\Program Files\nodejs\npx.cmd`, "-y", "server-fs"}, true},
		{[]string{"cmd", "/c", "npx", "-y", "server-fs@1.0.0"}, false},
		{[]string{"bunx", "server-fs"}, true},
		{[]string{"bunx", "server-fs@1.0.0"}, false},
		{[]string{"uvx", "mcp-server-git"}, true},
		{[]string{"uvx", "mcp-server-git==0.6.2"}, false},
		{[]string{"uvx", "mcp-server-git@0.6.2"}, false},
		{[]string{"uvx", "mcp-server-git>=0.6"}, true},
		{[]string{"uvx", "--python", "3.12", "mcp-server-git==0.6.2"}, false},
		{[]string{"uvx", "--with", "httpx==0.27.0", "mcp-server-git"}, true},
		{[]string{"uvx", "--from", "git+https://github.com/acme/server", "server"}, true},
		{[]string{"/usr/local/bin/pipx", "run", "mcp-server-time"}, true},
		{[]string{"pipx", "run", "--spec", "mcp-server-time==1.0.0", "mcp-server-time"}, false},
		{[]string{"pipx", "install", "mcp-server-time"}, false},
		{[]string{"node", "/opt/server/index.js"}, false},
		{[]string{"docker", "run", "-i", "ghcr.io/acme/server"}, false},
	} {
		if got := unpinnedPackage(tt.command); got != tt.unpinned {
			t.Errorf("%q: unpinned %v, want %v", tt.command, got, tt.unpinned)
		}
	}
}

func TestPathSegmentsThatLookLikeSecretsAreFlagged(t *testing.T) {
	for _, tt := range []struct {
		url    string
		secret bool
	}{
		{"https://mcp.zapier.com/api/mcp/s/NjA4Y2M2ZjctZTk2YS00ZmM2LTk0Y2UtOWZiNjM3NmZiZGE5/mcp", true},
		{"https://hooks.example.com/550e8400-e29b-41d4-a716-446655440000/", true},
		{"https://gateway.example.net/k/sk1aB2cD3eF4gH5iJ6kL7/v1", true},
		{"https://api.githubcopilot.com/mcp/", false},
		{"https://example.com/a-long-descriptive-path-segment-v2/", false},
		{"https://example.com/release-2024-ab/", false},
		{"https://example.com/v1/2024-11-05/", false},
		{"https://example.com/short1a2b/", false},
		{"https://example.com/<redacted>/mcp", false},
		{"https://example.com/mcp?token=NjA4Y2M2ZjctZTk2YS00ZmM2LTk0Y2U", false},
		{"https://example.com", false},
		{"not a url", false},
	} {
		if got := secretInPath(tt.url); got != tt.secret {
			t.Errorf("%q: secret %v, want %v", tt.url, got, tt.secret)
		}
	}
}

func TestAServersFlagsComeFromItsReference(t *testing.T) {
	for _, tt := range []struct {
		reference string
		want      []string
	}{
		{"https://api.githubcopilot.com/mcp/", []string{}},
		{"https://mcp.zapier.com/s/NjA4Y2M2ZjctZTk2YS00ZmM2LTk0Y2U/mcp", []string{FlagSecretInPath}},
		{`stdio:["npx","-y","server-fs@1.0.0"]`, []string{}},
		{
			`stdio:["npx","-y","mcp-remote","https://mcp.zapier.com/s/NjA4Y2M2ZjctZTk2YS00ZmM2LTk0Y2U/mcp"]`,
			[]string{FlagUnpinnedPackage, FlagSecretInPath},
		},
		{"connector:openai/conn_NjA4Y2M2ZjctZTk2YS00ZmM2", []string{}},
	} {
		if got := serverFlags(tt.reference); !slices.Equal(got, tt.want) {
			t.Errorf("%s: flags %q, want %q", tt.reference, got, tt.want)
		}
	}
}
