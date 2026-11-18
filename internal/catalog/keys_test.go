package catalog

import (
	"regexp"
	"strings"
	"testing"
)

// The forms of keys that the database checks (migration 00012).
var (
	serverKeyForm = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	modelKeyForm  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/[a-z0-9]([a-z0-9.-]{0,126}[a-z0-9])?$`)
)

// Keys come from reported text, so whatever a report holds gives keys of the
// forms that the database accepts, taken or not: a report can never fail on
// a key, nor take the reserved one.
func FuzzKeysAreAlwaysOfTheirForm(f *testing.F) {
	f.Add("https://api.githubcopilot.com/mcp/", "GitHub", "ollama", "http://gpu-01.internal:11434/", "llama3.1:8b")
	f.Add(`stdio:["npx","-y","server-fs"]`, "Agent", "openai", "https://api.openai.com/v1", "gpt-4o")
	f.Add("http://[::1]:8080/", "", "x", "https://[fe80::1]/", "...")
	f.Add("https://-.-.-/", strings.Repeat("ab-", 40), "openai", "http://10.0.0.5/", strings.Repeat("a.", 100))
	f.Add("https://ÄÖÜ.example/", "Ünïcødé ✓", "mistral_ai", "https://api.mistral.ai", "İstanbul")
	f.Fuzz(func(t *testing.T, reference, announced, provider, endpoint, name string) {
		base := serverSlug(reference, announced)
		for _, key := range []string{base, freeKey("", base, "", maxSlug, map[string]bool{base: true}, reservedServerKey)} {
			if !serverKeyForm.MatchString(key) {
				t.Fatalf("server key %q from %q and %q", key, reference, announced)
			}
		}
		if freeKey("", base, "", maxSlug, nil, reservedServerKey) == reservedServerKey {
			t.Fatal("a server took the reserved key")
		}
		first, second := modelSlugs(provider, endpoint, name)
		taken := map[string]bool{first + "/" + second: true}
		for _, key := range []string{first + "/" + second, freeKey(first+"/", second, ".", maxNameSlug, taken, "")} {
			if !modelKeyForm.MatchString(key) {
				t.Fatalf("model key %q from %q, %q and %q", key, provider, endpoint, name)
			}
		}
		_ = secretInPath(reference)
		_ = unpinnedPackage(strings.Fields(reference))
	})
}

func TestAServerKeyComesFromItsHostOrItsAnnouncedNameNeverItsCommandLine(t *testing.T) {
	for _, tt := range []struct {
		name, reference, announced, want string
	}{
		{"a remote server, from its host", "https://api.githubcopilot.com/mcp/", "GitHub", "githubcopilot"},
		{"a remote server announcing another's name", "https://evil.example.net/mcp/", "github", "evil-example"},
		{"a host with a port", "http://gpu-01.internal:8080/", "", "gpu-01"},
		{"an IPv4 address", "http://10.0.0.5/mcp", "", "10-0-0-5"},
		{"an IPv6 address", "http://[fd00::1]:3000/", "", "fd00-1"},
		{"a host of one label", "http://localhost:3000/mcp", "", "localhost"},
		{"generic labels go", "https://mcp.www.linear.app/sse", "", "linear"},
		{"a host of two labels keeps its first", "https://mcp.dev/", "", "mcp"},
		{"a local server, from its announced name", `stdio:["npx","-y","@acme/fs","/home/alice"]`, "Acme FS", "acme-fs"},
		{"a local server announcing nothing", `stdio:["/home/alice/bin/server"]`, "", "server"},
		{"a connector, from its announced name", "connector:openai/conn_123", "Drive", "drive"},
		{"a name of no ASCII letter or digit", `stdio:["x"]`, "Ünïcødé ✓", "n-c-d"},
		{"a name that slugs to nothing", `stdio:["x"]`, "✓✓✓", "server"},
		{"a long name is cut", `stdio:["x"]`, strings.Repeat("ab-", 40), strings.TrimSuffix(strings.Repeat("ab-", 21), "-")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := serverSlug(tt.reference, tt.announced)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "alice") {
				t.Fatalf("%q holds a part of the command line", got)
			}
		})
	}
}

func TestAModelKeyStartsWithItsProviderOnlyAtItsDefaultEndpoint(t *testing.T) {
	for _, tt := range []struct {
		provider, endpoint, name, wantFirst, wantSecond string
	}{
		{"openai", "https://api.openai.com/v1", "gpt-4o", "openai", "gpt-4o"},
		{"openai", "https://api.openai.com/", "gpt-4o", "openai", "gpt-4o"},
		{"anthropic", "https://api.anthropic.com/", "claude-sonnet-4.5", "anthropic", "claude-sonnet-4.5"},
		{"mistral_ai", "https://api.mistral.ai/v1", "mistral-large", "mistral-ai", "mistral-large"},
		// Not the default, which is https: the host gives the same slug.
		{"openai", "http://api.openai.com/v1", "gpt-4o", "openai", "gpt-4o"},
		{"openai", "https://api.openai.com.evil.net/v1", "gpt-4o", "openai-com-evil", "gpt-4o"},
		{"ollama", "http://gpu-01.internal:11434/", "llama3.1:8b", "gpu-01", "llama3.1-8b"},
		{"azure.ai.openai", "https://acme.openai.azure.com/openai/", "gpt-4o", "acme-openai-azure", "gpt-4o"},
		{"openai", "https://proxy.example.com/v1", "GPT-4o", "proxy-example", "gpt-4o"},
		{"ollama", "http://[::]/", "...", "endpoint", "model"},
	} {
		t.Run(tt.provider+" "+tt.endpoint, func(t *testing.T) {
			first, second := modelSlugs(tt.provider, tt.endpoint, tt.name)
			if first != tt.wantFirst || second != tt.wantSecond {
				t.Fatalf("got %q/%q, want %q/%q", first, second, tt.wantFirst, tt.wantSecond)
			}
		})
	}
}

func TestToolKeysFollowTheirKind(t *testing.T) {
	for _, tt := range []struct{ got, want string }{
		{mcpToolKey("github", "create_issue"), "github/create_issue"},
		{mcpToolKey("github", "a/b"), "github/a/b"},
		{agentToolKey("send_email"), "agent/send_email"},
		{builtinToolKey("openai", "web_search"), "provider.openai/web_search"},
		{builtinToolKey("aws.bedrock", "code/interpreter"), "provider.aws.bedrock/code/interpreter"},
		// A provider's / and % are escaped, so that two built-in tools never
		// share a key.
		{builtinToolKey("a/b", "c"), "provider.a%2Fb/c"},
		{builtinToolKey("a", "b/c"), "provider.a/b/c"},
		{builtinToolKey("a%2Fb", "c"), "provider.a%252Fb/c"},
	} {
		if tt.got != tt.want {
			t.Errorf("got %q, want %q", tt.got, tt.want)
		}
	}
}

func TestAKeyThatIsTakenGetsTheLowestFreeSuffix(t *testing.T) {
	long := strings.Repeat("a", 60) + "-bcd"
	for _, tt := range []struct {
		name, prefix, base string
		taken              []string
		reserved, want     string
	}{
		{"a free key", "", "github", nil, "agent", "github"},
		{"a taken key", "", "github", []string{"github", "github-2"}, "agent", "github-3"},
		{"the reserved key", "", "agent", nil, "agent", "agent-2"},
		{"a cut key loses its trailing hyphen", "", long[:63], []string{long[:63]}, "", strings.Repeat("a", 60) + "-2"},
		{"a model key", "gpu-01/", "llama3.1-8b", []string{"gpu-01/llama3.1-8b"}, "", "gpu-01/llama3.1-8b-2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keep, maxLen := "", maxSlug
			if tt.prefix != "" {
				keep, maxLen = ".", maxNameSlug
			}
			got := freeKey(tt.prefix, tt.base, keep, maxLen, set(tt.taken), tt.reserved)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if !strings.HasPrefix(got, keyPrefix(tt.prefix, tt.base, keep, maxLen)) {
				t.Fatalf("%q does not start with the prefix of its taken keys", got)
			}
		})
	}
}
