package tooling_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
	"github.com/J466Y/WhiteTower/test/conformance/tooling"
)

func TestMCPDefinitionsRefusesWhatIsNotAToolsListResponse(t *testing.T) {
	for _, tt := range []struct{ name, message string }{
		{"text that is not JSON", `{"result":`},
		{"a message that is not an object", `[{"result":{"tools":[]}}]`},
		{"an error response", `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`},
		{"a result that is not an object", `{"jsonrpc":"2.0","id":1,"result":[]}`},
		{"a result without tools", `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{"tools that are not an array", `{"jsonrpc":"2.0","id":1,"result":{"tools":{"name":"a"}}}`},
		{"a tool that is not an object", `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"},"b"]}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defs, err := tooling.MCPDefinitions([]byte(tt.message))
			if err == nil || errors.Is(err, canonical.ErrNoCanonicalJSON) {
				t.Errorf("got %v, %v; want an error that the message cannot be read", defs, err)
			}
		})
	}
}

func TestFunctionDefinitionRefusesASchemaThatIsNotJSON(t *testing.T) {
	def, err := tooling.FunctionDefinition("send_email", []byte(`{"type":`))
	if err == nil || errors.Is(err, canonical.ErrNoCanonicalJSON) {
		t.Errorf("got %v, %v; want an error that the schema cannot be read", def, err)
	}
}

func TestReadURLCannotReadTextThatIsNotUTF8(t *testing.T) {
	// A JSON string cannot hold it, so no vector can give it.
	u, err := tooling.ReadURL("https://example.com/\xff")
	if !errors.Is(err, tooling.ErrCannotRead) {
		t.Errorf("got %+v, %v; want ErrCannotRead", u, err)
	}
}

// nested are EP-14's two prefixes, one within the other.
var nested = []string{"https://a.example/s/", "https://a.example/s/x/"}

// FuzzReadURL checks that url_host's reading never panics, that a host it
// reads is one that normalized URLs can carry, within the bounds of DNS, and
// that normalizing a normalized URL changes nothing, redacted with nested
// prefixes or not.
func FuzzReadURL(f *testing.F) {
	f.Add("https://xn--kkg.de/")
	f.Add("https://a.example/s/x/SECRET/<redacted>/%3Credacted%3E")
	for _, seed := range []string{
		"HTTPS://API.Example.COM:443/mcp/./tools/../%7euser/",
		"http://evil.com\\@good.com/",
		"http://[2001:DB8:0:0:1:0:0:1]:08080/a b/%zz",
		" \x01https://user:pw@München.DE./?q#f\n",
		"http://xn--gd-.com/",
		"http://\u05d0\u05d1.example/",
		"http://a\u200cb.com/",
		"http://0x7f.1/",
		"https://example.com/a/%2e%2E/../..//b",
		"wss://example.com:65535",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		u, err := tooling.ReadURL(value)
		if err != nil {
			if !errors.Is(err, tooling.ErrCannotRead) {
				t.Fatalf("ReadURL(%q): %v, which does not wrap ErrCannotRead", value, err)
			}
			return
		}
		if !strings.HasPrefix(u.Host, "[") {
			labels := strings.Split(u.Host, ".")
			if strings.Trim(u.Host, "abcdefghijklmnopqrstuvwxyz0123456789.-_") != "" || len(u.Host) > 253 ||
				slices.ContainsFunc(labels, func(l string) bool { return len(l) > 63 }) {
				t.Fatalf("ReadURL(%q) reads the host %q", value, u.Host)
			}
		}
		normalized, err := u.Normalized()
		if err != nil {
			return
		}
		again, err := tooling.NormalizedURL(normalized, tooling.Rules{})
		if err != nil || again != normalized {
			t.Fatalf("%q normalizes to %q, which normalizes to %q, %v", value, normalized, again, err)
		}
		rules := tooling.Rules{URLPrefixes: nested}
		redacted, err := tooling.NormalizedURL(value, rules)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := tooling.NormalizedURL(redacted, rules); err != nil || again != redacted {
			t.Fatalf("%q redacts to %q, which redacts to %q, %v", value, redacted, again, err)
		}
	})
}

// FuzzRedactCommand checks that the redaction of a command line never panics,
// whatever the deployment's rules, and keeps every argument in its place. With
// EP-14's nested prefixes, and the fuzzer's when it is a normalized URL that
// ends with /, as section 7.7 requires, it also checks that redacting again
// changes nothing. The fuzzer's text is the command, its arguments separated
// by NULs, and the deployment's URL prefix and flag.
func FuzzRedactCommand(f *testing.F) {
	f.Add("srv\x00--token\x00--password\x00pw\x00--auth=x\x00postgresql://u:p@db/app?ssl=1", "https://a.example/s/", "pat")
	f.Add("mcp-remote\x00https://u@A.example/s/x/SECRET/sse?x\x00--pat\x00ghp\x00http://evil.com\\@good.com/", "https://a.example/", "pat")
	f.Add("docker\x00-e\x00GITHUB_TOKEN=ghp\x00--header=Authorization: Bearer x\x00Cookie:a\x00keycloak://u:p@kc/\x00pat=x", "https://kc/", "pat")
	// Prefixes that do not end with / name segments within those of
	// others.
	f.Add("srv\x00https://a.example/st/x", "https://a.example/s", "")
	// A flag written with = whose name ends with :, which a header that
	// could start with - would turn into a flag without =.
	f.Add("-tokeY:=\x000", "0", "0")
	f.Fuzz(func(t *testing.T, command, prefix, flag string) {
		args := strings.Split(command, "\x00")
		rules := tooling.Rules{URLPrefixes: []string{prefix, "https://a.example/"}, Flags: []string{flag}}
		if redacted := tooling.RedactCommand(args, rules); len(redacted) != len(args) {
			t.Fatalf("%q redacts to %q", args, redacted)
		}
		rules.URLPrefixes = nested
		// A prefix that holds <redacted>, which no deployment writes, can
		// match a URL only once it is redacted.
		if normalized, err := tooling.NormalizedURL(prefix, tooling.Rules{}); err == nil && normalized == prefix &&
			strings.HasSuffix(prefix, "/") && !strings.Contains(prefix, tooling.Redacted) {
			rules.URLPrefixes = append(slices.Clone(nested), prefix)
		}
		redacted := tooling.RedactCommand(args, rules)
		if again := tooling.RedactCommand(redacted, rules); !slices.Equal(again, redacted) {
			t.Fatalf("%q redacts to %q, which redacts to %q", args, redacted, again)
		}
	})
}
