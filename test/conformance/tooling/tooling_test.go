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

func TestTransformCannotReadTextThatIsNotUTF8(t *testing.T) {
	for _, name := range []string{"lowercase", "path", "url_host", "email_domain"} {
		if got, err := tooling.Transform(name, "a@b.example/\xff"); !errors.Is(err, tooling.ErrCannotRead) {
			t.Errorf("%s: got %q, %v; want ErrCannotRead", name, got, err)
		}
	}
}

func TestRecordRefusesAnUnknownTypeOrTransform(t *testing.T) {
	for _, arg := range []tooling.Argument{
		{Name: "n", Path: []string{"n"}, Type: "Decimal"},
		{Name: "n:uppercase", Path: []string{"n"}, Type: "String", Transform: "uppercase"},
	} {
		record, err := tooling.Record([]byte(`{"n":"1"}`), []tooling.Argument{arg})
		if err == nil || errors.Is(err, tooling.ErrInvalidArgument) {
			t.Errorf("%+v: got %v, %v; want an error in the declaration", arg, record, err)
		}
	}
}

// FuzzTransform checks that the transforms never panic, and that each reads
// what it gives as it is: a cleaned path cleans to itself and has no
// backslash, a host that url_host reads reads again in a URL, and a domain
// that email_domain reads reads again in an address.
func FuzzTransform(f *testing.F) {
	for _, seed := range []string{
		"//srv/./data/../../etc/passwd",
		"C:\\Windows\\..\\..\\x",
		"../../a/b/../c",
		"/etc/passwd\x00.png",
		"MAIN-\u212a",
		"Alice Smith <alice@M\u00fcnchen.DE.>",
		"\"a <b@evil.com>\" <x@good.com>",
		"alice@evil.com(@good.com)",
		"alice@good.com\u3002evil.com",
		"alice@192.168.1.1",
		"https://user@[2001:db8::1]:8443/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		for name, again := range map[string]func(string) string{
			"lowercase":    func(s string) string { return s },
			"path":         func(s string) string { return s },
			"url_host":     func(s string) string { return "https://" + s + "/" },
			"email_domain": func(s string) string { return "alice@" + s },
		} {
			got, err := tooling.Transform(name, value)
			if err != nil {
				if !errors.Is(err, tooling.ErrCannotRead) {
					t.Fatalf("%s(%q): %v, which does not wrap ErrCannotRead", name, value, err)
				}
				continue
			}
			if name == "path" && strings.Contains(got, `\`) {
				t.Fatalf("path(%q) gives %q", value, got)
			}
			if twice, err := tooling.Transform(name, again(got)); err != nil || twice != got {
				t.Fatalf("%s(%q) gives %q, which reads as %q, %v", name, value, got, twice, err)
			}
		}
	})
}

// FuzzRecord checks that filling a record never panics, whatever the call's
// arguments, that it denies a call only with ErrInvalidArgument, and that a
// record holds the declared argument alone, of its declared type. The
// fuzzer's text is the arguments, the argument's path, its names separated by
// dots, and a choice of its type and transform.
func FuzzRecord(f *testing.F) {
	f.Add(`{"options":{"to":["Alice <a@Corp.com>","b@corp.com"]}}`, "options.to", uint8(7))
	f.Add(`{"n":[3,1,3,-9223372036854775808]}`, "n", uint8(8))
	f.Add(`{"n":1.0,"n":2}`, "n", uint8(5))
	f.Add(`{"a":{"b":"//etc/../passwd"}}`, "a.b", uint8(2))
	kinds := []struct{ typ, transform string }{
		{"String", ""},
		{"String", "lowercase"},
		{"String", "path"},
		{"String", "url_host"},
		{"String", "email_domain"},
		{"Long", ""},
		{"Bool", ""},
		{"Set<String>", "email_domain"},
		{"Set<Long>", ""},
	}
	f.Fuzz(func(t *testing.T, arguments, path string, kind uint8) {
		k := kinds[int(kind)%len(kinds)]
		arg := tooling.Argument{Name: path, Path: strings.Split(path, "."), Transform: k.transform, Type: k.typ}
		record, err := tooling.Record([]byte(arguments), []tooling.Argument{arg})
		if err != nil {
			if !errors.Is(err, tooling.ErrInvalidArgument) {
				t.Fatalf("%q: %v, which does not wrap ErrInvalidArgument", arguments, err)
			}
			return
		}
		v, ok := record[path]
		switch {
		case !ok && len(record) == 0:
			return
		case !ok || len(record) != 1:
			t.Fatalf("%q gives the record %v for the argument %q", arguments, record, path)
		}
		var fits bool
		switch v := v.(type) {
		case string:
			fits = k.typ == "String"
		case int64:
			fits = k.typ == "Long"
		case bool:
			fits = k.typ == "Bool"
		case []string:
			fits = k.typ == "Set<String>" && slices.IsSorted(v) && len(slices.Compact(slices.Clone(v))) == len(v)
		case []int64:
			fits = k.typ == "Set<Long>" && slices.IsSorted(v) && len(slices.Compact(slices.Clone(v))) == len(v)
		}
		if !fits {
			t.Fatalf("%q gives %#v for an argument of type %s", arguments, v, k.typ)
		}
	})
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
	f.Add("srv\x00--env=GITHUB_TOKEN=x\x00A=B=pat=c\x00X-Note:  Authorization: Bearer x\x00Referer: https://u:p@a.example/s/x/y", "https://h/", "B")
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
