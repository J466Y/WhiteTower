package tooling

import (
	"fmt"
	"slices"
	"strings"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
)

// Rules are the deployment's redaction rules, which the catalog file carries
// (section 7.7, EP-14). Until a bundle is active, an enforcement point has
// none.
type Rules struct {
	// URLPrefixes are normalized http or https URLs that end with /: the
	// path segment that follows each is a secret.
	URLPrefixes []string `json:"url_prefixes"`
	// Flags are the names of the flags whose values are secrets, beyond
	// those that EP-14 lists, without their leading dashes.
	Flags []string `json:"flags"`
}

// Redacted is what EP-14 writes in place of a secret.
const Redacted = "<redacted>"

// secretWords make the value of a flag whose name contains one of them, in
// any case, a secret (EP-14).
var secretWords = []string{"token", "secret", "password", "passwd", "key", "auth", "credential", "cookie"}

// NormalizedURL returns a remote server's URL, or a model's endpoint,
// normalized as section 4.10 says, with the path segment that follows each of
// the deployment's prefixes redacted (EP-14). It returns an error that wraps
// ErrNoReference for a URL that makes no reference.
func NormalizedURL(value string, rules Rules) (string, error) {
	u, err := ReadURL(value)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoReference, err)
	}
	normalized, err := u.Normalized()
	if err != nil {
		return "", err
	}
	return redactPrefixes(normalized, rules.URLPrefixes), nil
}

// redactPrefixes replaces with <redacted> the path segment, up to the next /
// or to the end, that follows each prefix that a normalized URL starts with.
// Every prefix that matches before any replacement replaces its segment, and a
// URL equal to a prefix keeps it whole.
func redactPrefixes(normalized string, prefixes []string) string {
	var starts []int
	for _, prefix := range prefixes {
		if len(normalized) > len(prefix) && strings.HasPrefix(normalized, prefix) {
			starts = append(starts, len(prefix))
		}
	}
	slices.Sort(starts)
	var b strings.Builder
	last := 0
	for _, start := range slices.Compact(starts) {
		// A prefix that does not end with /, which section 7.7 does not
		// allow, can name a segment that another has replaced.
		if start < last {
			continue
		}
		end := strings.IndexByte(normalized[start:], '/')
		if end < 0 {
			end = len(normalized) - start
		}
		b.WriteString(normalized[last:start])
		b.WriteString(Redacted)
		last = start + end
	}
	b.WriteString(normalized[last:])
	return b.String()
}

// RedactCommand returns a command and its arguments redacted as EP-14 says,
// with the deployment's rules. The argument that follows a flag whose value
// is a secret becomes <redacted>, and so does the value of such a flag written
// --flag=value, which never redacts the argument after it. Every other
// argument, and the value of every other --flag=value, is written as
// redactURL says.
func RedactCommand(command []string, rules Rules) []string {
	redacted := make([]string, len(command))
	for i, arg := range command {
		flag, value, joined := strings.Cut(arg, "=")
		switch {
		case i > 0 && !strings.Contains(command[i-1], "=") && secretFlag(command[i-1], rules):
			redacted[i] = Redacted
		case joined && secretFlag(flag, rules):
			redacted[i] = flag + "=" + Redacted
		case joined && strings.HasPrefix(flag, "-"):
			redacted[i] = flag + "=" + redactURL(value, rules)
		default:
			redacted[i] = redactURL(arg, rules)
		}
	}
	return redacted
}

// secretFlag reports whether an argument, up to its first =, is a flag whose
// value is a secret. A flag starts with -, and its name follows its leading
// dashes. The name is a secret's when it contains one of EP-14's words,
// comparing ASCII letters without regard to case and every other character
// exactly, so that no Unicode case mapping changes what matches, or when it
// is one of the deployment's flags, matched exactly.
func secretFlag(flag string, rules Rules) bool {
	name, ok := strings.CutPrefix(flag, "-")
	if !ok {
		return false
	}
	name = strings.TrimLeft(name, "-")
	lower := strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, name)
	for _, word := range secretWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return slices.Contains(rules.Flags, name)
}

// redactURL writes an argument of a command line, or the value of
// --flag=value, as EP-14 says. One that url_host reads, whatever its scheme,
// is a URL: it is written normalized, with its secret segments redacted, when
// one of the deployment's prefixes matches it, and otherwise as given, without
// its user information, query and fragment. One that starts with a scheme and
// // but that url_host cannot read becomes <redacted>, since parsers disagree
// on where its user information ends. Any other is written as given.
func redactURL(arg string, rules Rules) string {
	u, err := ReadURL(arg)
	if err != nil {
		if scheme.MatchString(strings.TrimLeftFunc(arg, ignored)) {
			return Redacted
		}
		return arg
	}
	if normalized, err := u.Normalized(); err == nil {
		for _, prefix := range rules.URLPrefixes {
			if strings.HasPrefix(normalized, prefix) {
				return redactPrefixes(normalized, rules.URLPrefixes)
			}
		}
	}
	return u.bare
}

// LocalServerReference returns the reference of a local MCP server: stdio:
// followed by the canonical JSON of the array of its command and arguments,
// as configured, after the redaction of EP-14.
func LocalServerReference(command []string, rules Rules) string {
	items := []any{}
	for _, arg := range RedactCommand(command, rules) {
		items = append(items, text(arg))
	}
	return "stdio:" + canonicalJSON(items)
}

// ConnectorReference returns the reference of an MCP server that the model
// provider hosts and names by an ID rather than a URL.
func ConnectorReference(provider, connectorID string) string {
	return "connector:" + provider + "/" + connectorID
}

// MCPToolReference returns the string form of an MCP tool's reference: its
// server's reference and its name.
func MCPToolReference(server, name string) string {
	return stringForm("name", name, "server", server)
}

// ToolReference returns the string form of the reference of a function, http
// or other tool: its name alone.
func ToolReference(name string) string {
	return stringForm("name", name)
}

// BuiltinToolReference returns the string form of a built-in tool's
// reference: its provider and its type.
func BuiltinToolReference(provider, toolType string) string {
	return stringForm("provider", provider, "type", toolType)
}

// ModelReference returns the string form of a model's reference: its
// provider, the base URL of its endpoint, normalized as NormalizedURL says,
// and its name as requested. It returns an error that wraps ErrNoReference
// for an endpoint that makes no reference.
func ModelReference(provider, endpoint, name string, rules Rules) (string, error) {
	normalized, err := NormalizedURL(endpoint, rules)
	if err != nil {
		return "", err
	}
	return stringForm("endpoint", normalized, "name", name, "provider", provider), nil
}

// stringForm returns the canonical JSON of an object of strings, given as
// pairs of a member's name and its value: the string form of a reference with
// several parts (section 4.10).
func stringForm(pairs ...string) string {
	obj := canonical.Object{}
	for i := 0; i+1 < len(pairs); i += 2 {
		obj = append(obj, canonical.Member{Name: text(pairs[i]), Value: text(pairs[i+1])})
	}
	return canonicalJSON(obj)
}

// canonicalJSON returns the canonical JSON of strings, in an array or an
// object whose member names do not repeat, which canonical.Encode always
// writes: a string converted from Go holds no lone surrogate.
func canonicalJSON(v any) string {
	data, _ := canonical.Encode(v)
	return string(data)
}
