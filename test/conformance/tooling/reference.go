package tooling

import (
	"fmt"
	"regexp"
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

// namedValue is a name of ASCII letters, digits, _, . and -, not starting
// with -, followed by =: an argument or a value such as GITHUB_TOKEN=ghp_x
// (EP-14).
var namedValue = regexp.MustCompile(`^([A-Za-z0-9_.][A-Za-z0-9_.-]*)=`)

// header is a name of ASCII letters, digits and -, not starting with -,
// followed by : and the spaces after it, as an HTTP header is written: an
// argument or a value such as Authorization: Bearer abc (EP-14).
var header = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]*): *`)

// RedactCommand returns a command and its arguments redacted as EP-14 says,
// with the deployment's rules. The argument that follows a flag whose name is
// a secret's becomes <redacted>, as redactArgument says every other does.
func RedactCommand(command []string, rules Rules) []string {
	redacted := make([]string, len(command))
	for i, arg := range command {
		if i > 0 && redactsNext(command[i-1], rules) {
			redacted[i] = Redacted
		} else {
			redacted[i] = redactArgument(arg, rules)
		}
	}
	return redacted
}

// redactsNext reports whether an argument is a flag whose name is a secret's,
// written without =, so that the argument after it is its value. A flag
// starts with -, and its name follows its leading dashes, however many. The
// argument is read as given, even when it is itself redacted as the value of
// the flag before it.
func redactsNext(arg string, rules Rules) bool {
	return strings.HasPrefix(arg, "-") && !strings.Contains(arg, "=") && secretName(strings.TrimLeft(arg, "-"), rules)
}

// redactArgument writes an argument as EP-14 says. A flag written
// --flag=value keeps its name, and its value becomes <redacted> when the name
// is a secret's, or is written as redactValue says; it never redacts the
// argument after it. Any other flag is written as given, and an argument that
// is not a flag as redactValue says.
func redactArgument(arg string, rules Rules) string {
	if !strings.HasPrefix(arg, "-") {
		return redactValue(arg, rules)
	}
	flag, value, joined := strings.Cut(arg, "=")
	switch {
	case !joined:
		return arg
	case secretName(strings.TrimLeft(flag, "-"), rules):
		return flag + "=" + Redacted
	}
	return flag + "=" + redactValue(value, rules)
}

// redactValue writes an argument that is not a flag, or a value, as EP-14
// says: as a URL, as redactURL says; then as a named value, which keeps its
// name and whose value becomes <redacted> when the name is a secret's; then as
// a header, written as its name, :, a space and <redacted> when its name is a
// secret's, and otherwise keeping its name, the : and the spaces after it;
// and otherwise as given. The value of a named value, and the rest of a
// header, whose name is not a secret's, are values in turn, read in a loop
// rather than recursively, so that no nesting can exhaust a stack.
func redactValue(value string, rules Rules) string {
	var b strings.Builder
	for {
		if isURL(value) {
			b.WriteString(redactURL(value, rules))
			return b.String()
		}
		if m := namedValue.FindStringSubmatch(value); m != nil {
			if secretName(m[1], rules) {
				b.WriteString(m[1] + "=" + Redacted)
				return b.String()
			}
			b.WriteString(m[0])
			value = value[len(m[0]):]
			continue
		}
		if m := header.FindStringSubmatch(value); m != nil {
			if secretName(m[1], rules) {
				b.WriteString(m[1] + ": " + Redacted)
				return b.String()
			}
			b.WriteString(m[0])
			value = value[len(m[0]):]
			continue
		}
		b.WriteString(value)
		return b.String()
	}
}

// secretName reports whether the name of a flag, a named value or a header is
// a secret's: it contains one of EP-14's words, comparing ASCII letters
// without regard to case and every other character exactly, so that no
// Unicode case mapping changes what matches, or it is one of the deployment's
// flags, matched exactly, case included.
func secretName(name string, rules Rules) bool {
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

// isURL reports whether an argument or a value starts with a scheme and //,
// once what url_host ignores at its start is left out.
func isURL(value string) bool {
	return scheme.MatchString(strings.TrimLeftFunc(value, ignored))
}

// redactURL writes a URL of a command line as EP-14 says. One that url_host
// reads, whatever its scheme, is written normalized, with its secret segments
// redacted, when one of the deployment's prefixes matches it, and otherwise as
// given, without its user information, query and fragment. One that url_host
// cannot read becomes <redacted>, since parsers disagree on where its user
// information ends.
func redactURL(arg string, rules Rules) string {
	u, err := ReadURL(arg)
	if err != nil {
		return Redacted
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
