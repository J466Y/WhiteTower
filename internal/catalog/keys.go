package catalog

import (
	"strconv"
	"strings"
)

// The grammar of keys (RFC-0002, section 3; plan P1-16, step 2). The core
// assigns each entry its key the first time it sees the entry, and the key
// never changes once the entry is approved. Keys name entries in policies and
// in the console, and events carry them in clear, so none comes from a
// command line, whose paths can hold a user name.
//
//   - A server's key is a slug: lowercase letters, digits and inner hyphens,
//     at most 63 characters. A remote server's comes from its host, which TLS
//     vouches for, so that a server cannot take another's key by announcing
//     its name; any other server's comes from the name it announces; and a
//     server with neither is server. agent is reserved for the agent's own
//     tools.
//   - A tool's key is its server's key, a slash and its name for an MCP
//     tool; agent/<name> for the agent's own tool, unique within its agent;
//     and provider.<provider>/<type> for a built-in tool, with a / or a % of
//     the provider written %2F or %25, so that no two built-in tools share a
//     key.
//   - A model's key is a slug of its provider, for an endpoint that the core
//     knows as that provider's default, or of its endpoint's host, a slash,
//     and a slug of its name, which keeps its dots: at most 128 characters.
//
// A slug that another entry of its kind has takes the lowest free suffix -2,
// -3 and so on, its text cut so that the whole stays within its length.

const (
	// maxSlug is the length of a server's key, and of the first part of a
	// model's key.
	maxSlug = 63
	// maxNameSlug is the length of the second part of a model's key.
	maxNameSlug = 128
	// reservedServerKey names the agent's own tools, so no server takes it.
	reservedServerKey = "agent"
	// fallbackServerSlug is the key of a server whose host and announced
	// name give no slug.
	fallbackServerSlug = "server"
	// fallbackEndpointSlug and fallbackNameSlug stand for the parts of a
	// model's key that its endpoint or its name do not give.
	fallbackEndpointSlug = "endpoint"
	fallbackNameSlug     = "model"
)

// genericLabels are the leading labels of a host that say little about it,
// as in api.example.com and mcp.example.com.
var genericLabels = map[string]bool{"api": true, "mcp": true, "www": true}

// defaultEndpointHosts are the hosts that the core knows as the default
// endpoints of the providers of the contracts' table (section 6.3) that have
// one public endpoint. They shape only keys: references always carry the
// endpoint, even a provider's default (RFC-0002, section 3).
var defaultEndpointHosts = map[string]string{
	"anthropic":  "api.anthropic.com",
	"cohere":     "api.cohere.com",
	"deepseek":   "api.deepseek.com",
	"gcp.gemini": "generativelanguage.googleapis.com",
	"groq":       "api.groq.com",
	"mistral_ai": "api.mistral.ai",
	"openai":     "api.openai.com",
	"perplexity": "api.perplexity.ai",
	"x_ai":       "api.x.ai",
}

// slug returns s in lowercase ASCII letters and digits, and the characters
// of keep, with every other run of characters written as one hyphen, without
// leading or trailing hyphens or kept characters, and cut to max characters.
// Only ASCII letters change case, so that no Unicode case mapping decides a
// key.
func slug(s, keep string, maxLen int) string {
	var b strings.Builder
	pending := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			r += 'a' - 'A'
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r < 0x80 && strings.ContainsRune(keep, r):
		default:
			pending = true
			continue
		}
		if pending && b.Len() > 0 {
			b.WriteByte('-')
		}
		pending = false
		b.WriteRune(r)
	}
	return trimSlug(b.String(), keep, maxLen)
}

// trimSlug cuts a slug to max characters, and trims the hyphens and kept
// characters at its ends.
func trimSlug(s, keep string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return strings.Trim(s, "-"+keep)
}

// serverSlug returns the slug that a server's key starts from: from its host
// for a remote server, whose reference is a URL, and otherwise from the name
// it announces; server when neither gives one.
func serverSlug(reference, announcedName string) string {
	var s string
	if host, ok := urlHost(reference); ok {
		s = hostSlug(host)
	} else {
		s = slug(announcedName, "", maxSlug)
	}
	if s == "" {
		return fallbackServerSlug
	}
	return s
}

// modelSlugs returns the two slugs that a model's key starts from: its
// provider's, for an endpoint on the host that the core knows as the
// provider's default, or its endpoint host's; and its name's, which keeps its
// dots.
func modelSlugs(provider, endpoint, name string) (string, string) {
	host, _ := urlHost(endpoint)
	first := ""
	if def, ok := defaultEndpointHosts[provider]; ok && host == def && strings.HasPrefix(endpoint, "https://") {
		first = slug(provider, "", maxSlug)
	} else {
		first = hostSlug(host)
	}
	if first == "" {
		first = fallbackEndpointSlug
	}
	second := slug(name, ".", maxNameSlug)
	if second == "" {
		second = fallbackNameSlug
	}
	return first, second
}

// hostSlug returns the slug of a host: an IP address whole, and a domain name
// without its leading generic labels and its last label, so that
// api.githubcopilot.com gives githubcopilot and gpu-01.internal gives gpu-01.
func hostSlug(host string) string {
	labels := strings.Split(host, ".")
	last := labels[len(labels)-1]
	if strings.HasPrefix(host, "[") || last != "" && strings.Trim(last, "0123456789") == "" {
		return slug(host, "", maxSlug)
	}
	for len(labels) > 2 && genericLabels[labels[0]] {
		labels = labels[1:]
	}
	if len(labels) > 1 {
		labels = labels[:len(labels)-1]
	}
	return slug(strings.Join(labels, "-"), "", maxSlug)
}

// urlHost returns the host of an http or https URL, and whether the value is
// one: its authority without a port. A reference's URL is normalized, so its
// host is in lowercase.
func urlHost(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		if rest, ok = strings.CutPrefix(s, "http://"); !ok {
			return "", false
		}
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if strings.HasPrefix(rest, "[") {
		if i := strings.IndexByte(rest, ']'); i >= 0 {
			return rest[:i+1], true
		}
		return rest, true
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	return rest, true
}

// mcpToolKey returns the key of an MCP tool.
func mcpToolKey(serverKey, name string) string { return serverKey + "/" + name }

// agentToolKey returns the key of the agent's own tool.
func agentToolKey(name string) string { return "agent/" + name }

// builtinToolKey returns the key of a built-in tool, its provider's / and %
// escaped, as the database checks.
func builtinToolKey(provider, toolType string) string {
	escaped := strings.ReplaceAll(strings.ReplaceAll(provider, "%", "%25"), "/", "%2F")
	return "provider." + escaped + "/" + toolType
}

// freeKey returns the first of base, base-2, base-3 and so on, each cut to
// max characters with its suffix, that taken does not hold and that is not
// reserved. A cut slug loses the hyphens and kept characters that end it.
func freeKey(prefix, base, keep string, maxLen int, taken map[string]bool, reserved string) string {
	for n := 1; ; n++ {
		candidate := base
		if n > 1 {
			suffix := "-" + strconv.Itoa(n)
			candidate = trimSlug(base, keep, maxLen-len(suffix)) + suffix
		}
		if key := prefix + candidate; !taken[key] && key != reserved {
			return key
		}
	}
}

// keyPrefix returns the part of a key that every key freeKey may return for
// it starts with: the base, cut for the longest suffix it may take.
func keyPrefix(prefix, base, keep string, maxLen int) string {
	return prefix + trimSlug(base, keep, maxLen-len("-999999"))
}
