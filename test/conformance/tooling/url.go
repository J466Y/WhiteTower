package tooling

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// ErrCannotRead is the error of a value that a transform cannot read: url_host,
// path or email_domain (section 6.11).
var ErrCannotRead = errors.New("the transform cannot read the value")

// ErrNoReference is the error of a URL that makes no reference: one that
// url_host cannot read, whose scheme is not http or https, or with a
// backslash in its path (section 4.10).
var ErrNoReference = errors.New("the URL makes no reference")

// URL is a URL as the url_host transform reads it (section 6.11): the reading
// that normalized URLs (section 4.10) and the redaction of URLs in command
// lines (EP-14) build on.
type URL struct {
	// Scheme is the URL's scheme, as given.
	Scheme string
	// Host is the host that url_host reads: a domain name in A-labels and in
	// lowercase, an IPv4 address, or an IPv6 address in brackets.
	Host string
	// Port is the port's digits, as given, or empty when the URL has none.
	Port string
	// Path runs from the end of the authority to the first ? or #, as given.
	Path string
	// bare is the value as given, without its user information, query and
	// fragment, as EP-14 writes a URL of a command line.
	bare string
}

// scheme is a scheme (RFC 3986, section 3.1) followed by //.
var scheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// lookup converts a host to A-labels as WHATWG's "domain to ASCII" does
// without strictness: UTS #46, non-transitional, without the STD3 rules, so
// that underscores pass, without the checks on hyphens, and with joiners and
// Bidi checked. idna.Lookup applies the STD3 rules, and refuses underscores.
// It refuses an A-label whose Punycode gives an ASCII label, or a label that
// UTS #46 does not map to itself, and its decoder refuses a delimiter with
// nothing before it, as in xn---bbk. It reads two A-labels that step 7
// refuses, which readHost refuses itself: xn--, whose Punycode gives an empty
// label, and one that is not ASCII, such as xn--g例-. Its tables are those of
// Go's version of Unicode, 15.0 from Go 1.26, as step 7 allows.
var lookup = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false),
	idna.CheckHyphens(false), idna.CheckJoiners(true), idna.BidiRule())

// readDifferently are the characters that versions of UTS #46, or its
// transitional and non-transitional processing, read differently: ß, ς, the
// zero width non-joiner and joiner, and ẞ. A host that holds one, as written
// or within an A-label, cannot be read (step 7).
const readDifferently = "\u00df\u03c2\u200c\u200d\u1e9e"

// cannotRead returns an error that wraps ErrCannotRead and says why.
func cannotRead(why string) error {
	return fmt.Errorf("%w: %s", ErrCannotRead, why)
}

// ignored reports whether url_host ignores r at the start or at the end of a
// value: a space or a C0 control character.
func ignored(r rune) bool {
	return r <= ' '
}

// isControl reports whether r is a control character as url_host and path
// define it: U+0000 to U+001F, or U+007F.
func isControl(r rune) bool {
	return r < ' ' || r == 0x7F
}

// ReadURL reads a value as url_host does, step by step (section 6.11). It
// returns an error that wraps ErrCannotRead for a value that url_host cannot
// read, and for text that is not UTF-8, which no JSON string can hold.
func ReadURL(value string) (*URL, error) {
	if !utf8.ValidString(value) {
		return nil, cannotRead("the value is not UTF-8")
	}
	// 1. Leading and trailing spaces and C0 control characters are ignored,
	// and a control character anywhere else cannot be read.
	start := len(value) - len(strings.TrimLeftFunc(value, ignored))
	end := max(start, len(strings.TrimRightFunc(value, ignored)))
	text := value[start:end]
	if strings.IndexFunc(text, isControl) >= 0 {
		return nil, cannotRead("a control character")
	}
	// 2. A scheme and //.
	loc := scheme.FindStringIndex(text)
	if loc == nil {
		return nil, cannotRead("no scheme followed by //")
	}
	rest := text[loc[1]:]
	// 3. The authority runs to the first /, ? or #.
	authorityEnd := strings.IndexAny(rest, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	authority := rest[:authorityEnd]
	if strings.IndexFunc(authority, func(r rune) bool { return r == '\\' || unicode.Is(unicode.White_Space, r) }) >= 0 {
		return nil, cannotRead("a backslash or whitespace in the authority")
	}
	// 4. The host follows the last @ of the authority.
	hostPort := authority[strings.LastIndexByte(authority, '@')+1:]
	host, port, err := readHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	// What EP-14 writes of a URL in a command line keeps the value as given,
	// what url_host ignores included, but for the user information, and
	// everything from the first ? or # after the authority.
	path := rest[authorityEnd:]
	bare := value[:start] + text[:loc[1]] + hostPort
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		path = path[:cut]
		bare += path
	} else {
		bare += path + value[end:]
	}
	return &URL{Scheme: text[:loc[1]-len("://")], Host: host, Port: port, Path: path, bare: bare}, nil
}

// readHostPort reads the host and the port that follow the user
// information: steps 5 to 8.
func readHostPort(hostPort string) (host, port string, err error) {
	var hasPort bool
	if ipv6, ok := strings.CutPrefix(hostPort, "["); ok {
		address, after, found := strings.Cut(ipv6, "]")
		if !found {
			return "", "", cannotRead("an IPv6 address without its closing bracket")
		}
		if host, err = readIPv6(address); err != nil {
			return "", "", err
		}
		if port, hasPort = strings.CutPrefix(after, ":"); after != "" && !hasPort {
			return "", "", cannotRead("text after an IPv6 address")
		}
	} else {
		var name string
		name, port, hasPort = strings.Cut(hostPort, ":")
		if host, err = readHost(name); err != nil {
			return "", "", err
		}
	}
	// 5. A port is 1 to 5 digits, and at most 65535.
	if hasPort {
		// In base 10, ParseUint takes decimal digits only: no sign and no
		// underscore.
		n, err := strconv.ParseUint(port, 10, 32)
		if err != nil || len(port) > 5 || n > 65535 {
			return "", "", cannotRead("a port that is not 1 to 5 digits, at most 65535")
		}
	}
	return host, port, nil
}

// readIPv6 reads an IPv6 address, given without its brackets: step 6.
func readIPv6(address string) (string, error) {
	if strings.ContainsAny(address, "%.") {
		return "", cannotRead("an IPv6 address with a zone ID or a dotted part")
	}
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is6() {
		return "", cannotRead("not an IPv6 address")
	}
	if addr.Is4In6() {
		return "", cannotRead("an IPv6 address in the IPv4-mapped range")
	}
	// Addr.String writes an IPv6 address as section 4 of RFC 5952 says.
	return "[" + addr.String() + "]", nil
}

// number is a label that is a number: decimal digits, or 0x and any
// hexadecimal digits, none included.
var number = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]*)$`)

// ipv4Part is a decimal number from 0 to 255 without leading zeros.
var ipv4Part = regexp.MustCompile(`^(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$`)

// readHost reads a host that is not an IPv6 address: steps 7 and 8, with
// which email_domain also reads a domain (section 6.11).
func readHost(name string) (string, error) {
	// 7. A % cannot be read; the rest is converted to A-labels, in
	// lowercase, without one trailing dot. The conversion accepts empty
	// labels, characters that hosts cannot have and labels of any length, so
	// they are checked once it is done.
	if strings.Contains(name, "%") {
		return "", cannotRead("a % in the host")
	}
	// The bound of DNS applies as written too, so that a host padded with
	// characters that UTS #46 ignores is refused before it is converted.
	if utf8.RuneCountInString(strings.TrimSuffix(name, ".")) > 253 {
		return "", cannotRead("a host longer than 253 characters as written")
	}
	host, err := lookup.ToASCII(name)
	if err != nil {
		return "", cannotRead("a host that IDNA cannot convert")
	}
	// lookup reads xn-- as an empty label, so that a.b.xn-- would read as
	// a.b, and xn--g例- as the A-label of g例: every A-label of the host as
	// UTS #46 maps it must convert to itself.
	for _, label := range strings.Split(mapped(name), ".") {
		if !strings.HasPrefix(label, "xn--") {
			continue
		}
		if a, err := lookup.ToASCII(label); err != nil || a != label {
			return "", cannotRead("an A-label that does not convert to itself")
		}
	}
	// The characters that UTS #46 reads differently, as written, and within
	// the U-labels of the conversion, which hold those of the A-labels
	// given. ẞ is checked as written, since Unicode 15.0 maps it to ss.
	ulabels, err := idna.Punycode.ToUnicode(host)
	if err != nil || strings.ContainsAny(name, readDifferently) || strings.ContainsAny(ulabels, readDifferently) {
		return "", cannotRead("a character that versions of UTS #46 read differently")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) > 253 {
		return "", cannotRead("a host longer than 253 characters")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" {
			return "", cannotRead("an empty label")
		}
		if len(label) > 63 {
			return "", cannotRead("a label longer than 63 characters")
		}
		if strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return "", cannotRead("a character that a host cannot have")
		}
	}
	// 8. A host whose last label is a number is an IPv4 address of four
	// decimal numbers.
	if number.MatchString(labels[len(labels)-1]) {
		if len(labels) != 4 {
			return "", cannotRead("an IPv4 address that is not four decimal numbers")
		}
		for _, label := range labels {
			if !ipv4Part.MatchString(label) {
				return "", cannotRead("an IPv4 address that is not four decimal numbers")
			}
		}
	}
	return host, nil
}

// mapped returns a host as UTS #46 maps it, before any A-label is decoded,
// which lookup does not give. UTS #46 maps each character on its own, then
// normalizes the result to NFC, which joins characters but never makes an
// ASCII one, so a label that starts with xn-- once mapped starts with it here.
// A character that lookup refuses on its own once the whole host converts, a
// joiner, a combining mark or a number of a right-to-left script, stays as it
// is: none maps to x, n, - or a dot.
func mapped(name string) string {
	var b strings.Builder
	for _, r := range name {
		m, err := lookup.ToUnicode(string(r))
		if err != nil {
			m = string(r)
		}
		b.WriteString(m)
	}
	return b.String()
}

// defaultPorts are the default ports of the schemes that normalized URLs have.
var defaultPorts = map[string]uint64{"http": 80, "https": 443}

// Normalized returns the URL normalized as section 4.10 says: the scheme in
// lowercase, the host as url_host reads it, the port only when it is not the
// scheme's default, and the path percent-encoded and normalized as RFC 3986
// says, without the user information, the query and the fragment. It returns
// an error that wraps ErrNoReference for a scheme other than http and https,
// or a backslash in the path.
func (u *URL) Normalized() (string, error) {
	s := strings.ToLower(u.Scheme)
	defaultPort, ok := defaultPorts[s]
	if !ok {
		return "", fmt.Errorf("%w: the scheme %q is not http or https", ErrNoReference, u.Scheme)
	}
	if strings.Contains(u.Path, `\`) {
		return "", fmt.Errorf("%w: a backslash in the path", ErrNoReference)
	}
	s += "://" + u.Host
	if u.Port != "" {
		// ReadURL checked that the port is 1 to 5 digits.
		if n, _ := strconv.ParseUint(u.Port, 10, 32); n != defaultPort {
			s += ":" + strconv.FormatUint(n, 10)
		}
	}
	path := removeDotSegments(normalizePercentEncoding(u.Path))
	if path == "" {
		path = "/"
	}
	return s + path, nil
}

// unreserved reports whether c is an unreserved character (RFC 3986, section
// 2.3).
func unreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0
}

// inSegment reports whether c can be written in a path segment as it is
// (RFC 3986, section 3.3): an unreserved character, a sub-delimiter, : or @.
func inSegment(c byte) bool {
	return unreserved(c) || strings.IndexByte("!$&'()*+,;=:@", c) >= 0
}

// isHex reports whether c is a hexadecimal digit.
func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// normalizePercentEncoding percent-encodes, as UTF-8, each character that
// RFC 3986 does not allow in a path, and each % that two hexadecimal digits do
// not follow; then it writes the hexadecimal digits of every percent-encoded
// octet in uppercase, and decodes those of unreserved characters (RFC 3986,
// section 6.2.2). A segment that is exactly <redacted> stays as it is, so that
// redacting a reference again changes nothing.
func normalizePercentEncoding(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment != Redacted {
			segments[i] = normalizeSegment(segment)
		}
	}
	return strings.Join(segments, "/")
}

// normalizeSegment normalizes the percent-encoding of a path segment, as
// normalizePercentEncoding says.
func normalizeSegment(segment string) string {
	var b strings.Builder
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case c == '%' && i+2 < len(segment) && isHex(segment[i+1]) && isHex(segment[i+2]):
			octet, _ := strconv.ParseUint(segment[i+1:i+3], 16, 8)
			if unreserved(byte(octet)) {
				b.WriteByte(byte(octet))
			} else {
				fmt.Fprintf(&b, "%%%02X", octet)
			}
			i += 2
		case inSegment(c):
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// removeDotSegments removes the dot segments of a path as RFC 3986 says, in
// section 5.2.4.
func removeDotSegments(input string) string {
	var output []string
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			output = output[:max(len(output)-1, 0)]
		case input == "/..":
			input = "/"
			output = output[:max(len(output)-1, 0)]
		case input == "." || input == "..":
			input = ""
		default:
			// The first segment, with its leading slash, up to the next
			// slash.
			next := strings.IndexByte(input[1:], '/') + 1
			if next == 0 {
				next = len(input)
			}
			output = append(output, input[:next])
			input = input[next:]
		}
	}
	return strings.Join(output, "")
}
