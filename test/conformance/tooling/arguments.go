package tooling

import (
	"cmp"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
)

// ErrInvalidArgument is the error of a call's arguments that EP-19 denies with
// error.invalid_request (section 6.11): a declared argument whose value does
// not fit its declared type, or that its transform cannot read.
var ErrInvalidArgument = errors.New("the arguments do not fit their declarations")

// Argument is an argument that a tool's catalog entry declares (section 7.7).
type Argument struct {
	// Name is its key in the tool's record of context.args: its path, the
	// property names joined with ., followed by : and its transform when it
	// has one.
	Name string `json:"name"`
	// Path is the names of the properties that lead to it, through objects
	// only.
	Path []string `json:"path"`
	// Transform is lowercase, path, url_host or email_domain, or empty.
	Transform string `json:"transform"`
	// Type is its type as Cedar names it: String, Long, Bool, Set<String> or
	// Set<Long>.
	Type string `json:"type"`
}

// Record returns a tool's record of context.args as EP-19 fills it from the
// call's arguments, given as JSON text, or nil when the call has none, which
// reads as an empty object: each declared argument that the arguments have,
// under its name, with its transform applied, and nothing else. A string is a
// string, an integer an int64, a boolean a bool, and a set a slice of its
// distinct elements in ascending order. A missing argument is left out, so
// that usage rules apply if_absent.
//
// Record returns an error that wraps ErrInvalidArgument when EP-19 denies the
// call: arguments that are not a JSON object, or that repeat a member name,
// whatever the tool declares; a path through a value that is not an object, or
// through an object that repeats a member name; and a declared argument's value
// that does not fit its type, null and a string with a lone surrogate
// included, or that its transform cannot read.
func Record(arguments []byte, declared []Argument) (map[string]any, error) {
	var args any = canonical.Object{}
	if arguments != nil {
		var err error
		if args, err = canonical.Parse(arguments); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
		}
	}
	obj, ok := args.(canonical.Object)
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: the arguments are not an object", ErrInvalidArgument)
	case obj.HasRepeatedName():
		return nil, fmt.Errorf("%w: a member name repeats in the arguments", ErrInvalidArgument)
	}
	record := map[string]any{}
	for _, arg := range declared {
		v, found, err := find(obj, arg.Path)
		if err == nil && found {
			record[arg.Name], err = fit(v, arg.Type, arg.Transform)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", arg.Name, err)
		}
	}
	return record, nil
}

// find returns the value at a path of property names, and whether the
// arguments have it.
func find(v any, names []string) (any, bool, error) {
	for _, name := range names {
		obj, ok := v.(canonical.Object)
		switch {
		case !ok:
			return nil, false, fmt.Errorf("%w: the path goes through a value that is not an object", ErrInvalidArgument)
		case obj.HasRepeatedName():
			return nil, false, fmt.Errorf("%w: a member name repeats in an object that the path reads", ErrInvalidArgument)
		}
		if v, ok = member(obj, name); !ok {
			return nil, false, nil
		}
	}
	return v, true, nil
}

// fit returns a value as its declared type holds it, with the transform
// applied to each string.
func fit(v any, typ, transform string) (any, error) {
	switch typ {
	case "String":
		return fitString(v, transform)
	case "Long":
		return fitLong(v)
	case "Bool":
		if b, ok := v.(bool); ok {
			return b, nil
		}
		return nil, fmt.Errorf("%w: not a boolean", ErrInvalidArgument)
	case "Set<String>":
		return fitSet(v, func(item any) (string, error) { return fitString(item, transform) })
	case "Set<Long>":
		return fitSet(v, fitLong)
	}
	return nil, fmt.Errorf("the type %q is not one that section 7.7 names", typ)
}

// fitString returns a string with the transform applied, if there is one.
func fitString(v any, transform string) (string, error) {
	s, ok := v.(canonical.String)
	switch {
	case !ok:
		return "", fmt.Errorf("%w: not a string", ErrInvalidArgument)
	case s.HasLoneSurrogate():
		return "", fmt.Errorf("%w: a string with a lone surrogate", ErrInvalidArgument)
	case transform == "":
		return s.String(), nil
	}
	t, err := Transform(transform, s.String())
	if errors.Is(err, ErrCannotRead) {
		return "", fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return t, err
}

// fitLong returns a signed 64-bit integer, written without a fraction or an
// exponent (section 6.4).
func fitLong(v any) (int64, error) {
	n, ok := v.(canonical.Number)
	if !ok {
		return 0, fmt.Errorf("%w: not a number", ErrInvalidArgument)
	}
	// In base 10, ParseInt takes an optional sign and decimal digits only, and
	// refuses a value outside int64.
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: not a signed 64-bit integer without a fraction or an exponent", ErrInvalidArgument)
	}
	return i, nil
}

// fitSet returns an array as a set: the distinct values of its items, each
// fitted by fitItem, in ascending order.
func fitSet[T cmp.Ordered](v any, fitItem func(any) (T, error)) ([]T, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: not an array", ErrInvalidArgument)
	}
	set := make([]T, 0, len(items))
	for _, item := range items {
		x, err := fitItem(item)
		if err != nil {
			return nil, err
		}
		set = append(set, x)
	}
	slices.Sort(set)
	return slices.Compact(set), nil
}

// Transform applies a transform of section 6.11 to a string: lowercase, path,
// url_host or email_domain. It returns an error that wraps ErrCannotRead for a
// value that the transform cannot read, and for text that is not UTF-8, which
// no JSON string can hold.
func Transform(name, value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", cannotRead("the value is not UTF-8")
	}
	switch name {
	case "lowercase":
		return asciiLower(value), nil
	case "path":
		return cleanPath(value)
	case "url_host":
		u, err := ReadURL(value)
		if err != nil {
			return "", err
		}
		return u.Host, nil
	case "email_domain":
		return emailDomain(value)
	}
	return "", fmt.Errorf("the transform %q is not one that section 6.11 defines", name)
}

// asciiLower returns s with ASCII letters in lowercase and every other
// character as it is, so that no Unicode case mapping changes it: the
// lowercase transform, and how EP-14 compares names.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// cleanPath cleans a path as the path transform does: a value with a control
// character cannot be read, and once backslashes are slashes, the path is what
// path.Clean gives, which steps 3 and 4 describe.
func cleanPath(value string) (string, error) {
	if strings.IndexFunc(value, isControl) >= 0 {
		return "", cannotRead("a control character")
	}
	return path.Clean(strings.ReplaceAll(value, `\`, "/")), nil
}

// emailDomain reads the domain of an address as email_domain does, step by
// step.
func emailDomain(value string) (string, error) {
	// 1. Leading and trailing spaces are ignored, and a control character
	// anywhere cannot be read: unicode.IsControl is Unicode's Cc category, C1
	// included.
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", cannotRead("a control character")
	}
	// 2. The address, alone or after a name.
	address, err := angleAddress(strings.Trim(value, " "))
	if err != nil {
		return "", err
	}
	// 3. Exactly one @, and a local part that is not empty, without
	// whitespace, Unicode's White_Space property, or the characters that
	// parsers read differently.
	local, domain, _ := strings.Cut(address, "@")
	if strings.Count(address, "@") != 1 {
		return "", cannotRead("not exactly one @")
	}
	if local == "" || strings.IndexFunc(local, func(r rune) bool {
		return unicode.Is(unicode.White_Space, r) || strings.ContainsRune(`"()<>[]\,;:`, r)
	}) >= 0 {
		return "", cannotRead("an empty local part, or one with a character it may not have")
	}
	// 4. The domain, as url_host reads a host. Brackets and colons are
	// characters that a host cannot have, so neither an IPv6 address nor a
	// domain literal can be read.
	host, err := readHost(domain)
	if err != nil {
		return "", err
	}
	if labels := strings.Split(host, "."); number.MatchString(labels[len(labels)-1]) {
		return "", cannotRead("a domain whose last label is a number")
	}
	return host, nil
}

// angleAddress returns the address of a value as step 2 of email_domain reads
// it: the value itself; Display Name <address>, whose name may be empty, with
// no quote, angle bracket, @, ",", ";", ":", parenthesis, square bracket or
// backslash in the name; or "Quoted Name" <address>, with no quote or
// backslash between the quotes. A name that is not empty is followed by at
// least one space before <.
func angleAddress(text string) (string, error) {
	var rest string
	if quoted, ok := strings.CutPrefix(text, `"`); ok {
		name, after, closed := strings.Cut(quoted, `"`)
		if !closed || strings.Contains(name, `\`) {
			return "", cannotRead("a quoted name without its closing quote, or with a backslash")
		}
		if rest = strings.TrimLeft(after, " "); rest == after {
			return "", cannotRead("no space after a quoted name")
		}
	} else if strings.HasSuffix(text, ">") {
		i := strings.IndexByte(text, '<')
		if i < 0 || strings.ContainsAny(text[:i], `"<>@,;:()[]\`) || i > 0 && text[i-1] != ' ' {
			return "", cannotRead("a display name with a character it may not have, or no space after it")
		}
		rest = text[i:]
	} else {
		return text, nil
	}
	address, opened := strings.CutPrefix(rest, "<")
	address, closed := strings.CutSuffix(address, ">")
	if !opened || !closed {
		return "", cannotRead("no <address> after a name")
	}
	return address, nil
}
