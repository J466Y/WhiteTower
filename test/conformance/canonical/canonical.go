// Package canonical reads JSON text and writes it as the canonical JSON of
// section 4.10 of the module contracts (docs/contracts/module-contract-v0.1.md):
// RFC 8785, except that a number written without a fraction or an exponent is
// written as its exact value, whatever its size. Definition hashes (section
// 4.10) and the hashed mode of arguments (section 8.3) use it. It is the
// reference that their vectors are checked with. gowebpki/jcs cannot be:
// it rounds integers beyond 2^53 - 1, and refuses those of more than 309
// digits.
//
// Parse keeps what canonical JSON cannot write: a member name that repeats, a
// lone surrogate and the text of every number. Encode refuses them, so that
// each use decides what it leaves out: a definition hash looks only at the
// members that it covers, and the hashed mode records the arguments' names.
package canonical

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// ErrNoCanonicalJSON is the error of a value that section 4.10's canonical
// JSON cannot write: a number with a fraction or an exponent that is not
// finite as a double, a member name that repeats, or a string with a lone
// surrogate.
var ErrNoCanonicalJSON = errors.New("no canonical JSON")

// Number is a number, as its text is written.
type Number string

// String is a string as its UTF-16 code units, so that it keeps a lone
// surrogate, which a Go string cannot hold, and compares as RFC 8785 sorts
// member names.
type String []uint16

// Object is an object's members, in their order, repeated names included.
type Object []Member

// Member is a member of an object.
type Member struct {
	Name  String
	Value any
}

// String returns s with each lone surrogate replaced by U+FFFD.
func (s String) String() string {
	return string(utf16.Decode(s))
}

// HasLoneSurrogate reports whether s holds a surrogate that is not part of a
// pair: a low surrogate first, or a high surrogate without a low one after it.
func (s String) HasLoneSurrogate() bool {
	for i := 0; i < len(s); i++ {
		switch u := s[i]; {
		case !utf16.IsSurrogate(rune(u)):
		case u < 0xDC00 && i+1 < len(s) && 0xDC00 <= s[i+1] && s[i+1] <= 0xDFFF:
			i++
		default:
			return true
		}
	}
	return false
}

// HasRepeatedName reports whether two of o's members have the same name.
func (o Object) HasRepeatedName() bool {
	names := make([]String, len(o))
	for i, m := range o {
		names[i] = m.Name
	}
	slices.SortFunc(names, func(a, b String) int { return slices.Compare(a, b) })
	for i := 1; i < len(names); i++ {
		if slices.Equal(names[i-1], names[i]) {
			return true
		}
	}
	return false
}

// Parse reads one JSON value (RFC 8259), in UTF-8 without a byte order mark
// (section 1), with nothing around it but whitespace. It returns nil, a bool,
// a Number, a String, an []any or an Object.
func Parse(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("the text is not UTF-8")
	}
	p := parser{data: data}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.data) {
		return nil, p.errorAt("something follows the value")
	}
	return v, nil
}

// parser reads JSON text from its position i.
type parser struct {
	data []byte
	i    int
}

// number is the grammar of a number in RFC 8259.
var number = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?`)

// literals are the values that JSON writes as words.
var literals = []struct {
	text  string
	value any
}{{"true", true}, {"false", false}, {"null", nil}}

// errorAt returns an error that says what is wrong at the parser's position.
func (p *parser) errorAt(what string) error {
	return fmt.Errorf("byte %d: %s", p.i, what)
}

// space skips whitespace.
func (p *parser) space() {
	for p.i < len(p.data) && strings.IndexByte(" \t\n\r", p.data[p.i]) >= 0 {
		p.i++
	}
}

// consume skips c, if it comes next.
func (p *parser) consume(c byte) bool {
	if p.i < len(p.data) && p.data[p.i] == c {
		p.i++
		return true
	}
	return false
}

func (p *parser) value() (any, error) {
	p.space()
	if p.i == len(p.data) {
		return nil, p.errorAt("the text ends where a value should start")
	}
	switch p.data[p.i] {
	case '{':
		return p.object()
	case '[':
		return p.array()
	case '"':
		return p.string()
	}
	if loc := number.FindIndex(p.data[p.i:]); loc != nil {
		n := Number(p.data[p.i : p.i+loc[1]])
		p.i += loc[1]
		return n, nil
	}
	for _, l := range literals {
		if bytes.HasPrefix(p.data[p.i:], []byte(l.text)) {
			p.i += len(l.text)
			return l.value, nil
		}
	}
	return nil, p.errorAt("no value starts here")
}

func (p *parser) object() (Object, error) {
	p.i++
	obj := Object{}
	if p.space(); p.consume('}') {
		return obj, nil
	}
	for {
		if p.space(); p.i == len(p.data) || p.data[p.i] != '"' {
			return nil, p.errorAt("a member name should start here")
		}
		name, err := p.string()
		if err != nil {
			return nil, err
		}
		if p.space(); !p.consume(':') {
			return nil, p.errorAt("a colon should follow the member name")
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		obj = append(obj, Member{Name: name, Value: v})
		p.space()
		if p.consume('}') {
			return obj, nil
		}
		if !p.consume(',') {
			return nil, p.errorAt("a comma or the end of the object should follow a member")
		}
	}
}

func (p *parser) array() ([]any, error) {
	p.i++
	items := []any{}
	if p.space(); p.consume(']') {
		return items, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		items = append(items, v)
		p.space()
		if p.consume(']') {
			return items, nil
		}
		if !p.consume(',') {
			return nil, p.errorAt("a comma or the end of the array should follow an item")
		}
	}
}

// escapes are the escapes of RFC 8259 that stand for one character.
var escapes = map[byte]uint16{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

// string reads a string. A \u escape gives one UTF-16 code unit, so a lone
// surrogate stays as it is written.
func (p *parser) string() (String, error) {
	p.i++
	s := String{}
	for {
		if p.i == len(p.data) {
			return nil, p.errorAt("the text ends inside a string")
		}
		switch c := p.data[p.i]; {
		case c == '"':
			p.i++
			return s, nil
		case c < 0x20:
			return nil, p.errorAt("a control character inside a string")
		case c == '\\':
			u, err := p.escape()
			if err != nil {
				return nil, err
			}
			s = append(s, u)
		default:
			r, size := utf8.DecodeRune(p.data[p.i:])
			s = utf16.AppendRune(s, r)
			p.i += size
		}
	}
}

// escape reads the escape that starts at the backslash at i.
func (p *parser) escape() (uint16, error) {
	rest := p.data[p.i+1:]
	if len(rest) > 0 && rest[0] == 'u' {
		// In base 16, ParseUint takes hexadecimal digits only: no sign, no
		// prefix and no underscore.
		if len(rest) >= 5 {
			if u, err := strconv.ParseUint(string(rest[1:5]), 16, 16); err == nil {
				p.i += 6
				return uint16(u), nil
			}
		}
		return 0, p.errorAt("a \\u escape without four hexadecimal digits")
	}
	if len(rest) > 0 {
		if u, ok := escapes[rest[0]]; ok {
			p.i += 2
			return u, nil
		}
	}
	return 0, p.errorAt("an escape that JSON does not have")
}

// Encode writes the canonical JSON of a value that Parse returned, or of one
// built from the same types. It returns an error that wraps
// ErrNoCanonicalJSON for a value that canonical JSON cannot write.
func Encode(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func encode(b *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case Number:
		return encodeNumber(b, v)
	case String:
		return encodeString(b, v)
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case Object:
		if v.HasRepeatedName() {
			return fmt.Errorf("%w: a member name repeats", ErrNoCanonicalJSON)
		}
		members := slices.Clone(v)
		slices.SortFunc(members, func(a, b Member) int { return slices.Compare(a.Name, b.Name) })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeString(b, m.Name); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := encode(b, m.Value); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("a value of type %T is not JSON", v)
	}
	return nil
}

// encodeNumber writes a number without a fraction or an exponent as its exact
// value, which its text already is but for -0, and any other as RFC 8785 says,
// from its value as a double (section 4.10).
func encodeNumber(b *bytes.Buffer, n Number) error {
	if !strings.ContainsAny(string(n), ".eE") {
		if n == "-0" {
			n = "0"
		}
		b.WriteString(string(n))
		return nil
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if errors.Is(err, strconv.ErrRange) {
		return fmt.Errorf("%w: a number is not finite as a double", ErrNoCanonicalJSON)
	}
	if err != nil {
		return fmt.Errorf("%q is not a number: %w", string(n), err)
	}
	text, err := jcs.NumberToJSON(f)
	if err != nil {
		return err
	}
	b.WriteString(text)
	return nil
}

// encodeString writes a string as RFC 8785 does: a quote, a backslash and the
// control characters escaped, the five that have one with their short escape,
// and every other character as it is, in UTF-8.
func encodeString(b *bytes.Buffer, s String) error {
	if s.HasLoneSurrogate() {
		return fmt.Errorf("%w: a string has a lone surrogate", ErrNoCanonicalJSON)
	}
	b.WriteByte('"')
	for _, r := range s.String() {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
