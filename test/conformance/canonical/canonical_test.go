package canonical_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gowebpki/jcs"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
)

// transform parses data and writes its canonical JSON.
func transform(data []byte) ([]byte, error) {
	v, err := canonical.Parse(data)
	if err != nil {
		return nil, err
	}
	return canonical.Encode(v)
}

// written are JSON texts with their canonical JSON (section 4.10).
var written = []struct{ name, text, want string }{
	{"literals and whitespace", " [true ,\tfalse,\r\nnull] ", `[true,false,null]`},
	{"integers beyond 2^53 - 1, exactly", `[9007199254740993,18446744073709551615,-9223372036854775809]`, `[9007199254740993,18446744073709551615,-9223372036854775809]`},
	{"an integer of more than 309 digits", "[1" + strings.Repeat("0", 400) + "]", "[1" + strings.Repeat("0", 400) + "]"},
	{"minus zero, as an integer", `[-0,0]`, `[0,0]`},
	{"whole doubles", `[1.0,-0.0,1e3,1E20,1e21,2.50e+1]`, `[1,0,1000,100000000000000000000,1e+21,25]`},
	{"other doubles", `[0.1,1e-6,1e-7,-1.5e-7,123.456,5e-324]`, `[0.1,0.000001,1e-7,-1.5e-7,123.456,5e-324]`},
	{"a double below the smallest", `[1e-400,-2e-324]`, `[0,0]`},
	{"a double rounded", `[9007199254740993.0,0.10000000000000001]`, `[9007199254740992,0.1]`},
	{"escapes", `["\"\\\/\b\f\n\r\t\u0000\u001F\u007fé <>&"]`, "[\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0000\\u001f\u007fé <>&\"]"},
	{"a surrogate pair", "[\"\\ud83d\\ude00\"]", "[\"\U0001F600\"]"},
	{"members in the order of UTF-16 code units", "{\"\U0000FF61\":1,\"\U0001F600\":2,\"b\":3,\"a\":4,\"B\":5}", "{\"B\":5,\"a\":4,\"b\":3,\"\U0001F600\":2,\"\U0000FF61\":1}"},
	{"nested and empty", `{"b":[{"d":{},"c":[]}],"a":{"z":null,"y":"x"}}`, `{"a":{"y":"x","z":null},"b":[{"c":[],"d":{}}]}`},
	{"a scalar alone", ` "x" `, `"x"`},
}

func TestEncodeWritesTheCanonicalJSONOfSection410(t *testing.T) {
	for _, tt := range written {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transform([]byte(tt.text))
			if err != nil || string(got) != tt.want {
				t.Errorf("got %s, %v; want %s", got, err, tt.want)
			}
		})
	}
}

// unwritable are JSON texts that canonical JSON cannot write.
var unwritable = []struct{ name, text string }{
	{"a number beyond a double", `[1e400]`},
	{"a negative number beyond a double", `{"a":[-1.5e309]}`},
	{"a member name twice", `{"a":1,"b":2,"a":1}`},
	{"a member name twice, deeper", `[{"x":{"a":1,"a":2}}]`},
	{"a member name twice, written two ways", "{\"a\":1,\"\\u0061\":2}"},
	{"a lone high surrogate", `["\ud800"]`},
	{"a high surrogate before a pair", `["\ud800𐀀"]`},
	{"a low surrogate first", `["\udc00\ud800"]`},
	{"a high surrogate before a character that is not a low surrogate", `["\ud800A"]`},
	{"a lone surrogate in a member name", `{"\udfff":1}`},
}

func TestEncodeRefusesWhatCanonicalJSONCannotWrite(t *testing.T) {
	for _, tt := range unwritable {
		t.Run(tt.name, func(t *testing.T) {
			v, err := canonical.Parse([]byte(tt.text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got, err := canonical.Encode(v); !errors.Is(err, canonical.ErrNoCanonicalJSON) {
				t.Errorf("got %s, %v; want ErrNoCanonicalJSON", got, err)
			}
		})
	}
}

// notJSON are texts that RFC 8259, or section 1, does not take as JSON.
var notJSON = []struct{ name, text string }{
	{"nothing", ""},
	{"whitespace only", " \n"},
	{"a byte order mark", "\xef\xbb\xbf{}"},
	{"bytes that are not UTF-8", "[\"\xff\"]"},
	{"a second value", `{} {}`},
	{"a leading zero", `[01]`},
	{"a plus sign", `[+1]`},
	{"a fraction without digits", `[1.]`},
	{"a fraction without an integer", `[.5]`},
	{"an exponent without digits", `[1e+]`},
	{"NaN", `[NaN]`},
	{"Infinity", `[-Infinity]`},
	{"a hexadecimal number", `[0x10]`},
	{"a control character in a string", "[\"a\tb\"]"},
	{"an unknown escape", `["\x41"]`},
	{"a short \\u escape", `["\u12"]`},
	{"a \\u escape with a sign", `["\u+123"]`},
	{"a string that does not end", `["abc`},
	{"a single quote", `['a']`},
	{"a trailing comma in an array", `[1,]`},
	{"a trailing comma in an object", `{"a":1,}`},
	{"a member name that is not a string", `{a:1}`},
	{"a member without a colon", `{"a" 1}`},
	{"an array that does not end", `[1`},
	{"a literal in capitals", `[True]`},
	{"a truncated literal", `[nul]`},
	{"a comment", `[1 /* one */]`},
}

func TestParseRefusesWhatIsNotJSON(t *testing.T) {
	for _, tt := range notJSON {
		t.Run(tt.name, func(t *testing.T) {
			if v, err := canonical.Parse([]byte(tt.text)); err == nil {
				t.Errorf("got %#v, want an error", v)
			}
		})
	}
}

func TestAStringKeepsItsLoneSurrogates(t *testing.T) {
	v, err := canonical.Parse([]byte(`"a\udc00\ud800b😀"`))
	if err != nil {
		t.Fatal(err)
	}
	s := v.(canonical.String)
	if !s.HasLoneSurrogate() {
		t.Error("HasLoneSurrogate is false")
	}
	if got, want := s.String(), "a\U0000FFFD\U0000FFFDb\U0001F600"; got != want {
		t.Errorf("String() = %q, want %q: each lone surrogate replaced by U+FFFD", got, want)
	}
	if v, err = canonical.Parse([]byte("\"\\ud83d\\ude00\"")); err != nil || v.(canonical.String).HasLoneSurrogate() {
		t.Errorf("a surrogate pair: HasLoneSurrogate is true (%v)", err)
	}
}

// FuzzTransform checks the reader against encoding/json, and the writer
// against gowebpki/jcs where RFC 8785 and section 4.10 agree: on text without
// an integer beyond 15 digits, which jcs reads as a double.
func FuzzTransform(f *testing.F) {
	for _, tt := range written {
		f.Add([]byte(tt.text))
	}
	for _, tt := range unwritable {
		f.Add([]byte(tt.text))
	}
	for _, tt := range notJSON {
		f.Add([]byte(tt.text))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := canonical.Parse(data)
		if utf8.Valid(data) && (err == nil) != json.Valid(data) {
			t.Fatalf("Parse says %v, encoding/json says valid=%v", err, json.Valid(data))
		}
		if err != nil {
			return
		}
		got, err := canonical.Encode(v)
		want, jcsErr := jcs.Transform(data)
		switch {
		case err != nil && !errors.Is(err, canonical.ErrNoCanonicalJSON):
			t.Fatalf("Encode: %v", err)
		case err != nil && jcsErr == nil:
			t.Fatalf("Encode refuses what jcs writes as %s: %v", want, err)
		case err != nil:
			return
		}
		if again, err := transform(got); err != nil || !bytes.Equal(again, got) {
			t.Fatalf("the canonical JSON %s is not its own canonical JSON: %s, %v", got, again, err)
		}
		if shortIntegers(v) && (jcsErr != nil || !bytes.Equal(got, want)) {
			t.Fatalf("got %s, jcs writes %s (%v)", got, want, jcsErr)
		}
	})
}

// shortIntegers reports whether every number of v written without a fraction
// or an exponent has at most 15 digits, so that a double holds it exactly.
func shortIntegers(v any) bool {
	switch v := v.(type) {
	case canonical.Number:
		return strings.ContainsAny(string(v), ".eE") || len(strings.TrimPrefix(string(v), "-")) <= 15
	case []any:
		for _, item := range v {
			if !shortIntegers(item) {
				return false
			}
		}
	case canonical.Object:
		for _, m := range v {
			if !shortIntegers(m.Value) {
				return false
			}
		}
	}
	return true
}
