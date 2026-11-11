package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

// TestReadIJSONReadsNumbersByTheirValue checks that the JSON of a bundle
// reads a number by its exact value, whatever its spelling (section 1): an
// integer has a magnitude of at most 2^53 - 1, written with an exponent or a
// fraction of zeros too, and any other number is one that a double holds as
// written. The canonical JSON writes each by its value.
func TestReadIJSONReadsNumbersByTheirValue(t *testing.T) {
	for _, c := range []struct{ number, canonical string }{
		{"9007199254740991", "9007199254740991"},
		{"-9007199254740991.000", "-9007199254740991"},
		{"9.007199254740991e15", "9007199254740991"},
		{"4.2e1", "42"},
		{"4200E-2", "42"},
		{"0.042e+3", "42"},
		{"-0", "0"},
		{"0.0e-7", "0"},
		{"0e99999999999999999999", "0"},
		{"0.1", "0.1"},
		{"5e-324", "5e-324"},
		{"1.5e-7", "1.5e-7"},
		// Refused: integers beyond 2^53 - 1, and numbers that no double
		// holds as written.
		{"9007199254740992", ""},
		{"-9007199254740992", ""},
		{"9.007199254740992e15", ""},
		{"9007199254740992.0", ""},
		{"90071992547409920e-1", ""},
		{"1.5e300", ""},
		{"1e400", ""},
		{"1e99999999999999999999", ""},
		{"42.000000000000001", ""},
		{"0.10000000000000001", ""},
		{"1e-400", ""},
		{"1e-99999999999999999999", ""},
	} {
		got, err := ReadIJSON([]byte("[" + c.number + "]"))
		switch {
		case c.canonical == "" && err == nil:
			t.Errorf("%s: read as %s, want it refused", c.number, got)
		case c.canonical != "" && (err != nil || string(got) != "["+c.canonical+"]"):
			t.Errorf("%s: got %s, %v; want [%s]", c.number, got, err, c.canonical)
		}
	}
}

// TestReadIJSONRefusesWhatIsNotIJSON checks the rest of I-JSON (RFC 7493):
// member names once, at any depth, and strings without a lone surrogate or a
// noncharacter, in names too.
func TestReadIJSONRefusesWhatIsNotIJSON(t *testing.T) {
	for _, c := range []struct {
		text string
		ok   bool
	}{
		{`{"a":1,"b":{"a":1}}`, true},
		{`["😀","😀"]`, true},
		{`{"a":1,"a":1}`, false},
		{`[{"b":{"a":1,"a":2}}]`, false},
		{`["\ud800"]`, false},
		{`["\udc00\ud800"]`, false},
		{`{"￾":1}`, false},
		{`["﷯"]`, false},
		{`["􏿿"]`, false},
		{"[\"\U0001FFFF\"]", false},
		{"\xef\xbb\xbf[]", false},
	} {
		if _, err := ReadIJSON([]byte(c.text)); (err == nil) != c.ok {
			t.Errorf("%s: error %v, want I-JSON %v", c.text, err, c.ok)
		}
	}
}

// FuzzReadIJSONNumbers checks the reading of numbers against math/big's exact
// rationals, for every number whose exponent big.Rat reads.
func FuzzReadIJSONNumbers(f *testing.F) {
	for _, seed := range []string{"9007199254740991", "9.007199254740992e15", "4.2e1", "-0", "0.1", "1e-400", "42.000000000000001", "5e-324"} {
		f.Add(seed)
	}
	number := regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?$`)
	maxInt := new(big.Rat).SetInt64(maxInteger)
	f.Fuzz(func(t *testing.T, n string) {
		exact, ok := new(big.Rat).SetString(n)
		if !number.MatchString(n) || !ok {
			return
		}
		want := new(big.Rat).Abs(exact).Cmp(maxInt) <= 0
		if !exact.IsInt() {
			f, _ := strconv.ParseFloat(n, 64)
			held, ok := new(big.Rat).SetString(strconv.FormatFloat(f, 'g', -1, 64))
			want = ok && held.Cmp(exact) == 0
		}
		if _, err := ReadIJSON([]byte("[" + n + "]")); (err == nil) != want {
			t.Errorf("%s: error %v, want I-JSON %v", n, err, want)
		}
	})
}

// TestParseKeysIgnoresTheKeysItCannotUse checks section 7.3's JWK Set: the
// verifier trusts the OKP keys on Ed25519 that carry a key ID and a public key
// of 32 bytes in base64url, as RFC 7515 defines it, and, as RFC 7517 asks,
// ignores every other key of the set.
func TestParseKeysIgnoresTheKeysItCannotUse(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	set := fmt.Sprintf(`{"keys": [
		{"kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB"},
		{"kty": "OKP", "crv": "X25519", "kid": "x25519", "x": %[1]q},
		{"kty": "OKP", "crv": "Ed25519", "x": %[1]q},
		{"kty": "OKP", "crv": "Ed25519", "kid": "short", "x": "AAAA"},
		{"kty": "OKP", "crv": "Ed25519", "kid": "padded", "x": %[2]q},
		{"kty": "OKP", "crv": "Ed25519", "kid": "line-break", "x": %[3]q},
		{"kty": "OKP", "crv": "Ed25519", "kid": "trusted", "x": %[1]q, "alg": "EdDSA", "use": "sig"}
	]}`, x, x+"=", x[:20]+"\n"+x[20:])

	keys, err := ParseKeys([]byte(set))
	if err != nil {
		t.Fatal(err)
	}
	if want := []Key{{ID: "trusted", Public: pub}}; !slices.EqualFunc(keys, want, func(a, b Key) bool {
		return a.ID == b.ID && a.Public.Equal(b.Public)
	}) {
		t.Errorf("got keys %v, want %v", keys, want)
	}
}

// TestParseKeysRefusesWhatIsNotAJWKSet checks that a document without the
// keys member that RFC 7517 requires is an error, rather than a set that
// trusts nothing.
func TestParseKeysRefusesWhatIsNotAJWKSet(t *testing.T) {
	for _, doc := range []string{
		`not JSON`,
		`[]`,
		`{}`,
		`{"keys": null}`,
		`{"trusted": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "AAAA"}]}`,
	} {
		if _, err := ParseKeys([]byte(doc)); err == nil {
			t.Errorf("%s: no error", doc)
		}
	}
}
