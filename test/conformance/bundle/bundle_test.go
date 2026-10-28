package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"slices"
	"testing"
)

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
