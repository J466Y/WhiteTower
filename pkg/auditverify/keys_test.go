package auditverify_test

import (
	"bytes"
	"encoding/base64"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

// The public key of RFC 8037, appendix A.2.
const rfc8037 = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

func TestParseJWK(t *testing.T) {
	key, err := auditverify.ParseJWK([]byte(rfc8037))
	if err != nil {
		t.Fatal(err)
	}
	want, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil || !bytes.Equal(key, want) {
		t.Fatalf("%x, want %x", key, want)
	}
	for name, jwk := range map[string]string{
		"a private key":   `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}`,
		"another curve":   `{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"another type":    `{"kty":"EC","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"a short x":       `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg"}`,
		"x not base64url": `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"not JSON":        `kty=OKP`,
	} {
		if _, err := auditverify.ParseJWK([]byte(jwk)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// A verifier key reads back as the same key under the same name, as the
// tools of signed notes read it.
func TestVerifierKey(t *testing.T) {
	key, err := auditverify.ParseJWK([]byte(rfc8037))
	if err != nil {
		t.Fatal(err)
	}
	vkey, err := auditverify.VerifierKey(origin, key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil || v.Name() != origin {
		t.Fatalf("%q: %v", vkey, err)
	}
	if _, err := auditverify.VerifierKey("an origin with spaces", key); err == nil {
		t.Error("a name with spaces")
	}
}

func TestNewKeys(t *testing.T) {
	key, err := auditverify.ParseJWK([]byte(rfc8037))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := auditverify.NewKeys(origin, key)
	if err != nil || keys.Origin() != origin {
		t.Fatalf("%v %v", keys, err)
	}
	if _, err := auditverify.NewKeys(origin); err == nil {
		t.Error("keys without a key")
	}
	if _, err := auditverify.NewKeys(origin, key[:31]); err == nil {
		t.Error("a short key")
	}
}
