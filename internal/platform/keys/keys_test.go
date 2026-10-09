package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEd25519(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	k, err := LoadEd25519(writePEM(t, "PRIVATE KEY", der))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := k.Sign([]byte("checkpoint"))
	if err != nil || !ed25519.Verify(k.PublicKey(), []byte("checkpoint"), signature) {
		t.Fatalf("the signature does not verify: %v", err)
	}
	if k.Algorithm() != "EdDSA" || k.PublicJWK()["kty"] != "OKP" || k.PublicJWK()["crv"] != "Ed25519" {
		t.Fatalf("JWK %v", k.PublicJWK())
	}
	if _, ok := k.PublicJWK()["d"]; ok {
		t.Fatal("the public JWK holds the private key")
	}
}

// The example of RFC 8037, appendix A.3: the thumbprint of its Ed25519 key.
func TestTheIDIsTheRFC7638Thumbprint(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	if err != nil {
		t.Fatal(err)
	}
	k := NewEd25519(ed25519.NewKeyFromSeed(seed))
	if x := k.PublicJWK()["x"]; x != "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" {
		t.Fatalf("x %s", x)
	}
	if id := k.ID(); id != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("ID %s", id)
	}
}

func TestLoadEd25519RefusesOtherKeys(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		path string
		want string
	}{
		"an ECDSA key":   {writePEM(t, "PRIVATE KEY", pkcs8), "not an Ed25519 private key"},
		"a SEC 1 key":    {writePEM(t, "EC PRIVATE KEY", sec1), "PKCS #8"},
		"a missing file": {filepath.Join(t.TempDir(), "none.pem"), "none.pem"},
	} {
		if _, err := LoadEd25519(tt.path); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want %q", name, err, tt.want)
		}
	}
}
