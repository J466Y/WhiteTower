// Package keys holds the core's signing keys (plan P1-05, step 1; ADR-0006):
// one per purpose, of the token, bundle and checkpoint keys of the
// architecture. A key's private half is read from a file, a Kubernetes
// Secret mounted as one, and never enters the database, which keeps only
// public halves, as JWKs.
//
// Ed25519 keys come first, for the audit log's checkpoints; P1-05 adds ES256
// and rotation.
package keys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Signer signs with the private key of one purpose.
type Signer interface {
	// ID is the key's RFC 7638 JWK thumbprint.
	ID() string
	// Algorithm is the key's JOSE algorithm.
	Algorithm() string
	// PublicJWK is the key's public half, as a JWK.
	PublicJWK() map[string]string
	// Public is the key's public half.
	Public() crypto.PublicKey
	// Sign signs message.
	Sign(message []byte) ([]byte, error)
}

// Ed25519 is an Ed25519 key (RFC 8032), as a JWK of type OKP (RFC 8037).
type Ed25519 struct {
	private ed25519.PrivateKey
}

var _ Signer = Ed25519{}

// NewEd25519 returns the signer of an Ed25519 private key.
func NewEd25519(private ed25519.PrivateKey) Ed25519 { return Ed25519{private: private} }

// LoadEd25519 reads an Ed25519 private key from a PEM file in PKCS #8, as
// `openssl genpkey -algorithm ed25519` writes it.
func LoadEd25519(path string) (Ed25519, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return Ed25519{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return Ed25519{}, fmt.Errorf("%s: not a PEM private key in PKCS #8 (BEGIN PRIVATE KEY)", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Ed25519{}, fmt.Errorf("%s: %w", path, err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return Ed25519{}, fmt.Errorf("%s: a %T, not an Ed25519 private key", path, key)
	}
	return Ed25519{private: private}, nil
}

// ID implements Signer.
func (k Ed25519) ID() string {
	// The required members of an OKP key, sorted, without spaces (RFC 7638,
	// section 3.2; RFC 8037, section 2).
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + k.PublicJWK()["x"] + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Algorithm implements Signer.
func (Ed25519) Algorithm() string { return "EdDSA" }

// PublicJWK implements Signer.
func (k Ed25519) PublicJWK() map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(k.PublicKey())}
}

// Public implements Signer.
func (k Ed25519) Public() crypto.PublicKey { return k.PublicKey() }

// PublicKey returns the key's public half.
func (k Ed25519) PublicKey() ed25519.PublicKey {
	public, _ := k.private.Public().(ed25519.PublicKey)
	return public
}

// Sign implements Signer.
func (k Ed25519) Sign(message []byte) ([]byte, error) {
	if len(k.private) != ed25519.PrivateKeySize {
		return nil, errors.New("keys: no Ed25519 private key")
	}
	return ed25519.Sign(k.private, message), nil
}
