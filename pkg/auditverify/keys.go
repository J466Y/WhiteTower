package auditverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/note"
)

// Keys are the public keys that may sign a log's checkpoints. The log's
// origin names them.
//
// Take them from somewhere the log's administrators cannot change, such as
// the SIEM, or a copy made when the log was set up: a log rewritten and
// signed again with another key verifies with that other key.
type Keys struct {
	origin    string
	verifiers note.Verifiers
}

// NewKeys returns the keys of the log named origin, from their Ed25519
// public halves.
func NewKeys(origin string, public ...ed25519.PublicKey) (*Keys, error) {
	if len(public) == 0 {
		return nil, errors.New("auditverify: no key")
	}
	verifiers := make([]note.Verifier, 0, len(public))
	seen := map[string]bool{}
	for _, key := range public {
		vkey, err := VerifierKey(origin, key)
		if err != nil {
			return nil, err
		}
		// A key given twice would make every signature of it ambiguous.
		if seen[vkey] {
			continue
		}
		seen[vkey] = true
		v, err := note.NewVerifier(vkey)
		if err != nil {
			return nil, fmt.Errorf("auditverify: %w", err)
		}
		verifiers = append(verifiers, v)
	}
	return &Keys{origin: origin, verifiers: note.VerifierList(verifiers...)}, nil
}

// Origin returns the origin of the log the keys sign for.
func (k *Keys) Origin() string { return k.origin }

// VerifierKey returns an Ed25519 public key in the verifier key format of
// C2SP signed notes, name+hash+key, which golang.org/x/mod/sumdb/note and
// other tools of signed notes read. The name of a checkpoint key is its log's
// origin.
func VerifierKey(name string, public ed25519.PublicKey) (string, error) {
	vkey, err := note.NewEd25519VerifierKey(name, public)
	if err == nil {
		// It does not check the name, which the tools that read the key do.
		_, err = note.NewVerifier(vkey)
	}
	if err != nil {
		return "", fmt.Errorf("auditverify: %w", err)
	}
	return vkey, nil
}

// ParseJWK reads an Ed25519 public key in the JSON Web Key format of RFC 8037,
// in which White Tower publishes its checkpoint keys. It refuses a key with a
// private part, which a verifier never needs.
func ParseJWK(jwk []byte) (ed25519.PublicKey, error) {
	var key struct {
		Kty string  `json:"kty"`
		Crv string  `json:"crv"`
		X   string  `json:"x"`
		D   *string `json:"d"`
	}
	if err := json.Unmarshal(jwk, &key); err != nil {
		return nil, fmt.Errorf("auditverify: key: %w", err)
	}
	switch {
	case key.D != nil:
		return nil, errors.New("auditverify: key: a private key, where a public one was expected")
	case key.Kty != "OKP" || key.Crv != "Ed25519":
		return nil, fmt.Errorf("auditverify: key: type %q and curve %q: not an Ed25519 key", key.Kty, key.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, errors.New("auditverify: key: x is not an Ed25519 public key")
	}
	return ed25519.PublicKey(x), nil
}
