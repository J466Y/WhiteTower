// Package bundle implements the White Tower policy bundle format
// whitetower.bundle.v1: canonical manifests, detached JWS signatures with
// Ed25519 keys, and the verification an enforcement point performs before it
// activates a bundle (docs/contracts/module-contract-v0.1.md, section 7).
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/gowebpki/jcs"
)

// Format constants of whitetower.bundle.v1.
const (
	Format             = "whitetower.bundle.v1"
	CombiningAlgorithm = "wt-deny-overrides-v1"
	// Algorithm is the JWS algorithm: EdDSA with Ed25519 keys (RFC 8037).
	Algorithm = "EdDSA"
	// Type is the JWS "typ" header of bundle signatures.
	Type = "whitetower-bundle+jws"
	// CedarSchemaPath is where a bundle carries its Cedar schema.
	CedarSchemaPath = "schema.cedarschema"
	// MaxSize is the largest bundle, manifest and files together, in bytes.
	MaxSize = 2 << 20
	// MaxFiles is the largest number of files in a bundle.
	MaxFiles = 1000
)

// Rejection reasons (contract, section 7.5).
const (
	ReasonOversized        = "oversized"
	ReasonUnknownKey       = "unknown_key"
	ReasonSignature        = "signature"
	ReasonManifestMismatch = "manifest_mismatch"
	ReasonInvalidManifest  = "invalid_manifest"
	ReasonUnsupported      = "unsupported"
	ReasonMissingFile      = "missing_file"
	ReasonFileHash         = "file_hash"
	ReasonExtraFile        = "extra_file"
	ReasonOlderVersion     = "older_version"
	ReasonParseError       = "parse_error"
)

// RejectError is returned when a bundle must not be activated.
type RejectError struct {
	Reason string
	Detail string
}

func (e *RejectError) Error() string { return e.Reason + ": " + e.Detail }

func reject(reason, format string, args ...any) error {
	return &RejectError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Manifest is the signed description of a bundle.
type Manifest struct {
	Format             string        `json:"format"`
	AgentID            string        `json:"agent_id"`
	Version            uint64        `json:"version"`
	CreatedAt          string        `json:"created_at"`
	CombiningAlgorithm string        `json:"combining_algorithm"`
	Language           string        `json:"language"`
	CedarSchema        *File         `json:"cedar_schema,omitempty"`
	Policies           []PolicyEntry `json:"policies"`
}

// PolicyEntry lists one policy of the bundle.
type PolicyEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version uint64 `json:"version"`
	Scope   string `json:"scope"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
}

// File is a file of the bundle other than a policy.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Bundle is a manifest, its signature and its files.
type Bundle struct {
	// Manifest holds the exact signed bytes.
	Manifest  []byte
	Signature string
	Files     map[string][]byte
}

// Ref is how governance state refers to a bundle.
type Ref struct {
	Version        uint64 `json:"version"`
	ManifestSHA256 string `json:"manifest_sha256"`
	SizeBytes      uint64 `json:"size_bytes"`
}

// Size returns the size of the manifest and the files, in bytes.
func (b *Bundle) Size() uint64 {
	n := uint64(len(b.Manifest))
	for _, content := range b.Files {
		n += uint64(len(content))
	}
	return n
}

// Ref returns the reference governance state would carry for the bundle.
func (b *Bundle) Ref(version uint64) Ref {
	return Ref{Version: version, ManifestSHA256: SHA256Hex(b.Manifest), SizeBytes: b.Size()}
}

// SHA256Hex returns the lowercase hexadecimal SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Canonical returns the RFC 8785 canonical JSON of v.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// Key is a public key trusted to verify bundles.
type Key struct {
	ID     string
	Public ed25519.PublicKey
}

// KeyID returns the RFC 7638 JWK thumbprint of an Ed25519 public key, the
// recommended key ID.
func KeyID(pub ed25519.PublicKey) string {
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Build hashes the files into the manifest, canonicalizes it and signs it.
func Build(m Manifest, files map[string][]byte, keyID string, priv ed25519.PrivateKey) (*Bundle, error) {
	for i := range m.Policies {
		content, ok := files[m.Policies[i].Path]
		if !ok {
			return nil, fmt.Errorf("no file for %s", m.Policies[i].Path)
		}
		m.Policies[i].SHA256 = SHA256Hex(content)
	}
	if m.CedarSchema != nil {
		content, ok := files[m.CedarSchema.Path]
		if !ok {
			return nil, fmt.Errorf("no file for %s", m.CedarSchema.Path)
		}
		m.CedarSchema.SHA256 = SHA256Hex(content)
	}
	manifest, err := Canonical(m)
	if err != nil {
		return nil, err
	}
	return &Bundle{Manifest: manifest, Signature: Sign(manifest, keyID, priv), Files: maps.Clone(files)}, nil
}

// Sign returns a JWS compact serialization with a detached payload
// (RFC 7515, appendix F) over payload.
func Sign(payload []byte, keyID string, priv ed25519.PrivateKey) string {
	header, _ := json.Marshal(map[string]string{"alg": Algorithm, "kid": keyID, "typ": Type})
	protected := base64.RawURLEncoding.EncodeToString(header)
	input := protected + "." + base64.RawURLEncoding.EncodeToString(payload)
	return protected + ".." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
}

// Expectation is what the enforcement point knows before it verifies a bundle.
type Expectation struct {
	// The agent the bundle must be for.
	AgentID string
	// The reference received in the agent's governance state.
	Ref Ref
	// The active bundle, if any (version 0 when none).
	ActiveVersion uint64
	ActiveSHA256  string
	// Languages the enforcement point evaluates.
	Languages []string
}

var policyPath = regexp.MustCompile(`^policies/(global|agent)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(cedar|rego)$`)

// Verify applies the verification steps of section 7.4 in order and returns
// the manifest, or a *RejectError. A bundle whose version and hash equal the
// active one's verifies; the caller then has nothing to activate.
func Verify(b *Bundle, trusted []Key, want Expectation) (*Manifest, error) {
	// V1. Size.
	if want.Ref.SizeBytes > MaxSize || b.Size() > MaxSize || len(b.Files) > MaxFiles {
		return nil, reject(ReasonOversized, "%d bytes in %d files", b.Size(), len(b.Files))
	}

	// V2. Signature over the exact manifest bytes.
	parts := strings.Split(b.Signature, ".")
	if len(parts) != 3 || parts[1] != "" {
		return nil, reject(ReasonSignature, "not a JWS with a detached payload")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, reject(ReasonSignature, "header encoding: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, reject(ReasonSignature, "header: %v", err)
	}
	if len(header) != 3 || header["alg"] != Algorithm || header["typ"] != Type {
		return nil, reject(ReasonSignature, "header must be exactly alg %s, typ %s and kid", Algorithm, Type)
	}
	kid, _ := header["kid"].(string)
	idx := slices.IndexFunc(trusted, func(k Key) bool { return k.ID == kid })
	if idx < 0 {
		return nil, reject(ReasonUnknownKey, "key %q is not trusted", kid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, reject(ReasonSignature, "signature encoding: %v", err)
	}
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(b.Manifest)
	if !ed25519.Verify(trusted[idx].Public, []byte(input), sig) {
		return nil, reject(ReasonSignature, "signature does not verify with key %q", kid)
	}

	// V3. The manifest is the one governance state refers to.
	sum := SHA256Hex(b.Manifest)
	if sum != want.Ref.ManifestSHA256 {
		return nil, reject(ReasonManifestMismatch, "manifest SHA-256 %s, governance state expects %s", sum, want.Ref.ManifestSHA256)
	}

	// V4. The manifest's content.
	dec := json.NewDecoder(bytes.NewReader(b.Manifest))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, reject(ReasonInvalidManifest, "%v", err)
	}
	if m.Format != Format || m.CombiningAlgorithm != CombiningAlgorithm || !slices.Contains(want.Languages, m.Language) {
		return nil, reject(ReasonUnsupported, "format %q, combining algorithm %q, language %q", m.Format, m.CombiningAlgorithm, m.Language)
	}
	if m.AgentID != want.AgentID || m.Version != want.Ref.Version {
		return nil, reject(ReasonInvalidManifest, "bundle for agent %s version %d, expected agent %s version %d",
			m.AgentID, m.Version, want.AgentID, want.Ref.Version)
	}

	// V5. Files: exactly the listed ones, with their hashes.
	listed := map[string]string{}
	for _, p := range m.Policies {
		if !policyPath.MatchString(p.Path) || !strings.HasSuffix(p.Path, "."+m.Language) ||
			!strings.HasPrefix(p.Path, "policies/"+p.Scope+"/") {
			return nil, reject(ReasonInvalidManifest, "policy path %q", p.Path)
		}
		if _, dup := listed[p.Path]; dup {
			return nil, reject(ReasonInvalidManifest, "policy path %q listed twice", p.Path)
		}
		listed[p.Path] = p.SHA256
	}
	if m.CedarSchema != nil {
		if m.Language != "cedar" || m.CedarSchema.Path != CedarSchemaPath {
			return nil, reject(ReasonInvalidManifest, "cedar schema %q", m.CedarSchema.Path)
		}
		listed[m.CedarSchema.Path] = m.CedarSchema.SHA256
	}
	for _, path := range slices.Sorted(maps.Keys(listed)) {
		content, ok := b.Files[path]
		if !ok {
			return nil, reject(ReasonMissingFile, "%s", path)
		}
		if SHA256Hex(content) != listed[path] {
			return nil, reject(ReasonFileHash, "%s", path)
		}
	}
	for _, path := range slices.Sorted(maps.Keys(b.Files)) {
		if _, ok := listed[path]; !ok {
			return nil, reject(ReasonExtraFile, "%s", path)
		}
	}

	// V6. Never go back to an older bundle.
	if m.Version < want.ActiveVersion || (m.Version == want.ActiveVersion && sum != want.ActiveSHA256) {
		return nil, reject(ReasonOlderVersion, "version %d, active version %d", m.Version, want.ActiveVersion)
	}
	return &m, nil
}

// Reason returns the rejection reason of err, or "" if err is not a rejection.
func Reason(err error) string {
	var r *RejectError
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}
