// Package bundle implements the White Tower policy bundle format
// whitetower.bundle.v1: canonical manifests, detached JWS signatures with
// Ed25519 keys, bundle keys as a JWK Set, and the verification an enforcement
// point performs before it activates a bundle
// (docs/contracts/module-contract-v0.1.md, section 7).
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
	"unicode/utf8"

	"github.com/cedar-policy/cedar-go"
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

// Manifest is the signed description of a bundle. Every member is required
// (api/policy/bundle-manifest.schema.json).
type Manifest struct {
	Format             string        `json:"format"`
	AgentID            string        `json:"agent_id"`
	Version            uint64        `json:"version"`
	CreatedAt          string        `json:"created_at"`
	CombiningAlgorithm string        `json:"combining_algorithm"`
	Language           string        `json:"language"`
	CedarSchema        File          `json:"cedar_schema"`
	Policies           []PolicyEntry `json:"policies"`
}

// The members of a manifest, of its Cedar schema's entry and of a policy
// entry: exactly these, each of them required.
var (
	manifestMembers = []string{"format", "agent_id", "version", "created_at", "combining_algorithm", "language", "cedar_schema", "policies"}
	fileMembers     = []string{"path", "sha256"}
	policyMembers   = []string{"id", "name", "version", "scope", "path", "sha256"}
)

// The forms of the manifest's strings, as the schema states them.
var (
	uuidForm      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sha256Form    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	timestampForm = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
)

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

// ParseKeys reads bundle keys from a JWK Set (RFC 7517), the form in which
// section 7.3 has enforcement points take them: OKP keys on the Ed25519
// curve (RFC 8037), each with its key ID. As RFC 7517 asks, it ignores the
// keys it cannot use: other types and curves, and keys without an ID or with
// a malformed public key.
func ParseKeys(data []byte) ([]Key, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("not a JWK Set: %w", err)
	}
	if set.Keys == nil {
		return nil, errors.New("not a JWK Set: no keys member")
	}
	var keys []Key
	for _, k := range set.Keys {
		pub, err := decodeBase64URL(k.X)
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" || err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		keys = append(keys, Key{ID: k.Kid, Public: pub})
	}
	return keys, nil
}

// decodeBase64URL decodes base64url as RFC 7515 defines it: the URL-safe
// alphabet only, without padding, line breaks or any other character.
// base64.RawURLEncoding refuses padding and other characters, but skips line
// breaks, so they are refused first.
func decodeBase64URL(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("a line break in base64url")
	}
	return base64.RawURLEncoding.DecodeString(s)
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
	content, ok := files[m.CedarSchema.Path]
	if !ok {
		return nil, fmt.Errorf("no file for %s", m.CedarSchema.Path)
	}
	m.CedarSchema.SHA256 = SHA256Hex(content)
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

// Verify applies the verification steps of section 7.4, V1 to V7, in their
// order, and returns the manifest, or a *RejectError. A bundle whose version
// and hash equal the active one's verifies; the caller then has nothing to
// activate.
func Verify(b *Bundle, trusted []Key, want Expectation) (*Manifest, error) {
	// V1. Size.
	if want.Ref.SizeBytes > MaxSize || b.Size() > MaxSize || len(b.Files) > MaxFiles {
		return nil, reject(ReasonOversized, "%d bytes in %d files", b.Size(), len(b.Files))
	}

	// V2. Signature over the exact manifest bytes. The header and the
	// signature are in base64url as RFC 7515 defines it, and the header is
	// JSON in UTF-8 (section 1) with exactly alg, kid and typ, in any order
	// (section 7.2): any other member, such as b64, which would change what
	// is signed (RFC 7797), or such as jku in place of kid, is refused.
	parts := strings.Split(b.Signature, ".")
	if len(parts) != 3 || parts[1] != "" {
		return nil, reject(ReasonSignature, "not a JWS with a detached payload")
	}
	rawHeader, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, reject(ReasonSignature, "header encoding: %v", err)
	}
	if !utf8JSON(rawHeader) {
		return nil, reject(ReasonSignature, "header: JSON is UTF-8, without a byte order mark")
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, reject(ReasonSignature, "header: %v", err)
	}
	if _, named := header["kid"]; !named || len(header) != 3 || header["alg"] != Algorithm || header["typ"] != Type {
		return nil, reject(ReasonSignature, "header must be exactly alg %s, typ %s and kid", Algorithm, Type)
	}
	kid, _ := header["kid"].(string)
	idx := slices.IndexFunc(trusted, func(k Key) bool { return k.ID == kid })
	if idx < 0 {
		return nil, reject(ReasonUnknownKey, "key %q is not trusted", kid)
	}
	sig, err := decodeBase64URL(parts[2])
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

	// V4. The manifest alone, then against the state.
	m, err := ParseManifest(b.Manifest, want.Languages)
	if err != nil {
		return nil, err
	}
	if m.AgentID != want.AgentID || m.Version != want.Ref.Version {
		return nil, reject(ReasonInvalidManifest, "bundle for agent %s version %d, expected agent %s version %d",
			m.AgentID, m.Version, want.AgentID, want.Ref.Version)
	}

	// V5. Files. Each policy's path is built from its entry's ID and scope and
	// the language, with no duplicates, and the Cedar schema sits at
	// schema.cedarschema: any other path is malformed. Then exactly the
	// listed files, with their hashes.
	listed := map[string]string{}
	for _, p := range m.Policies {
		path := "policies/" + p.Scope + "/" + p.ID + "." + m.Language
		if p.Path != path {
			return nil, reject(ReasonInvalidManifest, "policy %s is at %q, not at %q", p.ID, p.Path, path)
		}
		if _, dup := listed[path]; dup {
			return nil, reject(ReasonInvalidManifest, "policy path %q listed twice", path)
		}
		listed[path] = p.SHA256
	}
	if m.CedarSchema.Path != CedarSchemaPath {
		return nil, reject(ReasonInvalidManifest, "Cedar schema at %q, not at %q", m.CedarSchema.Path, CedarSchemaPath)
	}
	listed[CedarSchemaPath] = m.CedarSchema.SHA256
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

	// V7. Every policy parses as a static Cedar policy. cedar-go parses no
	// templates, so a template does not parse. Validating the policies against
	// the bundle's schema is the core's job (POL-07): a policy that fails it is
	// activated all the same.
	for _, p := range m.Policies {
		if _, err := cedar.NewPolicyListFromBytes(p.Path, b.Files[p.Path]); err != nil {
			return nil, reject(ReasonParseError, "%s: %v", p.Path, err)
		}
	}
	return m, nil
}

// ParseManifest applies the checks of step V4 that read the manifest alone,
// in their order (section 7.4). A manifest that is not JSON in UTF-8 without a
// byte order mark (section 1), or not an object, or that has an unknown or a
// missing member, or a member of the wrong type, is invalid_manifest: the
// types are those of api/policy/bundle-manifest.schema.json, the forms of its
// strings included. Then a format, combining algorithm or language that is not
// supported is unsupported, even though the schema's constant fails too. Paths
// need only be strings here: step V5 builds them from their entries.
func ParseManifest(data []byte, languages []string) (*Manifest, error) {
	if !utf8JSON(data) {
		return nil, reject(ReasonInvalidManifest, "JSON is UTF-8, without a byte order mark")
	}
	if err := checkMembers(data); err != nil {
		return nil, reject(ReasonInvalidManifest, "%v", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, reject(ReasonInvalidManifest, "%v", err)
	}
	if err := checkForms(&m); err != nil {
		return nil, reject(ReasonInvalidManifest, "%v", err)
	}
	if m.Format != Format || m.CombiningAlgorithm != CombiningAlgorithm || !slices.Contains(languages, m.Language) {
		return nil, reject(ReasonUnsupported, "format %q, combining algorithm %q, language %q", m.Format, m.CombiningAlgorithm, m.Language)
	}
	return &m, nil
}

// utf8JSON reports whether data is in the encoding of JSON that section 1
// states: UTF-8 (RFC 8259, section 8.1), without a byte order mark.
// encoding/json reads an invalid byte as U+FFFD rather than refuse it.
func utf8JSON(data []byte) bool {
	return utf8.Valid(data) && !bytes.HasPrefix(data, []byte("\xef\xbb\xbf"))
}

// checkMembers checks that the manifest, its Cedar schema's entry and each
// policy entry are objects with exactly their members, none of them null.
// Decoding into a Manifest then checks the type of each member, since
// encoding/json neither reports a missing member nor refuses null.
func checkMembers(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	manifest, err := object(v, manifestMembers)
	if err != nil {
		return err
	}
	if _, err := object(manifest["cedar_schema"], fileMembers); err != nil {
		return fmt.Errorf("cedar_schema: %w", err)
	}
	policies, ok := manifest["policies"].([]any)
	if !ok {
		return errors.New("policies is not an array")
	}
	for i, p := range policies {
		if _, err := object(p, policyMembers); err != nil {
			return fmt.Errorf("policy %d: %w", i, err)
		}
	}
	return nil
}

// object returns v as an object that has exactly the members named, none of
// them null.
func object(v any, members []string) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	for name, value := range obj {
		if !slices.Contains(members, name) {
			return nil, fmt.Errorf("unknown member %q", name)
		}
		if value == nil {
			return nil, fmt.Errorf("member %q is null", name)
		}
	}
	for _, name := range members {
		if _, ok := obj[name]; !ok {
			return nil, fmt.Errorf("missing member %q", name)
		}
	}
	return obj, nil
}

// checkForms checks the values that the schema constrains beyond their JSON
// type: identifiers, hashes and times in their forms, versions from 1, names
// of 1 to 200 characters, and the two scopes.
func checkForms(m *Manifest) error {
	switch {
	case !uuidForm.MatchString(m.AgentID):
		return fmt.Errorf("agent_id %q is not a UUID", m.AgentID)
	case m.Version < 1:
		return errors.New("version is 0")
	case !timestampForm.MatchString(m.CreatedAt):
		return fmt.Errorf("created_at %q is not a time with milliseconds in UTC", m.CreatedAt)
	case !sha256Form.MatchString(m.CedarSchema.SHA256):
		return fmt.Errorf("cedar_schema.sha256 %q is not a SHA-256", m.CedarSchema.SHA256)
	}
	for i, p := range m.Policies {
		switch n := utf8.RuneCountInString(p.Name); {
		case !uuidForm.MatchString(p.ID):
			return fmt.Errorf("policy %d: id %q is not a UUID", i, p.ID)
		case n < 1 || n > 200:
			return fmt.Errorf("policy %d: a name of %d characters", i, n)
		case p.Version < 1:
			return fmt.Errorf("policy %d: version is 0", i)
		case p.Scope != "global" && p.Scope != "agent":
			return fmt.Errorf("policy %d: scope %q", i, p.Scope)
		case !sha256Form.MatchString(p.SHA256):
			return fmt.Errorf("policy %d: sha256 %q is not a SHA-256", i, p.SHA256)
		}
	}
	return nil
}

// Reason returns the rejection reason of err, or "" if err is not a rejection.
func Reason(err error) string {
	var r *RejectError
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}
