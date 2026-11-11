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
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cedar-policy/cedar-go"
	"github.com/gowebpki/jcs"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/J466Y/WhiteTower/api/policy"
	"github.com/J466Y/WhiteTower/test/conformance/canonical"
	"github.com/J466Y/WhiteTower/test/conformance/tooling"
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
	// CatalogPath is where a bundle carries its catalog file.
	CatalogPath = "catalog.json"
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

// Manifest is the signed description of a bundle. Every member but Catalog is
// required (api/policy/bundle-manifest.schema.json).
type Manifest struct {
	Format             string `json:"format"`
	AgentID            string `json:"agent_id"`
	Version            uint64 `json:"version"`
	CreatedAt          string `json:"created_at"`
	CombiningAlgorithm string `json:"combining_algorithm"`
	Language           string `json:"language"`
	CedarSchema        File   `json:"cedar_schema"`
	// Catalog names the catalog file, which the core always includes. A
	// bundle without one decides as with an empty catalog (section 7.7).
	Catalog  *File         `json:"catalog,omitempty"`
	Policies []PolicyEntry `json:"policies"`
}

// The members of a manifest, of the entry of its Cedar schema or of its
// catalog file, and of a policy entry: exactly these, each of them required
// but catalog.
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
	if m.Catalog != nil {
		content, ok := files[m.Catalog.Path]
		if !ok {
			return nil, fmt.Errorf("no file for %s", m.Catalog.Path)
		}
		m.Catalog = &File{Path: m.Catalog.Path, SHA256: SHA256Hex(content)}
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
	// I-JSON (section 1) with exactly alg, kid and typ, in any order (section
	// 7.2): any other member, such as b64, which would change what is signed
	// (RFC 7797), or such as jku in place of kid, is refused, and so is a
	// member name twice, whichever of its values a reader would keep.
	parts := strings.Split(b.Signature, ".")
	if len(parts) != 3 || parts[1] != "" {
		return nil, reject(ReasonSignature, "not a JWS with a detached payload")
	}
	rawHeader, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, reject(ReasonSignature, "header encoding: %v", err)
	}
	if _, err := ReadIJSON(rawHeader); err != nil {
		return nil, reject(ReasonSignature, "header: not I-JSON: %v", err)
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
	// the language, with no duplicates, the Cedar schema sits at
	// schema.cedarschema and the catalog file at catalog.json: any other path
	// is malformed. Then exactly the listed files, with their hashes.
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
	if m.Catalog != nil {
		if m.Catalog.Path != CatalogPath {
			return nil, reject(ReasonInvalidManifest, "catalog file at %q, not at %q", m.Catalog.Path, CatalogPath)
		}
		listed[CatalogPath] = m.Catalog.SHA256
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

	// V7. Every policy parses as a static Cedar policy. cedar-go parses no
	// templates, so a template does not parse. Validating the policies against
	// the bundle's schema is the core's job (POL-07): a policy that fails it is
	// activated all the same. The catalog file parses against its schema.
	for _, p := range m.Policies {
		if _, err := cedar.NewPolicyListFromBytes(p.Path, b.Files[p.Path]); err != nil {
			return nil, reject(ReasonParseError, "%s: %v", p.Path, err)
		}
	}
	if m.Catalog != nil {
		if err := parseCatalog(b.Files[CatalogPath]); err != nil {
			return nil, reject(ReasonParseError, "%s: %v", CatalogPath, err)
		}
	}
	return m, nil
}

// catalogSchemaURL places the embedded schema of the catalog file at a URL,
// from which the compiler resolves its references. Nothing is fetched from it.
const catalogSchemaURL = "file:///whitetower/policy/catalog.schema.json"

// parseCatalog parses a catalog file as step V7 does: I-JSON in its own
// canonical form, as the manifest is (readCanonical), that matches
// api/policy/catalog.schema.json and names its entries and arguments as
// section 7.7 says (checkEntries). JSON Schema reads an object whose member
// names repeat as one of its readings, which another reader could read
// otherwise, so such a file never reaches the schema.
func parseCatalog(data []byte) error {
	if err := readCanonical(data); err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	schema, err := policy.Files.ReadFile("catalog.schema.json")
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(catalogSchemaURL, doc); err != nil {
		return err
	}
	compiled, err := compiler.Compile(catalogSchemaURL)
	if err != nil {
		return err
	}
	if err := compiled.Validate(inst); err != nil {
		return err
	}
	var c catalogFile
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	return checkEntries(&c)
}

// catalogFile is what step V7 reads of a catalog file that matches its
// schema, to check what the schema cannot: its keys, references, servers and
// argument names (section 7.7).
type catalogFile struct {
	Redaction tooling.Rules `json:"redaction"`
	Servers   []struct {
		Key       string `json:"key"`
		Reference string `json:"reference"`
		Status    string `json:"status"`
	} `json:"servers"`
	Tools []struct {
		Key      string             `json:"key"`
		Server   string             `json:"server"`
		Provider string             `json:"provider"`
		Type     string             `json:"type"`
		Name     string             `json:"name"`
		Kind     string             `json:"kind"`
		Status   string             `json:"status"`
		Args     []tooling.Argument `json:"args"`
	} `json:"tools"`
	Models []struct {
		Key      string `json:"key"`
		Provider string `json:"provider"`
		Endpoint string `json:"endpoint"`
		Name     string `json:"name"`
	} `json:"models"`
}

// distinct holds the values of one list that are already taken.
type distinct map[string]bool

// take reports whether v was free, and takes it.
func (d distinct) take(v string) bool {
	if d[v] {
		return false
	}
	d[v] = true
	return true
}

// checkEntries checks the rules of section 7.7 that the schema cannot state:
// no two servers, two tools or two models share a key or a reference, so that
// an enforcement point never chooses between two entries; a tool's server is
// a server of the file, approved when the tool is; and an argument's name is
// its path joined by . and followed by : and its transform, once per tool.
// References are computed as section 4.10 says, a model's with the file's
// own redaction rules, and a model whose reference cannot be computed is
// refused.
func checkEntries(c *catalogFile) error {
	keys, refs := distinct{}, distinct{}
	servers := map[string]int{}
	for i, s := range c.Servers {
		if !keys.take(s.Key) || !refs.take(s.Reference) {
			return fmt.Errorf("server %q: a key or a reference that another server has", s.Key)
		}
		servers[s.Key] = i
	}
	keys, refs = distinct{}, distinct{}
	for _, t := range c.Tools {
		ref := tooling.ToolReference(t.Name)
		switch t.Kind {
		case "mcp":
			i, ok := servers[t.Server]
			if !ok {
				return fmt.Errorf("tool %q: no server has the key %q", t.Key, t.Server)
			}
			if t.Status == "approved" && c.Servers[i].Status != "approved" {
				return fmt.Errorf("tool %q is approved, and its server is not", t.Key)
			}
			ref = tooling.MCPToolReference(c.Servers[i].Reference, t.Name)
		case "builtin":
			ref = tooling.BuiltinToolReference(t.Provider, t.Type)
		}
		if !keys.take(t.Key) || !refs.take(ref) {
			return fmt.Errorf("tool %q: a key or a reference that another tool has", t.Key)
		}
		names := distinct{}
		for _, a := range t.Args {
			name := strings.Join(a.Path, ".")
			if a.Transform != "" {
				name += ":" + a.Transform
			}
			if a.Name != name || !names.take(a.Name) {
				return fmt.Errorf("tool %q: the argument %q is not named %q, or is declared twice", t.Key, a.Name, name)
			}
		}
	}
	keys, refs = distinct{}, distinct{}
	for _, m := range c.Models {
		ref, err := tooling.ModelReference(m.Provider, m.Endpoint, m.Name, c.Redaction)
		if err != nil {
			return fmt.Errorf("model %q: %w", m.Key, err)
		}
		if !keys.take(m.Key) || !refs.take(ref) {
			return fmt.Errorf("model %q: a key or a reference that another model has", m.Key)
		}
	}
	return nil
}

// ParseManifest applies the checks of step V4 that read the manifest alone,
// in their order (section 7.4). A manifest that is not I-JSON, or not its own
// canonical JSON (sections 1 and 7.2, readCanonical), or not an object, or
// that has an unknown or a missing member, or a member of the wrong type, is
// invalid_manifest: the types are those of
// api/policy/bundle-manifest.schema.json, the forms of its strings included.
// Then a format, combining algorithm or language that is not supported is
// unsupported, even though the schema's constant fails too. Paths need only be
// strings here: step V5 builds them from their entries.
func ParseManifest(data []byte, languages []string) (*Manifest, error) {
	if err := readCanonical(data); err != nil {
		return nil, reject(ReasonInvalidManifest, "%v", err)
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

// maxInteger is 2^53 - 1, the largest magnitude of an integer in I-JSON
// (section 1).
const maxInteger = 1<<53 - 1

// ErrNumber is the error of a number that I-JSON does not hold: an integer of
// a magnitude beyond 2^53 - 1, or another number that no double holds as it
// is written.
var ErrNumber = errors.New("a number that I-JSON does not hold")

// ReadIJSON reads JSON text that must be I-JSON (section 1, RFC 7493), as a
// bundle's JWS header, manifest and catalog file must, and returns its
// canonical JSON. It refuses text that is not UTF-8, or that starts with a
// byte order mark; a member name twice in an object, at any depth; a string
// with a lone surrogate or a noncharacter; and a number that a double does not
// hold as it is written. It reads a number by its exact value, whatever its
// spelling: 4.2e1 and 42.0 are the integer 42, which the canonical JSON writes
// 42, and 9007199254740992, 9.007199254740992e15 and -9007199254740992.0 are
// all integers beyond 2^53 - 1.
func ReadIJSON(data []byte) ([]byte, error) {
	if !utf8JSON(data) {
		return nil, errors.New("JSON is UTF-8, without a byte order mark")
	}
	v, err := canonical.Parse(data)
	if err != nil {
		return nil, err
	}
	if err := checkIJSON(v); err != nil {
		return nil, err
	}
	// Encode refuses a member name twice and a lone surrogate.
	return canonical.Encode(v)
}

// readCanonical checks that a bundle's manifest or catalog file is I-JSON and
// its own canonical JSON (sections 1 and 7.2): bytes that differ from it, by
// spaces, the order of members, an escape or the spelling of a number, are
// refused, so that a manifest has one form and one reference.
func readCanonical(data []byte) error {
	text, err := ReadIJSON(data)
	if err != nil {
		return fmt.Errorf("not I-JSON: %w", err)
	}
	if !bytes.Equal(text, data) {
		return errors.New("not its own canonical JSON")
	}
	return nil
}

// checkIJSON checks the numbers and the strings of a value that
// canonical.Parse returned, at every depth.
func checkIJSON(v any) error {
	switch v := v.(type) {
	case canonical.Number:
		return checkNumber(v)
	case canonical.String:
		return checkString(v)
	case []any:
		for _, item := range v {
			if err := checkIJSON(item); err != nil {
				return err
			}
		}
	case canonical.Object:
		for _, m := range v {
			if err := checkString(m.Name); err != nil {
				return err
			}
			if err := checkIJSON(m.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkString refuses a noncharacter, which I-JSON's strings never hold (RFC
// 7493, section 2.1). String writes a lone surrogate as U+FFFD, which is not
// one: canonical.Encode refuses it.
func checkString(s canonical.String) error {
	for _, r := range s.String() {
		if r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFE == 0xFFFE {
			return fmt.Errorf("the noncharacter %U", r)
		}
	}
	return nil
}

// checkNumber checks that a double holds a number as it is written, by the
// number's exact value: an integer has a magnitude of at most 2^53 - 1, and
// any other number is the value of the shortest form of its double, so that
// 0.1 passes, while 0.10000000000000001 and 1e-400 do not.
func checkNumber(n canonical.Number) error {
	neg, digits, exp := exactDecimal(string(n))
	if exp >= 0 {
		// At most 16 digits, which ParseUint always reads: 2^53 - 1 has 16.
		if int64(len(digits))+exp <= 16 {
			if v, _ := strconv.ParseUint("0"+digits+strings.Repeat("0", int(exp)), 10, 64); v <= maxInteger {
				return nil
			}
		}
		return fmt.Errorf("%w: %s is an integer of a magnitude beyond 2^53 - 1", ErrNumber, n)
	}
	if f, err := strconv.ParseFloat(string(n), 64); err == nil {
		if fneg, fdigits, fexp := exactDecimal(strconv.FormatFloat(f, 'g', -1, 64)); fneg == neg && fdigits == digits && fexp == exp {
			return nil
		}
	}
	return fmt.Errorf("%w: no double holds %s as it is written", ErrNumber, n)
}

// exactDecimal returns the exact value of a number that RFC 8259's grammar
// writes, as its sign, its digits without leading or trailing zeros, and the
// power of ten that multiplies them: -4.20e1 is true, "42" and 0, and 1.5 is
// false, "15" and -1. Zero has no sign, no digits and the power 0. A power
// beyond 2^40 either way, which no text of a bundle's size could bring back
// within reach, counts as 2^40.
func exactDecimal(text string) (neg bool, digits string, exp int64) {
	neg = strings.HasPrefix(text, "-")
	mantissa := strings.TrimPrefix(text, "-")
	if i := strings.IndexAny(mantissa, "eE"); i >= 0 {
		// ParseInt takes the exponent's sign, and gives the largest
		// magnitude of its sign for one out of range.
		exp, _ = strconv.ParseInt(mantissa[i+1:], 10, 64)
		exp = max(min(exp, 1<<40), -1<<40)
		mantissa = mantissa[:i]
	}
	whole, fraction, _ := strings.Cut(mantissa, ".")
	all := strings.TrimLeft(whole+fraction, "0")
	digits = strings.TrimRight(all, "0")
	if digits == "" {
		return false, "", 0
	}
	return neg, digits, exp - int64(len(fraction)) + int64(len(all)-len(digits))
}

// checkMembers checks that the manifest, the entries of its Cedar schema and
// of its catalog file, and each policy entry are objects with exactly their
// members, none of them null, the catalog's entry being optional. Decoding
// into a Manifest then checks the type of each member, since encoding/json
// neither reports a missing member nor refuses null.
func checkMembers(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	manifest, err := object(v, manifestMembers, "catalog")
	if err != nil {
		return err
	}
	if _, err := object(manifest["cedar_schema"], fileMembers); err != nil {
		return fmt.Errorf("cedar_schema: %w", err)
	}
	if catalog, ok := manifest["catalog"]; ok {
		if _, err := object(catalog, fileMembers); err != nil {
			return fmt.Errorf("catalog: %w", err)
		}
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

// object returns v as an object that has exactly the members required, and
// may have those optional, none of them null.
func object(v any, required []string, optional ...string) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	for name, value := range obj {
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return nil, fmt.Errorf("unknown member %q", name)
		}
		if value == nil {
			return nil, fmt.Errorf("member %q is null", name)
		}
	}
	for _, name := range required {
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
	case m.Catalog != nil && !sha256Form.MatchString(m.Catalog.SHA256):
		return fmt.Errorf("catalog.sha256 %q is not a SHA-256", m.Catalog.SHA256)
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
