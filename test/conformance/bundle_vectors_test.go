package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/J466Y/WhiteTower/test/conformance/bundle"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
)

var update = flag.Bool("update", false, "regenerate the signed bundle vectors in vectors/bundles")

const (
	bundleDir   = "vectors/bundles"
	vectorAgent = "0192f1c2-7a3b-7c4d-8e5f-000000000001"
	otherAgent  = "0192f1c2-7a3b-7c4d-8e5f-000000000002"
	globalID    = "0192f1c2-7a3b-7c4d-8e5f-000000000101"
	agentID     = "0192f1c2-7a3b-7c4d-8e5f-000000000202"
)

// testKey derives a published Ed25519 key. These keys sign test vectors only:
// anyone can compute them, so nothing may ever trust them outside tests.
func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("White Tower conformance test key: " + name + ". Never trust it outside tests."))
	return ed25519.NewKeyFromSeed(seed[:])
}

// bundleCase is one directory of vectors/bundles.
type bundleCase struct {
	Description   string        `json:"description"`
	Obligation    string        `json:"obligation"`
	AgentID       string        `json:"agent_id"`
	Ref           bundle.Ref    `json:"ref"`
	ActiveVersion uint64        `json:"active_version"`
	ActiveSHA256  string        `json:"active_manifest_sha256,omitempty"`
	Expected      bundleOutcome `json:"expected"`
}

type bundleOutcome struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// generated is a case with its files, ready to write or to compare.
type generated struct {
	name  string
	meta  bundleCase
	files map[string][]byte
}

func baseManifest(version uint64) bundle.Manifest {
	return bundle.Manifest{
		Format:             bundle.Format,
		AgentID:            vectorAgent,
		Version:            version,
		CreatedAt:          "2026-09-29T10:00:00.000Z",
		CombiningAlgorithm: bundle.CombiningAlgorithm,
		Language:           "cedar",
		CedarSchema:        &bundle.File{Path: bundle.CedarSchemaPath},
		Policies: []bundle.PolicyEntry{
			{ID: globalID, Name: "global-no-external-email", Version: 3, Scope: "global", Path: "policies/global/" + globalID + ".cedar"},
			{ID: agentID, Name: "invoice-triage-tools", Version: 1, Scope: "agent", Path: "policies/agent/" + agentID + ".cedar"},
		},
	}
}

func baseFiles(t *testing.T) map[string][]byte {
	t.Helper()
	schema, err := os.ReadFile("../../api/policy/whitetower.cedarschema")
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		bundle.CedarSchemaPath: schema,
		"policies/global/" + globalID + ".cedar": []byte(`@id("global-no-external-email")
forbid (principal, action == WhiteTower::Action::"tool.invoke", resource == WhiteTower::Tool::"send_email");
`),
		"policies/agent/" + agentID + ".cedar": []byte(`@id("invoice-triage-tools")
permit (principal, action == WhiteTower::Action::"tool.invoke", resource)
when { [WhiteTower::Tool::"read_invoice", WhiteTower::Tool::"send_email"].contains(resource) };
`),
	}
}

// generateBundleCases builds every case deterministically: Ed25519 signatures
// and RFC 8785 canonical JSON are both deterministic.
func generateBundleCases(t *testing.T) []generated {
	t.Helper()
	trusted, untrusted := testKey("trusted"), testKey("untrusted")
	trustedID := bundle.KeyID(trusted.Public().(ed25519.PublicKey))
	untrustedID := bundle.KeyID(untrusted.Public().(ed25519.PublicKey))

	build := func(m bundle.Manifest, files map[string][]byte, kid string, key ed25519.PrivateKey) *bundle.Bundle {
		b, err := bundle.Build(m, files, kid, key)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	valid := func() *bundle.Bundle { return build(baseManifest(42), baseFiles(t), trustedID, trusted) }

	var out []generated
	// Every bundle case checks obligation EP-7.
	add := func(name, description string, b *bundle.Bundle, ref bundle.Ref, active uint64, want bundleOutcome) {
		files := maps.Clone(b.Files)
		files["manifest.json"] = b.Manifest
		if b.Signature != "" {
			files["manifest.jws"] = []byte(b.Signature)
		}
		out = append(out, generated{name: name, files: files, meta: bundleCase{
			Description: description, Obligation: "EP-7", AgentID: vectorAgent,
			Ref: ref, ActiveVersion: active, Expected: want,
		}})
	}
	rejected := func(reason string) bundleOutcome { return bundleOutcome{Outcome: "rejected", Reason: reason} }

	b := valid()
	add("valid", "A valid bundle newer than the active one", b, b.Ref(42), 41, bundleOutcome{Outcome: "activated"})

	b = valid()
	add("first-bundle", "A valid bundle when none is active", b, b.Ref(42), 0, bundleOutcome{Outcome: "activated"})

	b = valid()
	b.Files["policies/global/"+globalID+".cedar"] = []byte("permit (principal, action, resource);\n")
	add("tampered-policy", "A policy file was changed after signing", b, b.Ref(42), 41, rejected(bundle.ReasonFileHash))

	b = valid()
	b.Manifest = bytes.Replace(b.Manifest, []byte(`"version":42`), []byte(`"version":43`), 1)
	add("tampered-manifest", "The manifest was changed after signing, and governance state refers to the changed one",
		b, b.Ref(43), 41, rejected(bundle.ReasonSignature))

	b = valid()
	b.Signature = ""
	add("unsigned", "The bundle has no signature", b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = build(baseManifest(42), baseFiles(t), untrustedID, untrusted)
	add("unknown-key", "Signed with a key the enforcement point does not trust", b, b.Ref(42), 41, rejected(bundle.ReasonUnknownKey))

	b = build(baseManifest(42), baseFiles(t), trustedID, untrusted)
	add("forged-key-id", "Signed with another key under a trusted key ID", b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = valid()
	other := build(baseManifest(43), baseFiles(t), trustedID, trusted)
	add("ref-mismatch", "A valid bundle, but not the one governance state refers to", b,
		bundle.Ref{Version: 42, ManifestSHA256: bundle.SHA256Hex(other.Manifest), SizeBytes: b.Size()}, 41,
		rejected(bundle.ReasonManifestMismatch))

	b = build(baseManifest(40), baseFiles(t), trustedID, trusted)
	add("older-version", "A valid bundle older than the active one", b, b.Ref(40), 41, rejected(bundle.ReasonOlderVersion))

	b = valid()
	delete(b.Files, "policies/agent/"+agentID+".cedar")
	add("missing-file", "A listed policy file is missing", b, b.Ref(42), 41, rejected(bundle.ReasonMissingFile))

	b = valid()
	b.Files["policies/agent/0192f1c2-7a3b-7c4d-8e5f-000000000299.cedar"] = []byte("permit (principal, action, resource);\n")
	add("extra-file", "A file the manifest does not list", b, b.Ref(42), 41, rejected(bundle.ReasonExtraFile))

	m := baseManifest(42)
	m.AgentID = otherAgent
	b = build(m, baseFiles(t), trustedID, trusted)
	add("wrong-agent", "A valid bundle for another agent", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	m = baseManifest(42)
	m.CombiningAlgorithm = "first-applicable"
	b = build(m, baseFiles(t), trustedID, trusted)
	add("unsupported-algorithm", "A combining algorithm the contract does not define", b, b.Ref(42), 41, rejected(bundle.ReasonUnsupported))

	files := baseFiles(t)
	files["policies/agent/"+agentID+".cedar"] = []byte("permit (principal, action, resource\n")
	b = build(baseManifest(42), files, trustedID, trusted)
	add("parse-error", "A validly signed bundle whose policy does not parse", b, b.Ref(42), 41, rejected(bundle.ReasonParseError))

	b = valid()
	ref := b.Ref(42)
	ref.SizeBytes = 3 << 20
	add("oversized", "Governance state announces a bundle larger than the limit", b, ref, 41, rejected(bundle.ReasonOversized))

	return out
}

// keysFile describes the published test keys.
type keysFile struct {
	Description string    `json:"description"`
	Trusted     []jwkFile `json:"trusted"`
	Untrusted   []jwkFile `json:"untrusted"`
}

type jwkFile struct {
	Kid  string `json:"kid"`
	Kty  string `json:"kty"`
	Crv  string `json:"crv"`
	Alg  string `json:"alg"`
	X    string `json:"x"`
	Seed string `json:"test_only_seed"`
}

func jwk(key ed25519.PrivateKey) jwkFile {
	pub := key.Public().(ed25519.PublicKey)
	return jwkFile{
		Kid: bundle.KeyID(pub), Kty: "OKP", Crv: "Ed25519", Alg: bundle.Algorithm,
		X: base64.RawURLEncoding.EncodeToString(pub), Seed: base64.RawURLEncoding.EncodeToString(key.Seed()),
	}
}

func marshalIndent(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

// wantTree is every file of vectors/bundles, as generated.
func wantTree(t *testing.T) map[string][]byte {
	t.Helper()
	tree := map[string][]byte{
		"keys.json": marshalIndent(t, keysFile{
			Description: "Published Ed25519 keys that sign the bundle vectors. Their seeds are public: never trust these keys outside tests.",
			Trusted:     []jwkFile{jwk(testKey("trusted"))},
			Untrusted:   []jwkFile{jwk(testKey("untrusted"))},
		}),
	}
	for _, c := range generateBundleCases(t) {
		tree[c.name+"/case.json"] = marshalIndent(t, c.meta)
		for path, content := range c.files {
			tree[c.name+"/"+path] = content
		}
	}
	return tree
}

func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	tree := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "README.md" {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		tree[filepath.ToSlash(rel)] = content
		return err
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return tree
}

// TestBundleVectorsAreCurrent checks that the committed vectors are exactly
// what the generator produces. Run `go test ./test/conformance -run
// TestBundleVectorsAreCurrent -update` to regenerate them.
func TestBundleVectorsAreCurrent(t *testing.T) {
	want := wantTree(t)
	if *update {
		for path := range readTree(t, bundleDir) {
			if err := os.Remove(filepath.Join(bundleDir, path)); err != nil {
				t.Fatal(err)
			}
		}
		for path, content := range want {
			full := filepath.Join(bundleDir, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	got := readTree(t, bundleDir)
	for _, path := range slices.Sorted(maps.Keys(want)) {
		if !bytes.Equal(got[path], want[path]) {
			t.Errorf("%s/%s is not current: run the test with -update", bundleDir, path)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			t.Errorf("%s/%s is not generated: remove it or run the test with -update", bundleDir, path)
		}
	}
}

// TestBundleVectors verifies every committed case as an enforcement point
// would, and checks the outcome it expects.
func TestBundleVectors(t *testing.T) {
	var keys keysFile
	loadJSON(t, filepath.Join(bundleDir, "keys.json"), &keys)
	var trusted []bundle.Key
	for _, k := range keys.Trusted {
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, bundle.Key{ID: k.Kid, Public: pub})
	}
	manifestSchema := compileSchema(t, "../../api/policy/bundle-manifest.schema.json")

	cases, err := os.ReadDir(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, dir := range cases {
		if !dir.IsDir() {
			continue
		}
		count++
		t.Run(dir.Name(), func(t *testing.T) {
			root := filepath.Join(bundleDir, dir.Name())
			var c bundleCase
			loadJSON(t, filepath.Join(root, "case.json"), &c)
			files := readTree(t, root)
			b := &bundle.Bundle{Manifest: files["manifest.json"], Signature: string(files["manifest.jws"]), Files: map[string][]byte{}}
			for path, content := range files {
				if path != "manifest.json" && path != "manifest.jws" && path != "case.json" {
					b.Files[path] = content
				}
			}

			m, err := bundle.Verify(b, trusted, bundle.Expectation{
				AgentID: c.AgentID, Ref: c.Ref, ActiveVersion: c.ActiveVersion, ActiveSHA256: c.ActiveSHA256,
				Languages: []string{"cedar"},
			})
			outcome := bundleOutcome{Outcome: "activated"}
			if err != nil {
				outcome = bundleOutcome{Outcome: "rejected", Reason: bundle.Reason(err)}
			} else {
				// A signed manifest always matches the published schema.
				if err := validateJSON(manifestSchema, m); err != nil {
					t.Errorf("manifest does not match its schema: %v", err)
				}
				var ps []profile.Policy
				for _, p := range m.Policies {
					ps = append(ps, profile.Policy{ID: p.ID, Text: string(b.Files[p.Path])})
				}
				if _, err := profile.NewEngine(m.AgentID, m.Version, ps); err != nil {
					outcome = bundleOutcome{Outcome: "rejected", Reason: bundle.ReasonParseError}
				}
			}
			if outcome != c.Expected {
				t.Errorf("got %+v, want %+v (%v)", outcome, c.Expected, err)
			}
		})
	}
	if count == 0 {
		t.Fatal("no bundle vectors: run TestBundleVectorsAreCurrent with -update")
	}
}
