package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/J466Y/WhiteTower/test/conformance/bundle"
	"github.com/J466Y/WhiteTower/test/conformance/kit"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
)

var update = flag.Bool("update", false, "regenerate the signed bundle vectors in vectors/bundles")

const (
	bundleDir     = "vectors/bundles"
	vectorAgent   = "0192f1c2-7a3b-7c4d-8e5f-000000000001"
	otherAgent    = "0192f1c2-7a3b-7c4d-8e5f-000000000002"
	globalID      = "0192f1c2-7a3b-7c4d-8e5f-000000000101"
	agentID       = "0192f1c2-7a3b-7c4d-8e5f-000000000202"
	otherPolicyID = "0192f1c2-7a3b-7c4d-8e5f-000000000299"
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
		CedarSchema:        bundle.File{Path: bundle.CedarSchemaPath},
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

// moved moves a bundle's file to another path, and returns the files.
func moved(files map[string][]byte, from, to string) map[string][]byte {
	files[to] = files[from]
	delete(files, from)
	return files
}

// decodeManifest decodes a manifest into its JSON members, so that a case can
// change it beyond what bundle.Manifest expresses. Numbers stay exact.
func decodeManifest(t *testing.T, manifest []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// policyEntry returns the members of the manifest's i-th policy entry.
func policyEntry(m map[string]any, i int) map[string]any {
	return m["policies"].([]any)[i].(map[string]any)
}

// failsValidation parses as a static Cedar policy, but fails validation
// against the profile's schema, which declares no vendor for a tool.
const failsValidation = `@id("global-no-acme-tools")
forbid (principal, action == WhiteTower::Action::"tool.invoke", resource)
when { resource.vendor == "acme" };
`

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
	b.Files["policies/agent/"+otherPolicyID+".cedar"] = []byte("permit (principal, action, resource);\n")
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

	// V2. The JWS header has exactly alg EdDSA, kid and typ, in any order
	// (section 7.2). signedWith signs a valid bundle with a detached JWS whose
	// protected header is the JSON text given: sign signs the JWS signing
	// input, the header and the manifest, both encoded (RFC 7515).
	signedWith := func(header string, sign func(input []byte) []byte) *bundle.Bundle {
		b := valid()
		protected := base64.RawURLEncoding.EncodeToString([]byte(header))
		input := protected + "." + base64.RawURLEncoding.EncodeToString(b.Manifest)
		b.Signature = protected + ".." + base64.RawURLEncoding.EncodeToString(sign([]byte(input)))
		return b
	}
	signedByTrusted := func(input []byte) []byte { return ed25519.Sign(trusted, input) }

	b = signedWith(fmt.Sprintf(`{"alg":"none","kid":%q,"typ":%q}`, trustedID, bundle.Type), func([]byte) []byte { return nil })
	add("header-alg-none", "The JWS header names the algorithm none, and the signature is empty", b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = signedWith(fmt.Sprintf(`{"alg":"HS256","kid":%q,"typ":%q}`, trustedID, bundle.Type), func(input []byte) []byte {
		mac := hmac.New(sha256.New, trusted.Public().(ed25519.PublicKey))
		mac.Write(input)
		return mac.Sum(nil)
	})
	add("header-hs256", "The JWS header names HS256, and the signature is an HMAC keyed with the trusted public key's 32 bytes",
		b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = signedWith(fmt.Sprintf(`{"alg":"Ed25519","kid":%q,"typ":%q}`, trustedID, bundle.Type), signedByTrusted)
	add("header-alg-ed25519", "The trusted key signs the bundle, but the JWS header names the algorithm Ed25519 rather than EdDSA",
		b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = signedWith(fmt.Sprintf(`{"alg":"EdDSA","kid":%q,"typ":"JWT"}`, trustedID), signedByTrusted)
	add("header-other-typ", "The trusted key signs the bundle, but the JWS header's typ is JWT", b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = signedWith(fmt.Sprintf(`{"alg":"EdDSA","b64":true,"crit":["b64"],"kid":%q,"typ":%q}`, trustedID, bundle.Type), signedByTrusted)
	add("header-b64-crit", "The trusted key signs the encoded manifest, as b64 true also means (RFC 7797), but the JWS header carries b64, listed in crit, beyond its three members",
		b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = signedWith(fmt.Sprintf(`{"alg":"EdDSA","typ":%q}`, bundle.Type), signedByTrusted)
	add("header-no-kid", "The trusted key signs the bundle, but the JWS header has no kid", b, b.Ref(42), 41, rejected(bundle.ReasonSignature))

	b = signedWith(fmt.Sprintf(`{"typ":%q,"kid":%q,"alg":"EdDSA"}`, bundle.Type, trustedID), signedByTrusted)
	add("header-any-order", "The JWS header has its three members in another order", b, b.Ref(42), 41, bundleOutcome{Outcome: "activated"})

	// V4. The manifest's structure, then the values it must support, then the
	// agent and the version that governance state names. changed signs again,
	// with the trusted key, the manifest of b once change has changed its
	// members; change returns the manifest to sign.
	changed := func(b *bundle.Bundle, change func(m map[string]any) any) *bundle.Bundle {
		manifest, err := bundle.Canonical(change(decodeManifest(t, b.Manifest)))
		if err != nil {
			t.Fatal(err)
		}
		b.Manifest, b.Signature = manifest, bundle.Sign(manifest, trustedID, trusted)
		return b
	}

	b = changed(valid(), func(m map[string]any) any { return []any{m} })
	add("not-an-object", "The manifest is an array that holds a valid manifest", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		m["comment"] = "Not a member of whitetower.bundle.v1"
		return m
	})
	add("unknown-member", "The manifest has a member that its format does not define", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		policyEntry(m, 0)["description"] = "Not a member of a policy entry"
		return m
	})
	add("unknown-policy-member", "A policy entry has a member that the format does not define", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		delete(m, "combining_algorithm")
		return m
	})
	add("missing-member", "The manifest has no combining_algorithm: a missing member is invalid, not unsupported",
		b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		delete(policyEntry(m, 0), "name")
		return m
	})
	add("missing-policy-member", "A policy entry has no name", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		delete(m, "cedar_schema")
		return m
	})
	delete(b.Files, bundle.CedarSchemaPath)
	add("no-schema", "The manifest names no Cedar schema, and the bundle carries none", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		policyEntry(m, 0)["version"] = "3"
		return m
	})
	add("wrong-type", "A policy entry's version is a string", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		m["language"] = nil
		return m
	})
	add("null-member", "The manifest's language is null, which is of no type the format allows: invalid, not unsupported",
		b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	b = changed(valid(), func(m map[string]any) any {
		m["created_at"] = "2026-09-29T10:00:00Z"
		return m
	})
	add("malformed-time", "The manifest's created_at has no milliseconds", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	m = baseManifest(42)
	m.Format = "whitetower.bundle.v2"
	b = build(m, baseFiles(t), trustedID, trusted)
	add("unsupported-format", "A format the enforcement point does not support", b, b.Ref(42), 41, rejected(bundle.ReasonUnsupported))

	// Only the language differs from the valid bundle, so that the schema
	// refuses this manifest for its language alone.
	m = baseManifest(42)
	m.Language = "rego"
	b = build(m, baseFiles(t), trustedID, trusted)
	add("unsupported-language", "The manifest names the language rego, which v1alpha1 does not have", b, b.Ref(42), 41, rejected(bundle.ReasonUnsupported))

	m = baseManifest(42)
	m.Format = "whitetower.bundle.v2"
	b = changed(build(m, baseFiles(t), trustedID, trusted), func(m map[string]any) any {
		m["comment"] = "Not a member of whitetower.bundle.v1"
		return m
	})
	add("unsupported-and-unknown-member", "A format the enforcement point does not support, with a member that whitetower.bundle.v1 does not define: the structure is checked first",
		b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	m = baseManifest(42)
	m.AgentID = otherAgent
	m.CombiningAlgorithm = "first-applicable"
	b = build(m, baseFiles(t), trustedID, trusted)
	add("unsupported-and-wrong-agent", "A combining algorithm the contract does not define, in a bundle for another agent: the values are checked before the agent",
		b, b.Ref(42), 41, rejected(bundle.ReasonUnsupported))

	b = build(baseManifest(43), baseFiles(t), trustedID, trusted)
	add("wrong-version", "A valid bundle at version 43, which governance state names as version 42", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	// V5. Each policy's path is built from its entry, and the Cedar schema
	// sits at schema.cedarschema.
	m = baseManifest(42)
	m.Policies[0].Path = "policies/" + globalID + ".cedar"
	b = build(m, moved(baseFiles(t), "policies/global/"+globalID+".cedar", m.Policies[0].Path), trustedID, trusted)
	add("malformed-path", "A policy's path has no directory for its scope", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	m = baseManifest(42)
	m.Policies[1].Path = "policies/agent/" + otherPolicyID + ".cedar"
	b = build(m, moved(baseFiles(t), "policies/agent/"+agentID+".cedar", m.Policies[1].Path), trustedID, trusted)
	add("mismatched-path", "A policy's path names the ID of another policy", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	m = baseManifest(42)
	m.Policies[0].Path = "policies/agent/" + globalID + ".cedar"
	b = build(m, moved(baseFiles(t), "policies/global/"+globalID+".cedar", m.Policies[0].Path), trustedID, trusted)
	add("mismatched-scope", "A global policy's path is in the directory of agent-specific policies", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	m = baseManifest(42)
	twice := m.Policies[0]
	twice.Version = 4
	m.Policies = append(m.Policies, twice)
	b = build(m, baseFiles(t), trustedID, trusted)
	add("duplicate-path", "The global policy is listed twice, in two versions, at the same path", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	m = baseManifest(42)
	m.CedarSchema.Path = "whitetower.cedarschema"
	b = build(m, moved(baseFiles(t), bundle.CedarSchemaPath, m.CedarSchema.Path), trustedID, trusted)
	add("misplaced-schema", "The Cedar schema is not at schema.cedarschema", b, b.Ref(42), 41, rejected(bundle.ReasonInvalidManifest))

	// V7. Static policies, which only the core validates against the schema.
	files = baseFiles(t)
	files["policies/agent/"+agentID+".cedar"] = []byte(`@id("invoice-triage-tools")
permit (principal == ?principal, action == WhiteTower::Action::"tool.invoke", resource);
`)
	b = build(baseManifest(42), files, trustedID, trusted)
	add("template", "A policy is a template, with a slot for its principal", b, b.Ref(42), 41, rejected(bundle.ReasonParseError))

	if err := validatePolicy(cedarValidator(t, ""), globalID, failsValidation); err == nil {
		t.Fatal("the policy of fails-validation passes the validator")
	}
	files = baseFiles(t)
	files["policies/global/"+globalID+".cedar"] = []byte(failsValidation)
	b = build(baseManifest(42), files, trustedID, trusted)
	add("fails-validation", "A policy parses, but fails validation against the bundle's Cedar schema, which is the core's job only",
		b, b.Ref(42), 41, bundleOutcome{Outcome: "activated"})

	return out
}

// jwkSet is a JWK Set (RFC 7517) of public Ed25519 keys (RFC 8037). Its
// description is a member that RFC 7517 has readers ignore.
type jwkSet struct {
	Description string `json:"description"`
	Keys        []jwk  `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// publicJWK returns the public half of a key, with its RFC 7638 thumbprint as
// its ID.
func publicJWK(key ed25519.PrivateKey) jwk {
	pub := key.Public().(ed25519.PublicKey)
	return jwk{
		Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub),
		Kid: bundle.KeyID(pub), Alg: bundle.Algorithm, Use: "sig",
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
		"trusted-keys.json": marshalIndent(t, jwkSet{
			Description: "The bundle keys that a module under test trusts. Their seeds are public: never trust these keys outside tests.",
			Keys:        []jwk{publicJWK(testKey("trusted"))},
		}),
		"untrusted-keys.json": marshalIndent(t, jwkSet{
			Description: "A key that no module under test trusts, which signs the unknown-key and forged-key-id cases. Its seed is public: never trust it anywhere.",
			Keys:        []jwk{publicJWK(testKey("untrusted"))},
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

// bundleCaseNames returns the directories of vectors/bundles, one per case.
func bundleCaseNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("no bundle vectors: run TestBundleVectorsAreCurrent with -update")
	}
	return names
}

// TestBundleVectors verifies every committed case as an enforcement point
// would, with the keys of trusted-keys.json, and checks the outcome it
// expects.
func TestBundleVectors(t *testing.T) {
	trusted, err := kit.LoadKeys(os.DirFS(bundleDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) == 0 {
		t.Fatal("trusted-keys.json holds no key the verifier can use")
	}
	for _, name := range bundleCaseNames(t) {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(bundleDir, name)
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
			}
			if outcome != c.Expected {
				t.Fatalf("got %+v, want %+v (%v)", outcome, c.Expected, err)
			}
			if err != nil {
				return
			}
			// The reference engine runs every bundle the verifier activates.
			var ps []profile.Policy
			for _, p := range m.Policies {
				ps = append(ps, profile.Policy{ID: p.ID, Text: string(b.Files[p.Path])})
			}
			if _, err := profile.NewEngine(m.AgentID, m.Version, ps); err != nil {
				t.Errorf("the engine refuses an activated bundle: %v", err)
			}
		})
	}
}

// TestTheManifestSchemaAgreesWithStepV4 checks the manifest of every bundle
// vector against bundle-manifest.schema.json. A manifest that step V4 refuses
// on its own, as invalid_manifest or unsupported, fails the schema, and the
// manifest of every activated bundle passes it. The other manifests may go
// either way: the schema cannot tie a policy's path to its entry, which step
// V5 does, nor know the agent and the version that governance state names.
func TestTheManifestSchemaAgreesWithStepV4(t *testing.T) {
	schema := compileSchema(t, "../../api/policy/bundle-manifest.schema.json")
	for _, name := range bundleCaseNames(t) {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(bundleDir, name)
			var c bundleCase
			loadJSON(t, filepath.Join(root, "case.json"), &c)
			manifest, err := os.ReadFile(filepath.Join(root, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			schemaErr := validateJSON(schema, json.RawMessage(manifest))
			if _, err := bundle.ParseManifest(manifest, []string{"cedar"}); err != nil && schemaErr == nil {
				t.Errorf("step V4 refuses the manifest (%v), and the schema accepts it", err)
			}
			if c.Expected.Outcome == "activated" && schemaErr != nil {
				t.Errorf("the bundle is activated, and the schema refuses its manifest: %v", schemaErr)
			}
		})
	}
}
