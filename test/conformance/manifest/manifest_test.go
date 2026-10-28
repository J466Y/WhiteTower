package manifest_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/J466Y/WhiteTower/internal/platform/golden"
	"github.com/J466Y/WhiteTower/test/conformance/bundle"
	"github.com/J466Y/WhiteTower/test/conformance/manifest"
)

const (
	vectorDir  = "../vectors/manifests"
	exampleDir = "../../../api/manifest/examples"
)

// examples are the manifests of exampleDir, each an accepted vector.
var examples = []string{"ep-python", "mock-module", "k8s-quarantine"}

// vectorCase is the case.json of a manifest vector.
type vectorCase struct {
	Description string   `json:"description"`
	Obligation  string   `json:"obligation"`
	Expected    expected `json:"expected"`
}

type expected struct {
	// Outcome is accepted or refused.
	Outcome string `json:"outcome"`
	// SHA256 is the hash of an accepted manifest's canonical JSON.
	SHA256 string `json:"sha256,omitempty"`
}

// generated is a vector as the examples make it.
type generated struct {
	name     string
	meta     vectorCase
	manifest []byte
	// canonical is the canonical JSON of an accepted manifest.
	canonical []byte
}

// refusals make the refused vectors: each is an example with one scalar
// replaced, so that the replacement alone is why the manifest is refused.
var refusals = []struct {
	name, description, example, old, new string
}{
	{
		"boolean-enumeration", "An enumeration [on, off]: booleans in YAML 1.1, strings in YAML 1.2",
		"mock-module.yaml", "enum: [normal, slow, silent, lying]", "enum: [on, off]",
	},
	{
		"date", "Versions written as a date: a timestamp in YAML 1.1, a string in YAML 1.2",
		"ep-python.yaml", `versions: ">=1.0,<2.0"`, "versions: 2026-10-28",
	},
	{
		"integer-beyond-2-53", "The integer 2^53 + 1, which a double cannot hold, so the manifest is not I-JSON",
		"ep-python.yaml", "minimum: 1048576", "minimum: 9007199254740993",
	},
}

func generate(t *testing.T) []generated {
	t.Helper()
	var out []generated
	for _, name := range examples {
		src, err := os.ReadFile(filepath.Join(exampleDir, name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := manifest.Read(src)
		if err != nil {
			t.Fatalf("%s.yaml: %v", name, err)
		}
		out = append(out, generated{name: name, manifest: src, canonical: canonical, meta: vectorCase{
			Description: "The example " + name + ".yaml, with the hash an instance presents when it registers",
			Obligation:  "MAN-2", Expected: expected{Outcome: "accepted", SHA256: bundle.SHA256Hex(canonical)},
		}})
	}
	for _, r := range refusals {
		src, err := os.ReadFile(filepath.Join(exampleDir, r.example))
		if err != nil {
			t.Fatal(err)
		}
		if n := bytes.Count(src, []byte(r.old)); n != 1 {
			t.Fatalf("%s: %q appears %d times in %s", r.name, r.old, n, r.example)
		}
		out = append(out, generated{
			name: r.name, manifest: bytes.Replace(src, []byte(r.old), []byte(r.new), 1),
			meta: vectorCase{Description: r.description, Obligation: "MAN-1", Expected: expected{Outcome: "refused"}},
		})
	}
	return out
}

// TestManifestVectorsAreCurrent checks that the committed vectors are what
// the examples make. Run `go test ./test/conformance/manifest -run
// TestManifestVectorsAreCurrent -update` to regenerate them.
func TestManifestVectorsAreCurrent(t *testing.T) {
	want := map[string]bool{"README.md": true}
	for _, c := range generate(t) {
		dir := filepath.Join(vectorDir, c.name)
		golden.AssertJSON(t, filepath.Join(dir, "case.json"), c.meta)
		golden.Assert(t, filepath.Join(dir, "manifest.yaml"), c.manifest)
		want[c.name+"/case.json"], want[c.name+"/manifest.yaml"] = true, true
		if c.canonical != nil {
			golden.Assert(t, filepath.Join(dir, "canonical.json"), c.canonical)
			want[c.name+"/canonical.json"] = true
		}
	}
	err := filepath.WalkDir(vectorDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(vectorDir, path)
		if err == nil && !want[filepath.ToSlash(rel)] {
			t.Errorf("%s is not generated: remove it", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestManifestVectors reads every committed vector as the core would, and
// checks the outcome, the canonical JSON and the hash it expects.
func TestManifestVectors(t *testing.T) {
	schema, err := jsonschema.NewCompiler().Compile("../../../api/manifest/module-manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := os.ReadDir(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		count++
		t.Run(d.Name(), func(t *testing.T) {
			read := func(name string) []byte {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(vectorDir, d.Name(), name))
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			var c vectorCase
			dec := json.NewDecoder(bytes.NewReader(read("case.json")))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&c); err != nil {
				t.Fatal(err)
			}
			canonical, err := manifest.Read(read("manifest.yaml"))
			switch c.Expected.Outcome {
			case "accepted":
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !bytes.Equal(canonical, read("canonical.json")) {
					t.Errorf("canonical JSON differs from canonical.json:\n%s", canonical)
				}
				if got := bundle.SHA256Hex(canonical); got != c.Expected.SHA256 {
					t.Errorf("SHA-256 %s, want %s", got, c.Expected.SHA256)
				}
				// An accepted vector is a valid manifest too (MAN-1).
				inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(canonical))
				if err != nil {
					t.Fatal(err)
				}
				if err := schema.Validate(inst); err != nil {
					t.Errorf("does not match the manifest's schema: %v", err)
				}
			case "refused":
				if err == nil {
					t.Errorf("accepted, as %s", canonical)
				}
			default:
				t.Fatalf("outcome %q", c.Expected.Outcome)
			}
		})
	}
	if count == 0 {
		t.Fatal("no manifest vectors: run TestManifestVectorsAreCurrent with -update")
	}
}

// refused are documents that MAN-1 refuses, each with what the refusal says.
var refused = []struct{ name, yaml, want string }{
	{"not UTF-8", "a: \xff", "not UTF-8"},
	{"not YAML", "a: [b", "not YAML"},
	{"no document", "# a comment", "no document"},
	{"two documents", "a: 1\n---\nb: 2", "more than one document"},
	{"an anchor", "a: &x 1", "an anchor or an alias"},
	{"an alias", "a: &x 1\nb: *x", "an anchor or an alias"},
	{"a named tag", "a: !!str 1", "a tag"},
	{"a local tag", "a: !port 1", "a tag"},
	{"the non-specific tag", "a: ! 1", "a tag"},
	{"a tag on a key", "!x a: b", "a tag"},
	{"a tag on a mapping", "a: !\n  b: c", "a tag"},
	{"a tag in a sequence", "- ! a", "a tag"},
	{"a tag after a byte order mark", "\uFEFFa: ! 1", "a tag"},
	{"a tag after a character of two bytes", "a: 'é'\nb: ! c", "a tag"},
	{"a tag after a YAML 1.1 line break", "x: 1\n\u2028a: ! 5", "a tag"},
	{"a merge key", "a: {b: 1}\n<<: {c: 2}", `"<<" is not a string`},
	{"a duplicate key", "a: 1\na: 2", `the key "a" twice`},
	{"a duplicate key, once quoted", "a: 1\n\"a\": 2", `the key "a" twice`},
	{"a number as a key", "1: a", "a key that is not a string"},
	{"a boolean as a key", "true: a", "a key that is not a string"},
	{"a sequence as a key", "? [a]\n: b", "a key that is not a string"},
	{"yes", "a: yes", "not a string"},
	{"no", "a: no", "not a string"},
	{"on", "a: on", "not a string"},
	{"off", "a: off", "not a string"},
	{"y", "a: y", "not a string"},
	{"n", "a: n", "not a string"},
	{"True", "a: True", "not a string"},
	{"NULL", "a: NULL", "not a string"},
	{"a tilde", "a: ~", "not a string"},
	{"an empty value", "a:", "not a string"},
	{"a YAML 1.1 octal", "a: 0755", "not a string"},
	{"a YAML 1.2 octal", "a: 0o755", "not a string"},
	{"a hexadecimal", "a: 0x1F", "not a string"},
	{"a binary", "a: 0b101", "not a string"},
	{"a sexagesimal", "a: 1:30", "not a string"},
	{"underscores", "a: 1_000", "not a string"},
	{"an exponent", "a: 1e3", "not a string"},
	{"a signed exponent", "a: 1.5e+3", "not a string"},
	{"a plus sign", "a: +5", "not a string"},
	{"a fraction without an integer part", "a: .5", "not a string"},
	{"a point without a fraction", "a: 1.", "not a string"},
	{"infinity", "a: .inf", "not a string"},
	{"not a number", "a: .nan", "not a string"},
	{"a date", "a: 2026-10-28", "not a string"},
	{"a time", "a: 2026-10-28T10:15:02Z", "not a string"},
	{"a time with spaces", "a: 2026-10-28 10:15:02 -5", "not a string"},
	{"the value key", "a: =", "not a string"},
	{"2^53", "a: 9007199254740992", "not I-JSON"},
	{"-2^53", "a: -9007199254740992", "not I-JSON"},
	{"a fraction more precise than a double", "a: 0.10000000000000001", "not I-JSON"},
	{"a fraction beyond a double", "a: 1" + strings.Repeat("0", 400) + ".5", "not I-JSON"},
	{"a noncharacter", `a: "\uFFFF"`, "not I-JSON"},
	{"a noncharacter of the Arabic block", `a: "\uFDD0"`, "not I-JSON"},
	{"the last noncharacter", `a: "\U0010FFFF"`, "not I-JSON"},
}

func TestTheReaderRefusesWhatMAN1Refuses(t *testing.T) {
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			got, err := manifest.Read([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %s, %v; want an error with %q", got, err, tt.want)
			}
		})
	}
}

// accepted are documents that MAN-1 accepts, with their canonical JSON.
var accepted = []struct{ name, yaml, want string }{
	{"literals", "a: true\nb: false\nc: null", `{"a":true,"b":false,"c":null}`},
	{"integers", "a: 0\nb: -5\nc: -0\nd: 9007199254740991\ne: -9007199254740991", `{"a":0,"b":-5,"c":0,"d":9007199254740991,"e":-9007199254740991}`},
	{"fractions", "a: 1.5\nb: 1.0\nc: 0.1\nd: 0.000001\ne: 0.0000001\nf: -0.25", `{"a":1.5,"b":1,"c":0.1,"d":0.000001,"e":1e-7,"f":-0.25}`},
	{"quoted scalars", `a: "yes"` + "\nb: 'on'\nc: \"2026-10-28\"\nd: '1e3'\ne: \"~\"\nf: '0755'\ng: \"<<\"", `{"a":"yes","b":"on","c":"2026-10-28","d":"1e3","e":"~","f":"0755","g":"<<"}`},
	{"a quoted merge key", `"<<": a`, `{"<<":"a"}`},
	{"plain strings", "a: 0.1.0\nb: v1alpha1\nc: Apache-2.0\nd: https://example.org/x\ne: inf\nf: 0x", `{"a":"0.1.0","b":"v1alpha1","c":"Apache-2.0","d":"https://example.org/x","e":"inf","f":"0x"}`},
	{"block scalars", "a: |\n  x\n  y\nb: >-\n  x\n  y\n", `{"a":"x\ny\n","b":"x y"}`},
	{"a multi-line plain scalar", "a: x\n  y", `{"a":"x y"}`},
	{"flow collections", "a: {b: [x, 1], c: {}}", `{"a":{"b":["x",1],"c":{}}}`},
	{"escapes", `a: "\t\u0007\\\"/"`, `{"a":"\t\u0007\\\"/"}`},
	{"keys in the order of UTF-16", "\uFF61: 1\n\U0001F600: 2\nb: 3\na: 4", "{\"a\":4,\"b\":3,\"\U0001F600\":2,\"\uFF61\":1}"},
	{"a byte order mark and document markers", "\uFEFF---\na: 1\n...\n", `{"a":1}`},
}

func TestTheReaderAcceptsWhatMAN1Accepts(t *testing.T) {
	for _, tt := range accepted {
		t.Run(tt.name, func(t *testing.T) {
			got, err := manifest.Read([]byte(tt.yaml))
			if err != nil || string(got) != tt.want {
				t.Errorf("got %s, %v; want %s", got, err, tt.want)
			}
		})
	}
}

// FuzzRead checks that what Read returns is canonical JSON, and the same each
// time.
func FuzzRead(f *testing.F) {
	for _, name := range examples {
		src, err := os.ReadFile(filepath.Join(exampleDir, name+".yaml"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(src)
	}
	for _, tt := range refused {
		f.Add([]byte(tt.yaml))
	}
	for _, tt := range accepted {
		f.Add([]byte(tt.yaml))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := manifest.Read(data)
		if err != nil {
			return
		}
		again, err := jcs.Transform(got)
		if err != nil || !bytes.Equal(again, got) {
			t.Fatalf("not canonical JSON: %s (%v)", got, err)
		}
		if second, err := manifest.Read(data); err != nil || !bytes.Equal(second, got) {
			t.Fatalf("a second read differs: %s (%v)", second, err)
		}
	})
}
