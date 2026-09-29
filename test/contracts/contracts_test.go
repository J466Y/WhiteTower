// Package contracts checks the contract files in api/: every schema compiles,
// every example is valid, every invalid example is refused, and the files agree
// with one another.
package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

const api = "../../api"

func compile(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	sch, err := jsonschema.NewCompiler().Compile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return sch
}

// loadYAML reads a YAML (or JSON) document and returns it in the form the
// JSON Schema validator expects.
func loadYAML(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return inst
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no files match %s", pattern)
	}
	return files
}

type manifest struct {
	Spec struct {
		Events struct {
			Emits []string `json:"emits"`
		} `json:"events"`
		ConfigSchema map[string]any `json:"configSchema"`
	} `json:"spec"`
}

func TestManifestExamplesAreValid(t *testing.T) {
	sch := compile(t, api+"/manifest/module-manifest.schema.json")
	catalog := catalogTypes(t)
	for _, path := range glob(t, api+"/manifest/examples/*.yaml") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			inst := loadYAML(t, path)
			if err := sch.Validate(inst); err != nil {
				t.Fatalf("invalid: %v", err)
			}
			raw, _ := json.Marshal(inst)
			var m manifest
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			for _, e := range m.Spec.Events.Emits {
				if !slices.Contains(catalog, e) {
					t.Errorf("emits %s, which is not in the event catalog", e)
				}
			}
			// The configuration schema must itself be a valid JSON Schema.
			if m.Spec.ConfigSchema != nil {
				c := jsonschema.NewCompiler()
				if err := c.AddResource("config.json", m.Spec.ConfigSchema); err != nil {
					t.Fatal(err)
				}
				if _, err := c.Compile("config.json"); err != nil {
					t.Errorf("configSchema: %v", err)
				}
			}
		})
	}
}

func TestInvalidManifestsAreRefused(t *testing.T) {
	sch := compile(t, api+"/manifest/module-manifest.schema.json")
	for _, path := range glob(t, api+"/manifest/testdata/invalid/*.yaml") {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if err := sch.Validate(loadYAML(t, path)); err == nil {
				t.Error("accepted, but the manifest is invalid")
			}
		})
	}
}

type catalogEntry struct {
	Type     string   `json:"type"`
	Summary  string   `json:"summary"`
	Emitters []string `json:"emitters"`
	Subject  string   `json:"subject"`
	Schema   string   `json:"schema"`
	Example  string   `json:"example"`
}

func catalogEntries(t *testing.T) []catalogEntry {
	t.Helper()
	var catalog struct {
		Description     string         `json:"description"`
		ContractVersion string         `json:"contract_version"`
		Types           []catalogEntry `json:"types"`
	}
	loadJSON(t, api+"/events/catalog.json", &catalog)
	return catalog.Types
}

func catalogTypes(t *testing.T) []string {
	t.Helper()
	var types []string
	for _, e := range catalogEntries(t) {
		types = append(types, e.Type)
	}
	return types
}

var eventType = regexp.MustCompile(`^whitetower\.[a-z_]+\.[a-z_]+\.v[1-9][0-9]*$`)

func TestEventCatalog(t *testing.T) {
	envelope := compile(t, api+"/events/cloudevent.schema.json")
	entries := catalogEntries(t)
	seen := map[string]bool{}
	for _, e := range entries {
		t.Run(e.Type, func(t *testing.T) {
			if !eventType.MatchString(e.Type) || seen[e.Type] {
				t.Fatalf("bad or duplicate type %q", e.Type)
			}
			seen[e.Type] = true
			if e.Schema != "schemas/"+e.Type+".json" || e.Example != "examples/"+e.Type+".json" {
				t.Errorf("unexpected paths %s, %s", e.Schema, e.Example)
			}
			data := compile(t, api+"/events/"+e.Schema)

			var event map[string]any
			raw, err := os.ReadFile(api + "/events/" + e.Example)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := envelope.Validate(inst); err != nil {
				t.Errorf("envelope: %v", err)
			}
			event = inst.(map[string]any)
			if event["type"] != e.Type {
				t.Errorf("example has type %v", event["type"])
			}
			if err := data.Validate(event["data"]); err != nil {
				t.Errorf("data: %v", err)
			}

			_, hasSubject := event["subject"]
			switch e.Subject {
			case "required":
				if !hasSubject {
					t.Error("the subject is required")
				}
			case "none":
				if hasSubject {
					t.Error("the subject must be absent")
				}
			case "optional":
			default:
				t.Errorf("subject rule %q", e.Subject)
			}

			source, _ := event["source"].(string)
			fromCore := slices.Contains(e.Emitters, "core")
			if fromCore && (len(e.Emitters) != 1 || source != "/core") {
				t.Errorf("core events come from /core only, got %v from %s", e.Emitters, source)
			}
			if !fromCore && source == "/core" {
				t.Error("module events never come from /core")
			}
			for _, emitter := range e.Emitters {
				if !slices.Contains([]string{"core", "enforcement-point", "runtime-control", "event-source"}, emitter) {
					t.Errorf("unknown emitter %q", emitter)
				}
			}
		})
	}
	if len(entries) == 0 {
		t.Fatal("empty catalog")
	}
	// Every schema file belongs to a catalog entry.
	for _, path := range glob(t, api+"/events/schemas/whitetower.*.json") {
		if !seen[strings.TrimSuffix(filepath.Base(path), ".json")] {
			t.Errorf("%s is not in the catalog", path)
		}
	}
}

func TestPolicySchemasCompile(t *testing.T) {
	for _, path := range glob(t, api+"/policy/*.schema.json") {
		compile(t, path)
	}
}
