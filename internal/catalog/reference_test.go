package catalog

import (
	"encoding/json"
	"os"
	"testing"
)

// The string forms of references that events hash are those of the
// conformance vectors, which enforcement points compute (contracts, section
// 4.10). The core receives a tool's server reference and a model's endpoint
// as computed, so the vectors give those parts from their expected string
// forms.
func TestStringFormsAreThoseOfTheConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile("../../test/conformance/vectors/tooling.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		References []struct {
			ID    string `json:"id"`
			Entry struct {
				Kind     string `json:"kind"`
				Name     string `json:"name"`
				Provider string `json:"provider"`
				Type     string `json:"type"`
			} `json:"entry"`
			Reference       *string `json:"reference"`
			ReferenceSHA256 *string `json:"reference_sha256"`
		} `json:"references"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, v := range vectors.References {
		if v.Reference == nil {
			continue
		}
		// computed returns a part that the enforcement point computed.
		computed := func(name string) string {
			var parts map[string]string
			if err := json.Unmarshal([]byte(*v.Reference), &parts); err != nil {
				t.Fatalf("%s: %v", v.ID, err)
			}
			return parts[name]
		}
		var parts map[string]string
		switch v.Entry.Kind {
		case "mcp_tool":
			parts = map[string]string{"name": v.Entry.Name, "server": computed("server")}
		case "tool":
			parts = map[string]string{"name": v.Entry.Name}
		case "builtin_tool":
			parts = map[string]string{"provider": v.Entry.Provider, "type": v.Entry.Type}
		case "model":
			parts = map[string]string{"endpoint": computed("endpoint"), "name": v.Entry.Name, "provider": v.Entry.Provider}
		default:
			continue
		}
		got, err := canonicalJSON(parts)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if got != *v.Reference || sha256Hex(got) != *v.ReferenceSHA256 {
			t.Errorf("%s: %s (%s), want %s (%s)", v.ID, got, sha256Hex(got), *v.Reference, *v.ReferenceSHA256)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no vector of a tool or a model")
	}
}
