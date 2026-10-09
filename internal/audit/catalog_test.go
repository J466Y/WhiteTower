package audit

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/J466Y/WhiteTower/api/events"
	"github.com/J466Y/WhiteTower/internal/platform/golden"
)

func loadCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := LoadCatalog(events.Files)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// decode canonicalizes an event, as the audit log stores it, and decodes it.
func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	_, event, err := canonicalize(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

// Every example of the catalog is valid, and what the audit log indexes of
// it is in testdata/facts.json.
func TestEveryExampleIsIndexed(t *testing.T) {
	c := loadCatalog(t)
	examples, err := filepath.Glob("../../api/events/examples/*.json")
	if err != nil || len(examples) != len(c.types) {
		t.Fatalf("%d examples for %d types: %v", len(examples), len(c.types), err)
	}
	indexed := map[string]map[string]string{}
	for _, path := range examples {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		event := decode(t, raw)
		et, err := c.check(event)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		f, err := factsOf(et, event)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		indexed[event["type"].(string)] = map[string]string{
			"actor_type": f.actorType, "actor_id": f.actorID, "action": f.action, "outcome": f.outcome, "reason": f.reason,
		}
	}
	golden.AssertJSON(t, "testdata/facts.json", indexed)
}

// withCatalog returns the catalog's files with catalog.json changed by edit.
func withCatalog(t *testing.T, edit func(types []any) []any) fs.FS {
	t.Helper()
	files := fstest.MapFS{}
	err := fs.WalkDir(events.Files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(events.Files, name)
		files[name] = &fstest.MapFile{Data: data}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(files["catalog.json"].Data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["types"] = edit(doc["types"].([]any))
	if files["catalog.json"].Data, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	return files
}

func TestEveryTypeNeedsARule(t *testing.T) {
	added := withCatalog(t, func(types []any) []any {
		extra := map[string]any{}
		for k, v := range types[0].(map[string]any) {
			extra[k] = v
		}
		extra["type"] = "whitetower.agent.renamed.v1"
		return append(types, extra)
	})
	if _, err := LoadCatalog(added); err == nil || !strings.Contains(err.Error(), "whitetower.agent.renamed.v1: the audit log has no rule") {
		t.Errorf("a type without a rule: %v", err)
	}
	removed := withCatalog(t, func(types []any) []any { return types[1:] })
	if _, err := LoadCatalog(removed); err == nil || !strings.Contains(err.Error(), "a type the catalog does not hold") {
		t.Errorf("a rule without a type: %v", err)
	}
}

func TestCheckRefusesInvalidEvents(t *testing.T) {
	c := loadCatalog(t)
	example := func(name string) map[string]any {
		raw, err := os.ReadFile("../../api/events/examples/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		return decode(t, raw)
	}
	for _, tt := range []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"a type outside the catalog", func(e map[string]any) { e["type"] = "whitetower.agent.renamed.v1" }, "not a type of the event catalog"},
		{"no subject where it is required", func(e map[string]any) { delete(e, "subject") }, "the subject, its agent, is required"},
		{"an unknown member of the data", func(e map[string]any) {
			e["data"].(map[string]any)["email"] = "olivia@example.org"
		}, "invalid data"},
		{"a source of no stream", func(e map[string]any) { e["source"] = "/elsewhere" }, "invalid envelope"},
		{"a time without milliseconds", func(e map[string]any) { e["time"] = "2026-09-29T10:15:02Z" }, "invalid envelope"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := example("whitetower.agent.created.v1")
			tt.edit(e)
			if _, err := c.check(e); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
	checkpoint := example("whitetower.audit.checkpoint.v1")
	checkpoint["subject"] = "0192f1c2-7a3b-7c4d-8e5f-000000000001"
	if _, err := c.check(checkpoint); err == nil || !strings.Contains(err.Error(), "has no subject") {
		t.Errorf("a subject where there is none: %v", err)
	}
}

func TestEmitterAndAction(t *testing.T) {
	for source, want := range map[string][2]string{
		"/core": {"system", ""},
		"/agents/0192f1c2-7a3b-7c4d-8e5f-000000000001/ep/b7e2c1d4": {"agent", "0192f1c2-7a3b-7c4d-8e5f-000000000001"},
		"/modules/k8s-quarantine/cluster-a":                        {"module", "k8s-quarantine"},
	} {
		if typ, id := emitter(source); typ != want[0] || id != want[1] {
			t.Errorf("%s: %s %s, want %v", source, typ, id, want)
		}
	}
	if got := action("whitetower.agent.lifecycle_changed.v12"); got != "agent.lifecycle_changed" {
		t.Errorf("action %q", got)
	}
}
