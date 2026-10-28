package contracts

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestTheManifestSchemaAcceptsWellFormedVersions checks, on the mock module's
// example, the versions that the invalid manifests cannot: contract versions
// to come, and module versions up to the bound.
func TestTheManifestSchemaAcceptsWellFormedVersions(t *testing.T) {
	sch := compile(t, api+"/manifest/module-manifest.schema.json")
	for _, tt := range []struct {
		name      string
		contracts []any
		version   string
	}{
		{"contract versions to come, in the order of section 4.5", []any{"v2", "v1", "v1beta2", "v1beta1", "v1alpha2", "v1alpha1"}, "0.1.0"},
		{"a prerelease and build metadata", []any{"v1alpha1"}, "1.0.0-rc.1+build.7"},
		{"a version of 64 characters", []any{"v1alpha1"}, "1.0.0-rc.1+build.20261028.sha.0123456789abcdef0123456789abcdef01"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := loadYAML(t, api+"/manifest/examples/mock-module.yaml").(map[string]any)
			m["spec"].(map[string]any)["contractVersions"] = tt.contracts
			m["metadata"].(map[string]any)["version"] = tt.version
			if err := sch.Validate(m); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// TestTheManifestSchemaRefusesACapabilityDeclaredTwice declares, in turn,
// each capability of each example a second time.
func TestTheManifestSchemaRefusesACapabilityDeclaredTwice(t *testing.T) {
	sch := compile(t, api+"/manifest/module-manifest.schema.json")
	for _, path := range glob(t, api+"/manifest/examples/*.yaml") {
		capabilities := loadYAML(t, path).(map[string]any)["spec"].(map[string]any)["capabilities"].([]any)
		for i := range capabilities {
			m := loadYAML(t, path).(map[string]any)
			spec := m["spec"].(map[string]any)
			declared := spec["capabilities"].([]any)
			spec["capabilities"] = append(declared, declared[i])
			if err := sch.Validate(m); err == nil {
				t.Errorf("%s with %v twice: accepted", filepath.Base(path), declared[i].(map[string]any)["name"])
			}
		}
	}
}

// TestTheManifestSchemaRequiresTheEventsEachCapabilityEmits removes, in turn,
// each type that a capability must emit from each example that declares the
// capability (section 3.3).
func TestTheManifestSchemaRequiresTheEventsEachCapabilityEmits(t *testing.T) {
	sch := compile(t, api+"/manifest/module-manifest.schema.json")
	required := map[string][]string{
		"enforcement-point": {
			"whitetower.decision.made.v1", "whitetower.action.executed.v1", "whitetower.instance.halted.v1",
			"whitetower.bundle.activated.v1", "whitetower.bundle.rejected.v1", "whitetower.lease.expired.v1",
		},
		"runtime-control": {"whitetower.lease.expired.v1", "whitetower.quarantine.applied.v1", "whitetower.quarantine.lifted.v1"},
	}
	removed := map[string]bool{}
	for _, path := range glob(t, api+"/manifest/examples/*.yaml") {
		for capability, types := range required {
			for _, typ := range types {
				m := loadYAML(t, path).(map[string]any)
				spec := m["spec"].(map[string]any)
				if !slices.ContainsFunc(spec["capabilities"].([]any), func(c any) bool {
					return c.(map[string]any)["name"] == capability
				}) {
					continue
				}
				events := spec["events"].(map[string]any)
				events["emits"] = slices.DeleteFunc(events["emits"].([]any), func(e any) bool { return e == typ })
				if err := sch.Validate(m); err == nil {
					t.Errorf("%s without %s: accepted", filepath.Base(path), typ)
				}
				removed[capability+" "+typ] = true
			}
		}
	}
	for capability, types := range required {
		for _, typ := range types {
			if !removed[capability+" "+typ] {
				t.Errorf("no example declares %s to remove %s from", capability, typ)
			}
		}
	}
}
