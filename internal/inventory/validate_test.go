package inventory

import (
	"encoding/json"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/J466Y/WhiteTower/api/openapi"
	"github.com/J466Y/WhiteTower/api/policy"
)

// member returns the member that the path of names leads to in a decoded
// document.
func member(t *testing.T, doc any, path ...string) any {
	t.Helper()
	for _, name := range path {
		object, ok := doc.(map[string]any)
		if !ok {
			t.Fatalf("no object holds the member %q", name)
		}
		doc = object[name]
	}
	return doc
}

// Enforcement points build the subject of each decision request from the
// labels that the inventory accepts, so the inventory checks label keys with
// the pattern of the request's schema (CORE-17), and the OpenAPI document
// tells clients the same pattern.
func TestTheInventoryTheAPIAndTheDecisionRequestShareTheLabelKeyPattern(t *testing.T) {
	raw, err := policy.Files.ReadFile("decision-request.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var request, document any
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(openapi.Document, &document); err != nil {
		t.Fatal(err)
	}
	patterns := map[string]any{
		"decision-request.schema.json": member(t, request,
			"properties", "subject", "properties", "properties", "properties", "labels", "propertyNames", "pattern"),
		"openapi.yaml": member(t, document, "components", "schemas", "Labels", "propertyNames", "pattern"),
	}
	for name, pattern := range patterns {
		if pattern != labelKeyPattern.String() {
			t.Errorf("%s gives label keys the pattern %v, the inventory %s", name, pattern, labelKeyPattern)
		}
	}
}
