package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// validRequest returns a decision request inside the profile: a tool call
// with an argument, from an agent with labels and data categories.
func validRequest() map[string]any {
	return map[string]any{
		"subject": map[string]any{
			"type": "agent",
			"id":   "0192f1c2-7a3b-7c4d-8e5f-000000000001",
			"properties": map[string]any{
				"slug":            "invoice-triage",
				"kind":            "in_house",
				"risk_tier":       "high",
				"environment":     "production",
				"data_categories": []any{"customer data", "financial data"},
				"owner":           "0192f1c2-7a3b-7c4d-8e5f-0000000000a1",
				"labels":          map[string]any{"team": "finance"},
			},
		},
		"action":   map[string]any{"name": "tool.invoke"},
		"resource": map[string]any{"type": "tool", "id": "send_email", "properties": map[string]any{"kind": "function"}},
		"context": map[string]any{
			"time": "2026-09-29T10:15:02.118Z",
			"args": map[string]any{"recipient_domain": "example.org"},
		},
	}
}

func subjectProperties(req map[string]any) map[string]any {
	return req["subject"].(map[string]any)["properties"].(map[string]any)
}

func requestContext(req map[string]any) map[string]any {
	return req["context"].(map[string]any)
}

// withLabels gives the agent n labels.
func withLabels(n int) func(map[string]any) {
	return func(req map[string]any) {
		labels := map[string]any{}
		for i := range n {
			labels[fmt.Sprintf("label-%d", i)] = "value"
		}
		subjectProperties(req)["labels"] = labels
	}
}

// withLabelValue gives the agent's label a value.
func withLabelValue(value string) func(map[string]any) {
	return func(req map[string]any) {
		subjectProperties(req)["labels"] = map[string]any{"team": value}
	}
}

// withCategories gives the agent n data categories.
func withCategories(n int) func(map[string]any) {
	return func(req map[string]any) {
		categories := make([]any, 0, n)
		for i := range n {
			categories = append(categories, fmt.Sprintf("category %d", i))
		}
		subjectProperties(req)["data_categories"] = categories
	}
}

// withCategory gives the agent one data category.
func withCategory(category string) func(map[string]any) {
	return func(req map[string]any) {
		subjectProperties(req)["data_categories"] = []any{category}
	}
}

// withContext sets a member of the request's context.
func withContext(name string, value any) func(map[string]any) {
	return func(req map[string]any) {
		requestContext(req)[name] = value
	}
}

// TestTheDecisionRequestSchemaRefusesRequestsOutsideTheProfile checks the
// rules of sections 6.2 and 6.4 that the request schema states: on_behalf_of
// is never present, arguments are never null, and labels and data categories
// keep the inventory's bounds (CORE-17). Each refusal sits next to a request
// at the bound that the schema accepts.
func TestTheDecisionRequestSchemaRefusesRequestsOutsideTheProfile(t *testing.T) {
	sch := compile(t, api+"/policy/decision-request.schema.json")
	cases := []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{name: "a request inside the profile", edit: func(map[string]any) {}, valid: true},

		{name: "on_behalf_of with a name", edit: withContext("on_behalf_of", "0192f1c2-7a3b-7c4d-8e5f-0000000000a2")},
		{name: "on_behalf_of empty", edit: withContext("on_behalf_of", "")},
		{name: "on_behalf_of null", edit: withContext("on_behalf_of", nil)},

		{name: "arguments with nested values", valid: true, edit: withContext("args", map[string]any{
			"recipients": []any{"a@example.org", "b@example.org"},
			"options":    map[string]any{"retries": 2, "urgent": false, "tags": []any{"invoice"}},
		})},
		{name: "a null argument", edit: withContext("args", map[string]any{"recipient_domain": nil})},
		{name: "a null in an argument's array", edit: withContext("args", map[string]any{
			"recipients": []any{"a@example.org", nil},
		})},
		{name: "a null in an argument's object", edit: withContext("args", map[string]any{
			"options": map[string]any{"retries": 2, "urgent": nil},
		})},

		{name: "64 labels", edit: withLabels(64), valid: true},
		{name: "65 labels", edit: withLabels(65)},
		{name: "a label value of 255 characters", edit: withLabelValue(strings.Repeat("a", 255)), valid: true},
		{name: "a label value of 256 characters", edit: withLabelValue(strings.Repeat("a", 256))},
		// U+1D49C takes 4 bytes in UTF-8 and 2 code units in UTF-16: the bound
		// counts characters, as the inventory does.
		{name: "a label value of 255 multi-byte characters", edit: withLabelValue(strings.Repeat("\U0001D49C", 255)), valid: true},

		{name: "32 data categories", edit: withCategories(32), valid: true},
		{name: "33 data categories", edit: withCategories(33)},
		{name: "a data category of 63 characters", edit: withCategory(strings.Repeat("c", 63)), valid: true},
		{name: "a data category of 64 characters", edit: withCategory(strings.Repeat("c", 64))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.edit(req)
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			err = sch.Validate(inst)
			switch {
			case tc.valid && err != nil:
				t.Errorf("refused, but the request is inside the profile: %v", err)
			case !tc.valid && err == nil:
				t.Error("accepted, but the request is outside the profile")
			}
		})
	}
}
