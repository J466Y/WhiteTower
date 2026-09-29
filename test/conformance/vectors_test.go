package conformance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	internalast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/J466Y/WhiteTower/test/conformance/profile"
)

// policyVector is a policy of a vector.
type policyVector struct {
	ID    string `json:"id"`
	Scope string `json:"scope"`
	Text  string `json:"text"`
	// Whether the policy passes the validator.
	Valid bool `json:"valid"`
}

// expectation is the part of a response a vector checks.
type expectation struct {
	Decision bool     `json:"decision"`
	Reason   string   `json:"reason"`
	Policies []string `json:"policies"`
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	sch, err := jsonschema.NewCompiler().Compile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return sch
}

// validateJSON checks a Go value against a JSON Schema, through its JSON form.
func validateJSON(sch *jsonschema.Schema, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}

// cedarValidator returns a validator for the profile's Cedar schema, with a
// deployment's ToolArgs extension when one is given.
func cedarValidator(t *testing.T, toolArgs string) *validate.Validator {
	t.Helper()
	text, err := os.ReadFile("../../api/policy/whitetower.cedarschema")
	if err != nil {
		t.Fatal(err)
	}
	src := string(text)
	if toolArgs != "" {
		if !strings.Contains(src, "type ToolArgs = {};") {
			t.Fatal("the schema no longer declares an empty ToolArgs")
		}
		src = strings.Replace(src, "type ToolArgs = {};", toolArgs, 1)
	}
	var s schema.Schema
	if err := s.UnmarshalCedar([]byte(src)); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return validate.New(resolved)
}

// validatePolicy validates every statement of a policy text.
func validatePolicy(v *validate.Validator, id, text string) error {
	list, err := cedar.NewPolicyListFromBytes(id, []byte(text))
	if err != nil {
		return err
	}
	for i, p := range list {
		if err := v.Policy(fmt.Sprintf("%s#%d", id, i), (*internalast.Policy)(p.AST())); err != nil {
			return err
		}
	}
	return nil
}

func policies(vs []policyVector) []profile.Policy {
	out := make([]profile.Policy, 0, len(vs))
	for _, v := range vs {
		out = append(out, profile.Policy{ID: v.ID, Text: v.Text})
	}
	return out
}

func checkResponse(t *testing.T, got profile.Response, want expectation) {
	t.Helper()
	if got.Decision != want.Decision || got.Context.Reason != want.Reason || !slices.Equal(got.Context.Policies, want.Policies) {
		t.Errorf("got decision %v, reason %s, policies %v; want %v, %s, %v",
			got.Decision, got.Context.Reason, got.Context.Policies, want.Decision, want.Reason, want.Policies)
	}
}

// TestCombinationVectors runs the combination vectors against the reference
// implementation of the decision profile, on cedar-go.
func TestCombinationVectors(t *testing.T) {
	var file struct {
		Description       string `json:"description"`
		Profile           string `json:"profile"`
		AgentID           string `json:"agent_id"`
		ToolArgsExtension string `json:"tool_args_extension"`
		Cases             []struct {
			ID          string          `json:"id"`
			Description string          `json:"description"`
			Section     string          `json:"section"`
			Policies    []policyVector  `json:"policies"`
			Request     profile.Request `json:"request"`
			Expected    expectation     `json:"expected"`
		} `json:"cases"`
	}
	loadJSON(t, "vectors/combination.json", &file)
	requestSchema := compileSchema(t, "../../api/policy/decision-request.schema.json")
	responseSchema := compileSchema(t, "../../api/policy/decision-response.schema.json")
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}
	validator := cedarValidator(t, file.ToolArgsExtension)
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			for _, p := range c.Policies {
				if err := validatePolicy(validator, p.ID, p.Text); (err == nil) != p.Valid {
					t.Errorf("policy %s: validator says %v, the vector says valid=%v", p.ID, err, p.Valid)
				}
			}
			// Every request is valid against the profile's schema, except
			// those whose point is to be refused.
			if err := validateJSON(requestSchema, c.Request); err != nil && c.Expected.Reason != profile.ReasonInvalidRequest {
				t.Errorf("request does not match the profile's schema: %v", err)
			}
			engine, err := profile.NewEngine(file.AgentID, 1, policies(c.Policies))
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Evaluate(c.Request)
			checkResponse(t, got, c.Expected)
			if err := validateJSON(responseSchema, got); err != nil {
				t.Errorf("response does not match the profile's schema: %v", err)
			}
		})
	}
}

// TestFailClosedVectors runs the gate vectors against the reference gate.
func TestFailClosedVectors(t *testing.T) {
	var file struct {
		Description string          `json:"description"`
		Profile     string          `json:"profile"`
		AgentID     string          `json:"agent_id"`
		Policies    []policyVector  `json:"policies"`
		Request     profile.Request `json:"request"`
		Cases       []struct {
			ID          string            `json:"id"`
			Description string            `json:"description"`
			Obligation  string            `json:"obligation"`
			State       profile.GateState `json:"state"`
			Expected    expectation       `json:"expected"`
		} `json:"cases"`
	}
	loadJSON(t, "vectors/fail-closed.json", &file)
	engine, err := profile.NewEngine(file.AgentID, 1, policies(file.Policies))
	if err != nil {
		t.Fatal(err)
	}
	responseSchema := compileSchema(t, "../../api/policy/decision-response.schema.json")
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got := engine.Evaluate(file.Request)
			if reason := profile.GateReason(c.State); reason != "" {
				got = profile.Deny(reason)
			}
			checkResponse(t, got, c.Expected)
			if err := validateJSON(responseSchema, got); err != nil {
				t.Errorf("response does not match the profile's schema: %v", err)
			}
		})
	}
}
