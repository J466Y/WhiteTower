package conformance_test

import (
	"bytes"
	"encoding/json"
	"errors"
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

// namedRules are the rules of the profile that its schema does not state, by
// the names that the combination vectors give them.
var namedRules = map[string]error{
	"another_agent":  profile.ErrAnotherAgent,
	"not_an_integer": profile.ErrNotAnInteger,
	"invalid_time":   profile.ErrTime,
}

// checkRefusal checks why a request that a vector refuses as outside the
// profile is outside it: it does not match the profile's schema, or, when the
// vector names a rule, it matches the schema and breaks that rule, which the
// schema does not state.
func checkRefusal(t *testing.T, requestSchema *jsonschema.Schema, request json.RawMessage, rule string) {
	t.Helper()
	schemaErr := validateJSON(requestSchema, request)
	if rule == "" {
		if schemaErr == nil {
			t.Error("the request matches the profile's schema, and the vector names no rule that refuses it")
		}
		return
	}
	want, ok := namedRules[rule]
	switch {
	case !ok:
		t.Errorf("the vector names the rule %q, which the profile does not have", rule)
	case schemaErr != nil:
		t.Errorf("the request does not match the profile's schema, so the rule %s is not what refuses it: %v", rule, schemaErr)
	default:
		req, err := profile.DecodeRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := profile.ToCedar(req); !errors.Is(err, want) {
			t.Errorf("the profile refuses the request with %v, want the rule %s: %v", err, rule, want)
		}
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
			ID          string `json:"id"`
			Description string `json:"description"`
			Section     string `json:"section"`
			// The rule of the profile, outside its schema, that refuses
			// the request; empty when the schema refuses it, or when the
			// request is inside the profile.
			Rule     string         `json:"rule"`
			Policies []policyVector `json:"policies"`
			// The request as the vector gives it, so that the profile
			// reads its members and numbers as they are written.
			Request  json.RawMessage `json:"request"`
			Expected expectation     `json:"expected"`
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
			// A request refused as outside the profile fails the schema, or
			// breaks the rule that its case names. One refused for another
			// agent may be outside the profile too, since that reason comes
			// first (section 6.6). Every other request matches the schema.
			switch {
			case c.Expected.Reason == profile.ReasonInvalidRequest:
				checkRefusal(t, requestSchema, c.Request, c.Rule)
			case c.Rule != "":
				t.Errorf("the vector names the rule %s, but expects %s", c.Rule, c.Expected.Reason)
			case c.Expected.Reason == profile.ReasonUnknownAgent:
			default:
				if err := validateJSON(requestSchema, c.Request); err != nil {
					t.Errorf("request does not match the profile's schema: %v", err)
				}
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

// withEnvironment returns a request whose subject carries the environment
// given, as an enforcement point builds it from its registration (section
// 6.2).
func withEnvironment(t *testing.T, request json.RawMessage, environment string) json.RawMessage {
	t.Helper()
	var req map[string]any
	dec := json.NewDecoder(bytes.NewReader(request))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		t.Fatal(err)
	}
	subject, _ := req["subject"].(map[string]any)
	properties, ok := subject["properties"].(map[string]any)
	if !ok {
		t.Fatal("the request's subject has no properties")
	}
	properties["environment"] = environment
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestFailClosedVectors runs the gate vectors against the reference gate.
func TestFailClosedVectors(t *testing.T) {
	var file struct {
		Description string          `json:"description"`
		Profile     string          `json:"profile"`
		AgentID     string          `json:"agent_id"`
		Policies    []policyVector  `json:"policies"`
		Request     json.RawMessage `json:"request"`
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
			got := engine.Evaluate(withEnvironment(t, file.Request, c.State.Environment))
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
