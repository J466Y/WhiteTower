package conformance_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cedar-policy/cedar-go"
	internalast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
	"github.com/J466Y/WhiteTower/test/conformance/profile"
	"github.com/J466Y/WhiteTower/test/conformance/tooling"
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

// vectorBundleVersion is the version of the bundle that the policies of a
// vector make up. Any version would do: what the tests check is that a
// response carries it where section 6.6 says it always does.
const vectorBundleVersion = 42

// withBundleVersion says, for each reason, whether a response carries the
// version of the bundle that decided: always (true) or never (false), as
// section 6.6 says. A response with any other reason, error.timeout,
// error.unknown_agent or error.invalid_request, may carry it or not.
var withBundleVersion = map[string]bool{
	profile.ReasonPermit:          true,
	profile.ReasonForbid:          true,
	profile.ReasonNoPermit:        true,
	profile.ReasonEvaluationError: true,
	profile.ReasonNoState:         false,
	profile.ReasonLeaseExpired:    false,
	profile.ReasonHalted:          false,
	profile.ReasonFleetHalted:     false,
	profile.ReasonLifecycle:       false,
	profile.ReasonNoBundle:        false,
	profile.ReasonEvidenceFull:    false,
}

// checkBundleVersion checks a response's bundle_version by its reason.
func checkBundleVersion(t *testing.T, got profile.Response) {
	t.Helper()
	always, ruled := withBundleVersion[got.Context.Reason]
	switch {
	case !ruled:
	case always && got.Context.BundleVersion != vectorBundleVersion:
		t.Errorf("reason %s with bundle_version %d, want %d", got.Context.Reason, got.Context.BundleVersion, vectorBundleVersion)
	case !always && got.Context.BundleVersion != 0:
		t.Errorf("reason %s with bundle_version %d, want none", got.Context.Reason, got.Context.BundleVersion)
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
			engine, err := profile.NewEngine(file.AgentID, vectorBundleVersion, policies(c.Policies))
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Evaluate(c.Request)
			checkResponse(t, got, c.Expected)
			checkBundleVersion(t, got)
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
	engine, err := profile.NewEngine(file.AgentID, vectorBundleVersion, policies(file.Policies))
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
			checkBundleVersion(t, got)
			if err := validateJSON(responseSchema, got); err != nil {
				t.Errorf("response does not match the profile's schema: %v", err)
			}
		})
	}
}

// hashedArguments is what a decision event records of a call's arguments in
// the hashed mode (section 8.3).
type hashedArguments struct {
	CanonicalJSON string   `json:"canonical_json"`
	HMACSHA256    string   `json:"hmac_sha256"`
	Names         []string `json:"names"`
	NamesSHA256   []string `json:"names_sha256"`
}

// maxNameLength is the length, in characters, beyond which an event records
// an argument name as its SHA-256 (section 8.3).
const maxNameLength = 128

// hashArguments computes the hashed mode of a call's arguments, given as JSON
// text (section 8.3): the HMAC-SHA-256 of their canonical JSON, which section
// 4.10 writes, with the key given. Arguments without a canonical JSON are
// recorded by their names alone, each once: a name longer than 128
// characters, or with a lone surrogate, which an event cannot write, as the
// SHA-256 of its UTF-8 bytes with each lone surrogate replaced by U+FFFD.
func hashArguments(t *testing.T, key, text []byte) hashedArguments {
	t.Helper()
	v, err := canonical.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	data, err := canonical.Encode(v)
	if err == nil {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return hashedArguments{CanonicalJSON: string(data), HMACSHA256: hex.EncodeToString(mac.Sum(nil))}
	}
	if !errors.Is(err, canonical.ErrNoCanonicalJSON) {
		t.Fatal(err)
	}
	args, ok := v.(canonical.Object)
	if !ok {
		t.Fatalf("the arguments are a %T, not an object", v)
	}
	var names, hashed []string
	for _, m := range args {
		name := m.Name.String()
		if !m.Name.HasLoneSurrogate() && utf8.RuneCountInString(name) <= maxNameLength {
			names = append(names, name)
			continue
		}
		sum := sha256.Sum256([]byte(name))
		hashed = append(hashed, hex.EncodeToString(sum[:]))
	}
	return hashedArguments{Names: set(names), NamesSHA256: set(hashed)}
}

// set returns the distinct strings of s, sorted.
func set(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

// TestHashedArgumentsVectors computes the hashed mode of a decision event's
// arguments (section 8.3) with the vectors' key, as the HMAC of their
// canonical JSON or as their names alone.
func TestHashedArgumentsVectors(t *testing.T) {
	var file struct {
		Description string `json:"description"`
		Key         string `json:"key"`
		Cases       []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			// The arguments as the vector writes them, members out of order
			// and escapes included, as a JSON value or as text.
			Arguments     json.RawMessage `json:"arguments"`
			ArgumentsText string          `json:"arguments_text"`
			hashedArguments
		} `json:"cases"`
	}
	loadJSON(t, "vectors/hashed-arguments.json", &file)
	key, err := hex.DecodeString(file.Key)
	if err != nil || len(key) == 0 {
		t.Fatalf("key %q: want bytes in hexadecimal (%v)", file.Key, err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			text := []byte(c.ArgumentsText)
			if (c.Arguments == nil) == (c.ArgumentsText == "") {
				t.Fatal("the case gives its arguments both as a value and as text, or neither way")
			}
			if c.Arguments != nil {
				text = c.Arguments
			}
			want := c.hashedArguments
			want.Names, want.NamesSHA256 = set(want.Names), set(want.NamesSHA256)
			if got := hashArguments(t, key, text); !reflect.DeepEqual(got, want) {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

// definition is a definition hash as tooling.json gives it.
type definition struct {
	CanonicalJSON string `json:"canonical_json"`
	SHA256        string `json:"sha256"`
}

// toolingFile is tooling.json: definition hashes, URLs and references.
type toolingFile struct {
	Description string `json:"description"`
	Definitions []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Kind        string `json:"kind"`
		// An MCP tool's: the JSON-RPC message, as a JSON value or as text.
		Message     json.RawMessage `json:"message"`
		MessageText string          `json:"message_text"`
		// A function's: its name, and the JSON Schema of its parameters as
		// a JSON value or as text, or neither.
		Name            string          `json:"name"`
		InputSchema     json.RawMessage `json:"input_schema"`
		InputSchemaText *string         `json:"input_schema_text"`
		// Each tool's definition, nil for a tool without a hash; nil as a
		// whole when the message leaves every tool without one.
		Definitions *[]*definition `json:"definitions"`
	} `json:"definitions"`
	URLs []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		URL         string `json:"url"`
		// The host that url_host reads, and the URL normalized; nil when
		// url_host cannot read it, or when it makes no reference.
		Host       *string `json:"host"`
		Normalized *string `json:"normalized"`
	} `json:"urls"`
	References []struct {
		ID          string         `json:"id"`
		Description string         `json:"description"`
		Entry       referenceEntry `json:"entry"`
		Rules       tooling.Rules  `json:"rules"`
		// nil for an entry that makes no reference.
		Reference       *string `json:"reference"`
		ReferenceSHA256 *string `json:"reference_sha256"`
	} `json:"references"`
}

// referenceEntry is an MCP server, a tool or a model, as tooling.json gives
// it.
type referenceEntry struct {
	Kind        string          `json:"kind"`
	URL         string          `json:"url"`
	Provider    string          `json:"provider"`
	ConnectorID string          `json:"connector_id"`
	Command     []string        `json:"command"`
	Server      *referenceEntry `json:"server"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Endpoint    string          `json:"endpoint"`
}

// toolingDefinition returns a reference implementation's definition as
// tooling.json gives it: nil for a definition without a hash.
func toolingDefinition(def *tooling.Definition) *definition {
	if def == nil {
		return nil
	}
	return &definition{CanonicalJSON: string(def.CanonicalJSON), SHA256: def.SHA256}
}

// TestDefinitionVectors computes the definition hashes of tooling.json
// (section 4.10): those of the tools of a tools/list response, and that of a
// function, an http or another tool.
func TestDefinitionVectors(t *testing.T) {
	var file toolingFile
	loadJSON(t, "vectors/tooling.json", &file)
	if len(file.Definitions) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Definitions {
		t.Run(c.ID, func(t *testing.T) {
			var got *[]*definition
			switch c.Kind {
			case "mcp":
				message := c.Message
				if message == nil {
					message = []byte(c.MessageText)
				}
				defs, err := tooling.MCPDefinitions(message)
				if err != nil && !errors.Is(err, canonical.ErrNoCanonicalJSON) {
					t.Fatal(err)
				}
				if err == nil {
					list := []*definition{}
					for _, def := range defs {
						list = append(list, toolingDefinition(def))
					}
					got = &list
				}
			case "function":
				schema := []byte(c.InputSchema)
				if c.InputSchemaText != nil {
					schema = []byte(*c.InputSchemaText)
				}
				def, err := tooling.FunctionDefinition(c.Name, schema)
				if err != nil && !errors.Is(err, canonical.ErrNoCanonicalJSON) {
					t.Fatal(err)
				}
				got = &[]*definition{toolingDefinition(def)}
			default:
				t.Fatalf("unknown kind %q", c.Kind)
			}
			if !reflect.DeepEqual(got, c.Definitions) {
				t.Errorf("got %s, want %s", show(got), show(c.Definitions))
			}
		})
	}
}

// TestURLVectors reads the URLs of tooling.json as url_host does (section
// 6.11), and normalizes them as section 4.10 says.
func TestURLVectors(t *testing.T) {
	var file toolingFile
	loadJSON(t, "vectors/tooling.json", &file)
	if len(file.URLs) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.URLs {
		t.Run(c.ID, func(t *testing.T) {
			var host, normalized *string
			u, err := tooling.ReadURL(c.URL)
			switch {
			case errors.Is(err, tooling.ErrCannotRead):
			case err != nil:
				t.Fatal(err)
			default:
				host = &u.Host
				n, err := u.Normalized()
				if err != nil && !errors.Is(err, tooling.ErrNoReference) {
					t.Fatal(err)
				}
				if err == nil {
					normalized = &n
				}
			}
			if !reflect.DeepEqual(host, c.Host) || !reflect.DeepEqual(normalized, c.Normalized) {
				t.Errorf("got host %s, normalized %s; want %s, %s", show(host), show(normalized), show(c.Host), show(c.Normalized))
			}
		})
	}
}

// reference computes an entry's reference with the reference implementation,
// as its string form.
func reference(t *testing.T, e referenceEntry, rules tooling.Rules) (string, error) {
	t.Helper()
	switch e.Kind {
	case "remote_server":
		return tooling.NormalizedURL(e.URL, rules)
	case "connector":
		return tooling.ConnectorReference(e.Provider, e.ConnectorID), nil
	case "local_server":
		return tooling.LocalServerReference(e.Command, rules), nil
	case "mcp_tool":
		if e.Server == nil {
			t.Fatal("an MCP tool without its server")
		}
		server, err := reference(t, *e.Server, rules)
		if err != nil {
			return "", err
		}
		return tooling.MCPToolReference(server, e.Name), nil
	case "tool":
		return tooling.ToolReference(e.Name), nil
	case "builtin_tool":
		return tooling.BuiltinToolReference(e.Provider, e.Type), nil
	case "model":
		return tooling.ModelReference(e.Provider, e.Endpoint, e.Name, rules)
	}
	t.Fatalf("unknown kind %q", e.Kind)
	return "", nil
}

// TestReferenceVectors computes the references of tooling.json, as their
// string forms and the SHA-256 that blocks and events name them by, after the
// redaction of EP-14 with the deployment's rules (section 4.10).
func TestReferenceVectors(t *testing.T) {
	var file toolingFile
	loadJSON(t, "vectors/tooling.json", &file)
	if len(file.References) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.References {
		t.Run(c.ID, func(t *testing.T) {
			var ref, sum *string
			got, err := reference(t, c.Entry, c.Rules)
			if err != nil && !errors.Is(err, tooling.ErrNoReference) {
				t.Fatal(err)
			}
			if err == nil {
				digest := sha256.Sum256([]byte(got))
				hexDigest := hex.EncodeToString(digest[:])
				ref, sum = &got, &hexDigest
			}
			if !reflect.DeepEqual(ref, c.Reference) || !reflect.DeepEqual(sum, c.ReferenceSHA256) {
				t.Errorf("got %s (%s), want %s (%s)", show(ref), show(sum), show(c.Reference), show(c.ReferenceSHA256))
			}
		})
	}
}

// show returns the JSON of a test's value, for its messages.
func show(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(data)
}
