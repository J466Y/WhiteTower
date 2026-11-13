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

// cedarValidator returns a validator for the profile's Cedar schema, with the
// ToolArgs that a bundle's schema declares when one is given (section 6.7).
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
	"another_tool":   profile.ErrAnotherTool,
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

// vectorCatalog is what the combination vectors read of their catalog file
// (section 7.7): what makes up a resource's properties, and the arguments
// that each tool declares.
type vectorCatalog struct {
	Servers []struct {
		Key       string `json:"key"`
		Transport string `json:"transport"`
	} `json:"servers"`
	Tools []struct {
		Key         string             `json:"key"`
		Server      string             `json:"server"`
		Provider    string             `json:"provider"`
		Name        string             `json:"name"`
		Kind        string             `json:"kind"`
		Origin      string             `json:"origin"`
		ReadOnly    bool               `json:"read_only"`
		Destructive bool               `json:"destructive"`
		OpenWorld   bool               `json:"open_world"`
		Args        []tooling.Argument `json:"args"`
	} `json:"tools"`
	Models []struct {
		Key      string `json:"key"`
		Provider string `json:"provider"`
		Endpoint string `json:"endpoint"`
		Name     string `json:"name"`
	} `json:"models"`
}

// toolArgs returns the ToolArgs that the core declares in a bundle's Cedar
// schema for the catalog (section 6.7): one optional record per tool that
// declares arguments, keyed by the tool's key, with each argument under its
// name and of its type.
func (c vectorCatalog) toolArgs() string {
	quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	var records []string
	for _, tool := range c.Tools {
		if len(tool.Args) == 0 {
			continue
		}
		attrs := make([]string, 0, len(tool.Args))
		for _, a := range tool.Args {
			attrs = append(attrs, `"`+quote.Replace(a.Name)+`"?: `+a.Type)
		}
		records = append(records, `"`+quote.Replace(tool.Key)+`"?: { `+strings.Join(attrs, ", ")+" }")
	}
	return "type ToolArgs = { " + strings.Join(records, ", ") + " };"
}

// entry returns the properties that the catalog gives a resource, and the
// types of the arguments that a tool declares, by their names (sections 6.3
// and 7.7).
func (c vectorCatalog) entry(r profile.Resource) (map[string]any, map[string]string, error) {
	for _, m := range c.Models {
		if r.Type == "model" && m.Key == r.ID {
			return map[string]any{"provider": m.Provider, "name": m.Name, "endpoint": m.Endpoint}, nil, nil
		}
	}
	for _, tool := range c.Tools {
		if r.Type != "tool" || tool.Key != r.ID {
			continue
		}
		properties := map[string]any{
			"kind": tool.Kind, "origin": tool.Origin, "name": tool.Name,
			"read_only": tool.ReadOnly, "destructive": tool.Destructive, "open_world": tool.OpenWorld,
		}
		switch tool.Kind {
		case "mcp":
			properties["server"] = tool.Server
			for _, s := range c.Servers {
				if s.Key == tool.Server {
					properties["transport"] = s.Transport
				}
			}
		case "builtin":
			properties["provider"] = tool.Provider
		}
		declared := map[string]string{}
		for _, a := range tool.Args {
			declared[a.Name] = a.Type
		}
		return properties, declared, nil
	}
	return nil, nil, fmt.Errorf("the catalog has no %s with the key %q", r.Type, r.ID)
}

// check checks that a request inside the profile takes its resource from the
// catalog: a tool or a model names an entry by its key, with the properties
// that the catalog gives it (section 6.3), and a tool call's record holds only
// arguments that the entry declares, each of its declared type (section
// 6.11).
func (c vectorCatalog) check(request json.RawMessage) error {
	req, err := profile.DecodeRequest(request)
	if err != nil {
		return err
	}
	if req.Resource.Type != "tool" && req.Resource.Type != "model" {
		return nil
	}
	properties, declared, err := c.entry(req.Resource)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(req.Resource.Properties, properties) {
		return fmt.Errorf("properties %s, the catalog's %s", show(req.Resource.Properties), show(properties))
	}
	record, _ := req.Context.Args[req.Resource.ID].(map[string]any)
	for name, v := range record {
		if typ, ok := declared[name]; !ok || !fits(v, typ) {
			return fmt.Errorf("the argument %q is not one that the tool declares, of its type", name)
		}
	}
	return nil
}

// fits reports whether a value of a record, as DecodeRequest decodes it, has
// the type that section 7.7 names.
func fits(v any, typ string) bool {
	if item, ok := strings.CutPrefix(typ, "Set<"); ok {
		item = strings.TrimSuffix(item, ">")
		items, isArray := v.([]any)
		return isArray && !slices.ContainsFunc(items, func(x any) bool { return !fits(x, item) })
	}
	switch x := v.(type) {
	case string:
		return typ == "String"
	case bool:
		return typ == "Bool"
	case json.Number:
		_, err := x.Int64()
		return typ == "Long" && err == nil
	}
	return false
}

// TestCombinationVectors runs the combination vectors against the reference
// implementation of the decision profile, on cedar-go.
func TestCombinationVectors(t *testing.T) {
	var file struct {
		Description string `json:"description"`
		Profile     string `json:"profile"`
		AgentID     string `json:"agent_id"`
		// The agent's catalog file, from which the requests take their
		// resources. It is read as text, and then for what the test needs.
		Catalog json.RawMessage `json:"catalog"`
		Cases   []struct {
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
	if err := validateJSON(compileSchema(t, "../../api/policy/catalog.schema.json"), file.Catalog); err != nil {
		t.Fatalf("the catalog does not match its schema: %v", err)
	}
	var catalog vectorCatalog
	if err := json.Unmarshal(file.Catalog, &catalog); err != nil {
		t.Fatal(err)
	}
	validator := cedarValidator(t, catalog.toolArgs())
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
			// first (section 6.6). Every other request matches the schema,
			// and takes its resource from the catalog.
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
				if err := catalog.check(c.Request); err != nil {
					t.Errorf("the request does not take its resource from the catalog: %v", err)
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

// argumentsFile is arguments.json: the transforms, and tools' records of
// context.args.
type argumentsFile struct {
	Description string `json:"description"`
	Transforms  []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Transform   string `json:"transform"`
		Value       string `json:"value"`
		// nil when the transform cannot read the value.
		Result *string `json:"result"`
	} `json:"transforms"`
	Records []struct {
		ID          string             `json:"id"`
		Description string             `json:"description"`
		Args        []tooling.Argument `json:"args"`
		// The call's arguments as a JSON value or, where a parsed value
		// cannot hold them, as their text; neither when the call has none.
		Arguments     json.RawMessage `json:"arguments"`
		ArgumentsText *string         `json:"arguments_text"`
		// nil when EP-19 denies the call; sets as their distinct elements
		// in ascending order.
		Record map[string]any `json:"record"`
	} `json:"records"`
}

// TestTransformVectors applies the transforms of arguments.json (section
// 6.11).
func TestTransformVectors(t *testing.T) {
	var file argumentsFile
	loadJSON(t, "vectors/arguments.json", &file)
	if len(file.Transforms) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Transforms {
		t.Run(c.ID, func(t *testing.T) {
			var result *string
			got, err := tooling.Transform(c.Transform, c.Value)
			switch {
			case errors.Is(err, tooling.ErrCannotRead):
			case err != nil:
				t.Fatal(err)
			default:
				result = &got
			}
			if !reflect.DeepEqual(result, c.Result) {
				t.Errorf("got %s, want %s", show(result), show(c.Result))
			}
		})
	}
}

// TestTheTransformVectorsTakeTheValuesOfTheCheck checks that arguments.json
// has a case for each value of the URL and address check, under its ID: each
// URL as url_host reads it, each address as email_domain does, and each host
// of its IDNA, in its order, as email_domain reads alice@ and the host.
func TestTheTransformVectorsTakeTheValuesOfTheCheck(t *testing.T) {
	data, err := os.ReadFile("vectors/inputs/url-and-address-check.json")
	if err != nil {
		t.Fatal(err)
	}
	type value struct{ ID, Value string }
	var check struct {
		URLHost     []value `json:"url_host"`
		EmailDomain []value `json:"email_domain"`
		IDNA        []struct{ Host string }
	}
	if err := json.Unmarshal(data, &check); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{}
	for _, v := range check.URLHost {
		want[v.ID] = [2]string{"url_host", v.Value}
	}
	for _, v := range check.EmailDomain {
		want[v.ID] = [2]string{"email_domain", v.Value}
	}
	for i, v := range check.IDNA {
		want[fmt.Sprintf("I%02d", i+1)] = [2]string{"email_domain", "alice@" + v.Host}
	}
	if len(want) != 80+33+14 {
		t.Fatalf("the check has %d values, want 127", len(want))
	}
	var file argumentsFile
	loadJSON(t, "vectors/arguments.json", &file)
	for _, c := range file.Transforms {
		if w, ok := want[c.ID]; ok {
			if got := [2]string{c.Transform, c.Value}; got != w {
				t.Errorf("%s: %s of %q, want %s of %q", c.ID, got[0], got[1], w[0], w[1])
			}
			delete(want, c.ID)
		}
	}
	for id := range want {
		t.Errorf("no case takes the check's %s", id)
	}
}

// TestRecordVectors fills the records of arguments.json from each call's
// arguments, as EP-19 says (section 6.11).
func TestRecordVectors(t *testing.T) {
	var file argumentsFile
	loadJSON(t, "vectors/arguments.json", &file)
	if len(file.Records) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Records {
		t.Run(c.ID, func(t *testing.T) {
			arguments := []byte(c.Arguments)
			switch {
			case c.Arguments != nil && c.ArgumentsText != nil:
				t.Fatal("the case gives its arguments both as a value and as text")
			case c.ArgumentsText != nil:
				arguments = []byte(*c.ArgumentsText)
			}
			got, err := tooling.Record(arguments, c.Args)
			if err != nil && !errors.Is(err, tooling.ErrInvalidArgument) {
				t.Fatal(err)
			}
			// Through JSON, an int64 and the vector's number compare as the
			// same text.
			if show(got) != show(c.Record) {
				t.Errorf("got %s (%v), want %s", show(got), err, show(c.Record))
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
