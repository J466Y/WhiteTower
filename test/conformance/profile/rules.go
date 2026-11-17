package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/cedar-policy/cedar-go"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
	"github.com/J466Y/WhiteTower/test/conformance/tooling"
)

// ErrUsageRule is the error of a usage rule that the generator refuses, and
// of a policy whose @rule statements are not exactly what the generator writes
// from their annotations (section 6.11).
var ErrUsageRule = errors.New("a usage rule that section 6.11 refuses")

// NamedRule is a usage rule that a policy.forbid decision names, by its
// policy's ID and its rule's ID (sections 6.11 and 8.5).
type NamedRule struct {
	PolicyID string `json:"policy_id"`
	RuleID   string `json:"rule_id"`
}

// ruleOperators are the operators that each argument type takes, since Cedar
// cannot test each element of a set against a pattern or a bound.
var ruleOperators = map[string][]string{
	"String":      {"equals", "not_equals", "in", "not_in", "matches", "not_matches"},
	"Long":        {"equals", "not_equals", "in", "not_in", "less_than", "greater_than"},
	"Bool":        {"equals", "not_equals"},
	"Set<String>": {"in", "not_in"},
	"Set<Long>":   {"in", "not_in"},
}

var (
	// ruleOperatorNames are the operators of section 6.11, and singleValue
	// those that take exactly one value.
	ruleOperatorNames = []string{"equals", "not_equals", "in", "not_in", "matches", "not_matches", "less_than", "greater_than"}
	singleValue       = []string{"equals", "not_equals", "less_than", "greater_than"}
	// ruleTransforms are the transforms of section 6.11.
	ruleTransforms = []string{"lowercase", "path", "url_host", "email_domain"}
)

// usageRule is a usage rule as the generator reads it. A rule read from a
// statement's annotation has the statement's tool alone.
type usageRule struct {
	ID, Description string
	Tools           []string
	When            []ruleCondition
}

// ruleCondition is a condition of a usage rule. Its values are as given:
// canonical.String, canonical.Number or bool.
type ruleCondition struct {
	Arg, Transform, Op string
	NoMatch            bool
	Values             []any
}

// refuse returns an error that wraps ErrUsageRule.
func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUsageRule, fmt.Sprintf(format, a...))
}

// GenerateRules writes the Cedar statements of a policy's usage rules, given
// as the JSON text of an array of rules, for a policy of the scope given,
// global or agent, with the arguments that the catalog declares (section
// 6.11): for each rule, and for each of its tools in their order, its
// tool.invoke statement, then its tool.expose statement, separated by an
// empty line. It returns an error that wraps ErrUsageRule for a rule that
// section 6.11 refuses.
func GenerateRules(rules []byte, c *tooling.Catalog, scope string) (string, error) {
	v, err := canonical.Parse(rules)
	if err != nil {
		return "", refuse("%v", err)
	}
	list, ok := v.([]any)
	if !ok {
		return "", refuse("not an array of rules")
	}
	var ids, statements []string
	for _, item := range list {
		r, err := readRule(item, false)
		if err != nil {
			return "", err
		}
		if slices.Contains(ids, r.ID) {
			return "", refuse("the id %q of another rule of the policy", r.ID)
		}
		ids = append(ids, r.ID)
		for _, tool := range r.Tools {
			pair, err := r.statements(tool, c, scope)
			if err != nil {
				return "", err
			}
			statements = append(statements, pair[:]...)
		}
	}
	return strings.Join(statements, "\n\n"), nil
}

// CheckRules checks a policy's text as the core does when a version is
// submitted (section 6.11). It regenerates each statement that carries @rule
// from its annotation, with the catalog's declarations and the policy's scope,
// and returns an error that wraps ErrUsageRule unless every such statement
// equals, once parsed, what the generator writes, and every rule is whole: the
// statements whose annotations carry one ID have the same description and
// conditions, and each of their tools has exactly its two statements, none
// missing and none repeated (the review of 2026-11-16). It returns another
// error for a text that does not parse.
func CheckRules(text string, c *tooling.Catalog, scope string) error {
	list, err := cedar.NewPolicyListFromBytes("", []byte(text))
	if err != nil {
		return err
	}
	type statements struct {
		// content is the annotation without its tool, the same for every
		// statement of the rule.
		content string
		// count is the number of tool.invoke and of tool.expose statements
		// of each tool.
		count map[string]*[2]int
	}
	rules := map[string]*statements{}
	for _, p := range list {
		annotation, ok := p.Annotations()["rule"]
		if !ok {
			continue
		}
		r, err := readAnnotation(string(annotation))
		if err != nil {
			return err
		}
		tool := r.Tools[0]
		pair, err := r.statements(tool, c, scope)
		if err != nil {
			return err
		}
		action, err := matching(p, pair)
		if err != nil {
			return err
		}
		content, err := r.annotation("")
		if err != nil {
			return err
		}
		s := rules[r.ID]
		if s == nil {
			s = &statements{content: content, count: map[string]*[2]int{}}
			rules[r.ID] = s
		}
		if s.content != content {
			return refuse("statements of the rule %q with another description or other conditions", r.ID)
		}
		if s.count[tool] == nil {
			s.count[tool] = &[2]int{}
		}
		s.count[tool][action]++
	}
	for id, s := range rules {
		for tool, count := range s.count {
			if *count != [2]int{1, 1} {
				return refuse("the rule %q has %d tool.invoke and %d tool.expose statements of %q, not one of each", id, count[0], count[1], tool)
			}
		}
	}
	return nil
}

// matching returns the index in pair of the generated statement that equals
// p once parsed, as cedar-go writes both in Cedar's JSON form.
func matching(p *cedar.Policy, pair [2]string) (int, error) {
	got, err := json.Marshal(p)
	if err != nil {
		return 0, err
	}
	for i, text := range pair {
		generated, err := cedar.NewPolicyListFromBytes("", []byte(text))
		if err != nil || len(generated) != 1 {
			return 0, fmt.Errorf("the generator wrote a statement that does not parse: %w", err)
		}
		want, err := json.Marshal(generated[0])
		if err != nil {
			return 0, err
		}
		if bytes.Equal(got, want) {
			return i, nil
		}
	}
	return 0, refuse("a statement that is not what the generator writes from its annotation")
}

// readAnnotation reads the rule of a statement's @rule annotation: the JSON of
// an object with exactly description, id, tool and when.
func readAnnotation(annotation string) (usageRule, error) {
	v, err := canonical.Parse([]byte(annotation))
	if err != nil {
		return usageRule{}, refuse("an annotation that is not JSON: %v", err)
	}
	return readRule(v, true)
}

// statementRule returns the ID of the rule that a statement's annotation reads
// as, or "": an annotation reads as a rule when it is the JSON of an object
// with exactly description, id, tool and when, each read as the generator
// reads it, without the catalog or the policy's scope (the review of
// 2026-11-16). The core's check keeps a bundle from holding a statement that
// does not match its annotation, so an enforcement point needs no generator.
func statementRule(p *cedar.Policy) string {
	annotation, ok := p.Annotations()["rule"]
	if !ok {
		return ""
	}
	r, err := readAnnotation(string(annotation))
	if err != nil {
		return ""
	}
	return r.ID
}

// readRule reads a usage rule from a value that canonical.Parse returned: an
// object with the members that section 6.11 names, id, description, tools and
// when, or, for a rule read from an annotation, tool in place of tools. It
// refuses what the generator refuses without the catalog. The rule's JSON is
// I-JSON apart from the size of its integers, so that the rule has one text: no
// member name repeats, and no string holds a lone surrogate or a noncharacter
// (the review of 2026-11-16). No string holds a control character either,
// which section 6.11 refuses in the id, the description, values and patterns,
// and the review of 2026-11-16 in tool keys and argument names.
func readRule(v any, fromAnnotation bool) (usageRule, error) {
	if _, err := canonical.Encode(v); err != nil {
		return usageRule{}, refuse("%v", err)
	}
	if err := checkRuleStrings(v); err != nil {
		return usageRule{}, err
	}
	obj, ok := v.(canonical.Object)
	if !ok {
		return usageRule{}, refuse("a rule that is not an object")
	}
	tools := "tools"
	if fromAnnotation {
		tools = "tool"
	}
	var r usageRule
	for _, m := range obj {
		var err error
		switch name := m.Name.String(); name {
		case "id":
			r.ID, err = ruleString(m.Value)
		case "description":
			r.Description, err = ruleString(m.Value)
		case tools:
			r.Tools, err = ruleTools(m.Value, fromAnnotation)
		case "when":
			r.When, err = ruleConditions(m.Value)
		default:
			err = refuse("the member %q", name)
		}
		if err != nil {
			return usageRule{}, err
		}
	}
	switch n := utf8.RuneCountInString(r.ID); {
	case n < 1 || n > 128:
		return usageRule{}, refuse("an id of %d characters", n)
	case r.Description == "":
		return usageRule{}, refuse("no description")
	case len(r.Tools) == 0:
		return usageRule{}, refuse("no tools")
	case len(r.When) == 0:
		return usageRule{}, refuse("no conditions")
	}
	for i, tool := range r.Tools {
		if slices.Contains(r.Tools[:i], tool) {
			return usageRule{}, refuse("the tool %q twice", tool)
		}
	}
	return r, nil
}

// checkRuleStrings refuses a string, at any depth, member names included, that
// holds a control character or a noncharacter.
func checkRuleStrings(v any) error {
	switch v := v.(type) {
	case canonical.String:
		for _, r := range v.String() {
			if r < 0x20 || r == 0x7f || r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFE == 0xFFFE {
				return refuse("the character %U", r)
			}
		}
	case []any:
		for _, item := range v {
			if err := checkRuleStrings(item); err != nil {
				return err
			}
		}
	case canonical.Object:
		for _, m := range v {
			if err := checkRuleStrings(m.Name); err != nil {
				return err
			}
			if err := checkRuleStrings(m.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

// ruleString returns a string of a rule, which has no lone surrogate.
func ruleString(v any) (string, error) {
	s, ok := v.(canonical.String)
	if !ok {
		return "", refuse("a member that is not a string")
	}
	return s.String(), nil
}

// ruleTools returns a rule's tools, or the tool of an annotation.
func ruleTools(v any, fromAnnotation bool) ([]string, error) {
	if fromAnnotation {
		tool, err := ruleString(v)
		return []string{tool}, err
	}
	items, ok := v.([]any)
	if !ok {
		return nil, refuse("tools that are not an array")
	}
	tools := make([]string, len(items))
	for i, item := range items {
		var err error
		if tools[i], err = ruleString(item); err != nil {
			return nil, err
		}
	}
	return tools, nil
}

// ruleConditions returns a rule's conditions, each an object with arg, op and
// values, an optional transform and an optional if_absent. A value is a
// string, a boolean or a signed 64-bit integer written without a fraction or
// an exponent, the only values that an argument type takes, and the values of
// matches and not_matches are patterns, which are strings.
func ruleConditions(v any) ([]ruleCondition, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, refuse("conditions that are not an array")
	}
	conditions := make([]ruleCondition, len(items))
	for i, item := range items {
		obj, ok := item.(canonical.Object)
		if !ok {
			return nil, refuse("a condition that is not an object")
		}
		c := &conditions[i]
		hasArg, hasValues := false, false
		for _, m := range obj {
			var err error
			var s string
			switch name := m.Name.String(); name {
			case "arg":
				c.Arg, err = ruleString(m.Value)
				hasArg = true
			case "transform":
				if c.Transform, err = ruleString(m.Value); err == nil && !slices.Contains(ruleTransforms, c.Transform) {
					err = refuse("the transform %q", c.Transform)
				}
			case "op":
				if c.Op, err = ruleString(m.Value); err == nil && !slices.Contains(ruleOperatorNames, c.Op) {
					err = refuse("the operator %q", c.Op)
				}
			case "values":
				c.Values, ok = m.Value.([]any)
				hasValues = true
				if !ok {
					err = refuse("values that are not an array")
				}
			case "if_absent":
				if s, err = ruleString(m.Value); err == nil && s != "match" && s != "no_match" {
					err = refuse("if_absent %q", s)
				}
				c.NoMatch = s == "no_match"
			default:
				err = refuse("the member %q of a condition", name)
			}
			if err != nil {
				return nil, err
			}
		}
		switch {
		case !hasArg || c.Op == "" || !hasValues:
			return nil, refuse("a condition without its arg, op or values")
		case len(c.Values) == 0:
			return nil, refuse("a condition without values")
		case slices.Contains(singleValue, c.Op) && len(c.Values) != 1:
			return nil, refuse("%s with %d values", c.Op, len(c.Values))
		}
		for _, x := range c.Values {
			_, isString := x.(canonical.String)
			_, isBool := x.(bool)
			_, err := ruleLong(x)
			if !isString && (c.Op == "matches" || c.Op == "not_matches" || !isBool && err != nil) {
				return nil, refuse("a value that no argument type takes")
			}
		}
	}
	return conditions, nil
}

// ruleLong returns a value that is a signed 64-bit integer written without a
// fraction or an exponent.
func ruleLong(v any) (int64, error) {
	n, ok := v.(canonical.Number)
	if !ok {
		return 0, refuse("not a number")
	}
	// In base 10, ParseInt takes an optional sign and decimal digits only, and
	// refuses a value outside int64.
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return 0, refuse("%s is not a signed 64-bit integer written without a fraction or an exponent", n)
	}
	return i, nil
}

// statements writes a rule's two statements for one of its tools, its
// tool.invoke statement then its tool.expose statement, each condition
// compiled for the type that the catalog declares for the tool's argument.
func (r usageRule) statements(tool string, c *tooling.Catalog, scope string) ([2]string, error) {
	i := slices.IndexFunc(c.Tools, func(t tooling.CatalogTool) bool { return t.Key == tool })
	switch {
	case i < 0:
		return [2]string{}, refuse("the tool %q, which the catalog does not list", tool)
	case scope != "agent" && strings.HasPrefix(tool, "agent/"):
		return [2]string{}, refuse("the agent's own tool %q in a global policy", tool)
	}
	conditions := make([]string, len(r.When))
	for k, cond := range r.When {
		path := strings.Split(cond.Arg, ".")
		j := slices.IndexFunc(c.Tools[i].Args, func(a tooling.Argument) bool {
			return slices.Equal(a.Path, path) && a.Transform == cond.Transform
		})
		if j < 0 {
			return [2]string{}, refuse("the argument %q with the transform %q, which the catalog does not declare for %q", cond.Arg, cond.Transform, tool)
		}
		arg := c.Tools[i].Args[j]
		v := "context.args[" + cedarString(tool) + "][" + cedarString(arg.Name) + "]"
		test, err := cond.compile(v, arg.Type)
		if err != nil {
			return [2]string{}, err
		}
		otherwise := "true"
		if cond.NoMatch {
			otherwise = "false"
		}
		conditions[k] = "if context has args && context.args has " + cedarString(tool) +
			" && context.args[" + cedarString(tool) + "] has " + cedarString(arg.Name) +
			"\n  then " + test + "\n  else " + otherwise
		// Cedar reads if a then b else c && d as if a then b else (c && d).
		if len(r.When) > 1 {
			conditions[k] = "(" + conditions[k] + ")"
		}
	}
	annotation, err := r.annotation(tool)
	if err != nil {
		return [2]string{}, err
	}
	head := func(action string) string {
		return "@rule(" + cedarString(annotation) + ")\nforbid (\n  principal,\n  action == WhiteTower::Action::\"" + action +
			"\",\n  resource == WhiteTower::Tool::" + cedarString(tool) + "\n) "
	}
	return [2]string{
		head("tool.invoke") + "when {\n  " + strings.Join(conditions, " &&\n  ") + "\n};",
		head("tool.expose") + "unless {\n  context.calls_decided\n};",
	}, nil
}

// compile writes a condition's test of V, the argument's value, for its type:
// C in the table of section 6.11.
func (c ruleCondition) compile(v, typ string) (string, error) {
	if !slices.Contains(ruleOperators[typ], c.Op) {
		return "", refuse("an argument of type %s with the operator %s", typ, c.Op)
	}
	item, isSet := strings.CutPrefix(typ, "Set<")
	item = strings.TrimSuffix(item, ">")
	literals := make([]string, len(c.Values))
	for i, x := range c.Values {
		var err error
		if literals[i], err = cedarLiteral(x, item); err != nil {
			return "", err
		}
	}
	list := "[" + strings.Join(literals, ", ") + "]"
	switch c.Op {
	case "equals":
		return v + " == " + literals[0], nil
	case "not_equals":
		return v + " != " + literals[0], nil
	case "less_than":
		return v + " < " + literals[0], nil
	case "greater_than":
		return v + " > " + literals[0], nil
	case "in":
		if isSet {
			return v + ".containsAny(" + list + ")", nil
		}
		return list + ".contains(" + v + ")", nil
	case "not_in":
		if isSet {
			return "!" + list + ".containsAll(" + v + ")", nil
		}
		return "!" + list + ".contains(" + v + ")", nil
	}
	likes := make([]string, len(literals))
	for i, pattern := range literals {
		likes[i] = v + " like " + pattern
	}
	if c.Op == "not_matches" {
		return "!(" + strings.Join(likes, " || ") + ")", nil
	}
	return strings.Join(likes, " || "), nil
}

// cedarLiteral writes a value of the type given as a Cedar literal: a string
// or a pattern as cedarString writes it, an integer in decimal, a boolean as
// true or false.
func cedarLiteral(v any, typ string) (string, error) {
	switch x := v.(type) {
	case canonical.String:
		if typ == "String" {
			return cedarString(x.String()), nil
		}
	case canonical.Number:
		if i, err := ruleLong(x); err == nil && typ == "Long" {
			return strconv.FormatInt(i, 10), nil
		}
	case bool:
		if typ == "Bool" {
			return strconv.FormatBool(x), nil
		}
	}
	return "", refuse("a value that is not a %s", typ)
}

// cedarString writes a string as a Cedar string: its backslashes and quotes
// escaped by a backslash, every other character as itself. In a pattern, * is
// then the wildcard and a backslash matches itself.
func cedarString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// annotation returns a statement's @rule annotation, before it is written as
// a Cedar string: the canonical JSON of the rule's description and id, the
// statement's tool and the rule's conditions, each with arg, op and values,
// transform only when one applies, and if_absent only when it is no_match.
func (r usageRule) annotation(tool string) (string, error) {
	when := make([]any, len(r.When))
	for i, c := range r.When {
		cond := canonical.Object{member("arg", c.Arg), member("op", c.Op), {Name: text("values"), Value: c.Values}}
		if c.Transform != "" {
			cond = append(cond, member("transform", c.Transform))
		}
		if c.NoMatch {
			cond = append(cond, member("if_absent", "no_match"))
		}
		when[i] = cond
	}
	data, err := canonical.Encode(canonical.Object{
		member("description", r.Description), member("id", r.ID), member("tool", tool), {Name: text("when"), Value: when},
	})
	return string(data), err
}

// member returns an object's member whose value is a string.
func member(name, value string) canonical.Member {
	return canonical.Member{Name: text(name), Value: text(value)}
}

// text returns a Go string as a canonical.String.
func text(s string) canonical.String {
	return utf16.Encode([]rune(s))
}
