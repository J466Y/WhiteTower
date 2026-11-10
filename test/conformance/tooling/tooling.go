// Package tooling computes what an enforcement point reports of an agent's
// tooling as section 4.10 of the module contracts
// (docs/contracts/module-contract-v0.1.md) says: the definition hashes of its
// tools, and the references of its servers, tools and models, with the URLs
// that url_host reads (section 6.11) and normalizes, after the redaction of
// EP-14. It is the reference that the vectors of tooling.json are checked
// with.
package tooling

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"

	"github.com/J466Y/WhiteTower/test/conformance/canonical"
)

// Definition is a tool's definition as section 4.10 hashes it.
type Definition struct {
	// CanonicalJSON is the canonical JSON of the members that the hash
	// covers, those that are null left out.
	CanonicalJSON []byte
	// SHA256 is the definition hash: the SHA-256 of CanonicalJSON, in
	// lowercase hexadecimal.
	SHA256 string
}

// mcpMembers are the members of an MCP tool that its definition hash covers.
var mcpMembers = []string{"name", "title", "description", "inputSchema", "outputSchema", "annotations"}

// MCPDefinitions returns the definition of each tool of a tools/list
// response, read from the JSON-RPC message itself, in the order of its
// result's tools. A tool's definition is nil when it has no hash: when the
// members that the hash covers hold, at any depth, a number with a fraction
// or an exponent that is not finite as a double, a member name that repeats
// or a string with a lone surrogate. What a tool carries beside them never
// takes its hash away. A member name that repeats in the message itself or in
// its result leaves every tool without a hash, since two readers could then
// read different lists of tools: MCPDefinitions returns an error that wraps
// canonical.ErrNoCanonicalJSON.
func MCPDefinitions(message []byte) ([]*Definition, error) {
	v, err := canonical.Parse(message)
	if err != nil {
		return nil, err
	}
	msg, ok := v.(canonical.Object)
	if !ok {
		return nil, errors.New("the message is not an object")
	}
	if msg.HasRepeatedName() {
		return nil, fmt.Errorf("%w: a member name repeats in the message", canonical.ErrNoCanonicalJSON)
	}
	result, ok := member(msg, "result").(canonical.Object)
	if !ok {
		return nil, errors.New("the message has no result object")
	}
	if result.HasRepeatedName() {
		return nil, fmt.Errorf("%w: a member name repeats in the result", canonical.ErrNoCanonicalJSON)
	}
	tools, ok := member(result, "tools").([]any)
	if !ok {
		return nil, errors.New("the result has no array of tools")
	}
	defs := make([]*Definition, len(tools))
	for i, t := range tools {
		tool, ok := t.(canonical.Object)
		if !ok {
			return nil, fmt.Errorf("tool %d is not an object", i)
		}
		covered := slices.DeleteFunc(slices.Clone(tool), func(m canonical.Member) bool {
			return !slices.Contains(mcpMembers, m.Name.String())
		})
		def, err := hash(covered)
		switch {
		case errors.Is(err, canonical.ErrNoCanonicalJSON):
		case err != nil:
			return nil, fmt.Errorf("tool %d: %w", i, err)
		default:
			defs[i] = def
		}
	}
	return defs, nil
}

// FunctionDefinition returns the definition of a function, http or other
// tool: its name and the JSON Schema of its parameters, as the framework
// presents them to the model, as the members name and inputSchema. The schema
// is JSON text, or nil when the framework presents none. A definition without
// a hash returns an error that wraps canonical.ErrNoCanonicalJSON.
func FunctionDefinition(name string, inputSchema []byte) (*Definition, error) {
	members := canonical.Object{{Name: text("name"), Value: text(name)}}
	if inputSchema != nil {
		schema, err := canonical.Parse(inputSchema)
		if err != nil {
			return nil, err
		}
		members = append(members, canonical.Member{Name: text("inputSchema"), Value: schema})
	}
	return hash(members)
}

// hash returns the definition of the members given, those that are null left
// out. A name that repeats among them leaves the definition without a hash,
// even when one of its values is null, as one that repeats deeper does.
func hash(members canonical.Object) (*Definition, error) {
	if members.HasRepeatedName() {
		return nil, fmt.Errorf("%w: a member name repeats", canonical.ErrNoCanonicalJSON)
	}
	members = slices.DeleteFunc(members, func(m canonical.Member) bool { return m.Value == nil })
	data, err := canonical.Encode(members)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return &Definition{CanonicalJSON: data, SHA256: hex.EncodeToString(sum[:])}, nil
}

// member returns the value of the member of obj named name, or nil. obj has
// no repeated names.
func member(obj canonical.Object, name string) any {
	for _, m := range obj {
		if m.Name.String() == name {
			return m.Value
		}
	}
	return nil
}

// text returns a Go string as a canonical.String.
func text(s string) canonical.String {
	return utf16.Encode([]rune(s))
}
