// Package manifest reads module manifests written in YAML as the core does
// (docs/contracts/module-contract-v0.1.md, sections 1, 3.1 and 3.2): under
// the YAML 1.2 Core schema, with the refusals of MAN-1, into the RFC 8785
// canonical JSON whose SHA-256 identifies the manifest. It is the reference
// that the manifest vectors are checked with; the core's own reader comes with
// plan P1-07. The manifest's schema is checked apart, against
// module-manifest.schema.json.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
	"go.yaml.in/yaml/v3"
)

// decimal is a plain decimal number as JSON writes it, without an exponent:
// the one form of number that MAN-1 accepts in an unquoted scalar.
var decimal = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)

// notAString matches the unquoted scalars that the YAML 1.2 Core schema or
// YAML 1.1's types (yaml.org/type) read as something other than a string:
// nulls, booleans, integers, floats, timestamps, and YAML 1.1's merge and
// value keys, so that a merge key is refused with them. A YAML 1.1 float has
// one decimal point, as PyYAML reads it: the type repository's expression
// would read the version 0.1.0 as a float.
var notAString = regexp.MustCompile(`^(?:` + strings.Join([]string{
	// Nulls and booleans, of both versions.
	`~|null|Null|NULL|`,
	`y|Y|yes|Yes|YES|n|N|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF`,
	// YAML 1.2 Core's integers and floats.
	`[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+`,
	`[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)`,
	// YAML 1.1's integers: binary, octal, decimal, hexadecimal and sexagesimal, with underscores.
	`[-+]?0b[01_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+`,
	// YAML 1.1's floats.
	`[-+]?(?:[0-9][0-9_]*)?\.[0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*`,
	// YAML 1.1's timestamps.
	`[0-9]{4}-[0-9]{2}-[0-9]{2}`,
	`[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?`,
	// YAML 1.1's merge and value keys.
	`<<|=`,
}, "|") + `)$`)

// maxInteger is 2^53 - 1, the largest magnitude of an integer in I-JSON
// (section 1).
var maxInteger = big.NewInt(1<<53 - 1)

// Read reads a manifest written in YAML and returns its canonical JSON. It
// refuses what MAN-1 refuses in YAML: anchors, aliases, tags, and an unquoted
// scalar that YAML 1.1 or YAML 1.2 would read as something other than a
// string, a merge key among them, unless it is true, false, null or a plain
// decimal number. It also refuses a manifest that is not I-JSON (RFC 7493): a
// duplicate key, a key that is not a string, a noncharacter, an integer
// beyond 2^53 - 1 or a number more precise than a double.
func Read(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("the manifest is not UTF-8")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the manifest has no document")
		}
		return nil, fmt.Errorf("the manifest is not YAML: %w", err)
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, errors.New("the manifest has more than one document")
	}
	r := reader{tags: tagPositions(string(data))}
	value, err := r.value(doc.Content[0])
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// position is where a node starts, as yaml.v3 reports it.
type position struct{ line, column int }

// reader turns a document's nodes into the values of its JSON.
type reader struct {
	// tags holds the positions of every '!' in the document.
	tags map[position]bool
}

func (r reader) value(n *yaml.Node) (any, error) {
	switch {
	case n.Anchor != "" || n.Kind == yaml.AliasNode:
		// An anchor comes before its aliases, so it is the one refused.
		return nil, fmt.Errorf("line %d: an anchor or an alias", n.Line)
	// yaml.v3's API marks a named tag with TaggedStyle. The non-specific tag
	// "!" shows only in the text, where the node starts.
	case n.Style&yaml.TaggedStyle != 0 || r.tags[position{n.Line, n.Column}]:
		return nil, fmt.Errorf("line %d: a tag", n.Line)
	}
	switch n.Kind {
	case yaml.MappingNode:
		members := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			key, err := r.value(k)
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("line %d: a key that is not a string", k.Line)
			}
			if _, dup := members[name]; dup {
				return nil, fmt.Errorf("line %d: the key %q twice", k.Line, name)
			}
			if members[name], err = r.value(v); err != nil {
				return nil, err
			}
		}
		return members, nil
	case yaml.SequenceNode:
		items := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			item, err := r.value(c)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	}
	var (
		v   any
		err error
	)
	if n.Style == 0 {
		v, err = plain(n.Value)
	} else {
		// Quoted and block scalars are strings.
		v, err = text(n.Value)
	}
	if err != nil {
		return nil, fmt.Errorf("line %d: %w", n.Line, err)
	}
	return v, nil
}

// plain reads an unquoted scalar.
func plain(s string) (any, error) {
	switch {
	case s == "true":
		return true, nil
	case s == "false":
		return false, nil
	case s == "null":
		return nil, nil
	case decimal.MatchString(s):
		return number(s)
	case notAString.MatchString(s):
		return nil, fmt.Errorf("%q is not a string in both YAML 1.1 and YAML 1.2: quote it", s)
	}
	return text(s)
}

// text checks that a string is I-JSON, which has no noncharacters. Valid
// UTF-8, which Read checks, has no surrogates.
func text(s string) (string, error) {
	for _, c := range s {
		if c >= 0xFDD0 && c <= 0xFDEF || c&0xFFFE == 0xFFFE {
			return "", fmt.Errorf("the noncharacter %U is not I-JSON", c)
		}
	}
	return s, nil
}

// number checks that a plain decimal number is I-JSON: an integer of a
// magnitude of at most 2^53 - 1, or a number that a double holds without
// rounding what it says. jcs.Transform then writes it as RFC 8785 does.
func number(s string) (json.Number, error) {
	exact, ok := new(big.Rat).SetString(s)
	if !ok {
		return "", fmt.Errorf("%s is not a number", s)
	}
	if exact.IsInt() {
		if exact.Num().CmpAbs(maxInteger) > 0 {
			return "", fmt.Errorf("%s is not I-JSON: an integer's magnitude is at most 2^53 - 1", s)
		}
		return json.Number(exact.Num().String()), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err == nil {
		read, ok := new(big.Rat).SetString(strconv.FormatFloat(f, 'g', -1, 64))
		if ok && read.Cmp(exact) == 0 {
			return json.Number(s), nil
		}
	}
	return "", fmt.Errorf("%s is not I-JSON: a double cannot hold it", s)
}

// tagPositions returns where the document has a '!', as yaml.v3 counts
// positions: after a byte order mark, lines and columns from 1, columns in
// characters, and the line breaks of YAML 1.1. A node that starts at one has
// a tag, since nothing else starts with '!'. yaml.v3 reports the non-specific
// tag "!" no other way.
func tagPositions(text string) map[position]bool {
	tags := map[position]bool{}
	p := position{1, 1}
	text = strings.TrimPrefix(text, "\uFEFF")
	for i, c := range text {
		switch c {
		case '\r':
			if !strings.HasPrefix(text[i+1:], "\n") {
				p = position{p.line + 1, 1}
			}
		case '\n', '\u0085', '\u2028', '\u2029':
			p = position{p.line + 1, 1}
		case '!':
			tags[p] = true
			p.column++
		default:
			p.column++
		}
	}
	return tags
}
