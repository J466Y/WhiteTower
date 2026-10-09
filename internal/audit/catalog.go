package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Catalog is the event catalog of the module contracts (contracts, section
// 8.5), compiled: the schema of the envelope and, for each type, the schema
// of its data, who emits it, whether it is about an agent, and how the audit
// log indexes it.
type Catalog struct {
	envelope *jsonschema.Schema
	types    map[string]eventType
}

// eventType is a type of the catalog.
type eventType struct {
	// subject is required, optional or none.
	subject  string
	emitters []string
	data     *jsonschema.Schema
	rule     rule
}

// schemaBase places the catalog's files at URLs, so that their relative
// references resolve. Nothing is fetched from it.
const schemaBase = "file:///whitetower/events/"

// LoadCatalog compiles the catalog in files, which hold api/events. Every
// type must have its schema and an indexing rule of this package.
func LoadCatalog(files fs.FS) (*Catalog, error) {
	raw, err := fs.ReadFile(files, "catalog.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Types []struct {
			Type     string   `json:"type"`
			Subject  string   `json:"subject"`
			Emitters []string `json:"emitters"`
			Schema   string   `json:"schema"`
		} `json:"types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("catalog.json: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	err = fs.WalkDir(files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || !isSchema(name, d) {
			return err
		}
		f, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		schema, err := jsonschema.UnmarshalJSON(bytes.NewReader(f))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return compiler.AddResource(schemaBase+name, schema)
	})
	if err != nil {
		return nil, err
	}

	c := &Catalog{types: map[string]eventType{}}
	if c.envelope, err = compiler.Compile(schemaBase + "cloudevent.schema.json"); err != nil {
		return nil, err
	}
	var errs []error
	inCatalog := map[string]bool{}
	for _, t := range doc.Types {
		inCatalog[t.Type] = true
		data, err := compiler.Compile(schemaBase + t.Schema)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Type, err))
			continue
		}
		r, ok := rules[t.Type]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: the audit log has no rule to index it (internal/audit, rules)", t.Type))
			continue
		}
		c.types[t.Type] = eventType{subject: t.Subject, emitters: t.Emitters, data: data, rule: r}
	}
	for name := range rules {
		if !inCatalog[name] {
			errs = append(errs, fmt.Errorf("%s: an indexing rule for a type the catalog does not hold", name))
		}
	}
	return c, errors.Join(errs...)
}

// isSchema reports whether a file of the catalog is a JSON Schema: the
// envelope's, or one in schemas/.
func isSchema(name string, d fs.DirEntry) bool {
	return !d.IsDir() && (strings.HasSuffix(name, ".schema.json") || path.Dir(name) == "schemas")
}

// check validates an event, decoded as jsonschema.UnmarshalJSON decodes it,
// against the envelope's schema, its type's and its type's subject rule, and
// returns its type.
func (c *Catalog) check(event map[string]any) (eventType, error) {
	if err := c.envelope.Validate(event); err != nil {
		return eventType{}, fmt.Errorf("invalid envelope: %w", err)
	}
	name, _ := event["type"].(string)
	t, ok := c.types[name]
	if !ok {
		return eventType{}, fmt.Errorf("%s: not a type of the event catalog", name)
	}
	if err := t.data.Validate(event["data"]); err != nil {
		return eventType{}, fmt.Errorf("%s: invalid data: %w", name, err)
	}
	_, hasSubject := event["subject"]
	switch {
	case t.subject == "required" && !hasSubject:
		return eventType{}, fmt.Errorf("%s: the subject, its agent, is required", name)
	case t.subject == "none" && hasSubject:
		return eventType{}, fmt.Errorf("%s: an event of this type has no subject", name)
	}
	return t, nil
}
