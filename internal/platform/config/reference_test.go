package config

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/J466Y/WhiteTower/internal/platform/golden"
)

const referencePath = "../../../docs/reference/configuration.md"

// TestReferenceIsCurrent keeps the configuration reference in step with the
// code: it renders the reference from the field comments of config.go, and
// fails when docs/reference/configuration.md differs. Run it with -update to
// rewrite the file.
func TestReferenceIsCurrent(t *testing.T) {
	docs, err := fieldComments("config.go")
	if err != nil {
		t.Fatal(err)
	}
	golden.Assert(t, referencePath, renderReference(docs))
}

// fieldComments returns the doc comment of every struct field declared in a
// source file, keyed by "Type.Field".
func fieldComments(file string) (map[string]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	docs := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				docs[spec.Name.Name+"."+name.Name] = strings.Join(strings.Fields(field.Doc.Text()), " ")
			}
		}
		return false
	})
	return docs, nil
}

func renderReference(docs map[string]string) []byte {
	var b bytes.Buffer
	b.WriteString(`# Configuration reference

The ` + "`whitetower`" + ` server reads a YAML file, named by ` + "`--config`" + ` or the ` + "`WT_CONFIG`" + ` variable, then environment variables, which take precedence. Every setting has one: ` + "`listeners.console.address`" + ` is ` + "`WT_LISTENERS_CONSOLE_ADDRESS`" + `. Unknown keys and invalid values stop the server at startup, with a message naming the setting.

Secrets are never values in the configuration: settings ending in ` + "`_file`" + ` name the files that hold them. ` + "`whitetower config print`" + ` shows the effective configuration.

This page is generated from ` + "`internal/platform/config/config.go`" + `; do not edit it by hand. After changing a setting, run ` + "`go test ./internal/platform/config -run TestReferenceIsCurrent -update`" + `.
`)
	defaults := Defaults()
	renderSection(&b, reflect.ValueOf(defaults), reflect.TypeFor[Config](), nil, docs)
	return b.Bytes()
}

// renderSection writes a heading and a table for every struct in the
// configuration, depth first.
func renderSection(b *bytes.Buffer, v reflect.Value, t reflect.Type, path []string, docs map[string]string) {
	var leaves, structs []int
	for i := range t.NumField() {
		if t.Field(i).Type.Kind() == reflect.Struct {
			structs = append(structs, i)
		} else {
			leaves = append(leaves, i)
		}
	}
	if len(leaves) > 0 {
		b.WriteString("\n| Key | Environment variable | Type | Default | Description |\n| --- | --- | --- | --- | --- |\n")
		for _, i := range leaves {
			f := t.Field(i)
			p := append(append([]string(nil), path...), yamlKey(f))
			fmt.Fprintf(b, "| `%s` | `%s` | %s | %s | %s |\n",
				strings.Join(p, "."), EnvPrefix+strings.ToUpper(strings.Join(p, "_")),
				typeName(f.Type), defaultText(v.Field(i)), docs[t.Name()+"."+f.Name])
		}
	}
	for _, i := range structs {
		f := t.Field(i)
		p := append(append([]string(nil), path...), yamlKey(f))
		fmt.Fprintf(b, "\n%s `%s`\n\n%s\n", strings.Repeat("#", min(len(p)+1, 4)), strings.Join(p, "."), docs[t.Name()+"."+f.Name])
		renderSection(b, v.Field(i), f.Type, p, docs)
	}
}

func yamlKey(f reflect.StructField) string { return strings.Split(f.Tag.Get("yaml"), ",")[0] }

func typeName(t reflect.Type) string {
	switch {
	case t == durationType:
		return "duration"
	case t.Kind() == reflect.Bool:
		return "boolean"
	case t.Kind() == reflect.Int || t.Kind() == reflect.Int64:
		return "integer"
	case t.Kind() == reflect.Float64:
		return "number"
	default:
		return "string"
	}
}

func defaultText(v reflect.Value) string {
	switch {
	case v.Type() == durationType:
		return "`" + time.Duration(v.Int()).String() + "`"
	case v.Kind() == reflect.Bool:
		return "`" + strconv.FormatBool(v.Bool()) + "`"
	case v.Kind() == reflect.String && v.String() == "":
		return "none"
	default:
		return "`" + fmt.Sprint(v.Interface()) + "`"
	}
}
