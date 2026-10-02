package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/J466Y/WhiteTower/api/openapi"
)

// document is the OpenAPI document as JSON, with its entity tag.
var document = sync.OnceValues(func() ([]byte, string) {
	var doc any
	if err := yaml.Unmarshal(openapi.Document, &doc); err != nil {
		panic("rest: the embedded OpenAPI document: " + err.Error())
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic("rest: the embedded OpenAPI document: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return b, `"` + hex.EncodeToString(sum[:16]) + `"`
})

// documentHandler serves the OpenAPI document, which clients may cache and
// revalidate.
func documentHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, etag := document()
		h := w.Header()
		h.Set("ETag", etag)
		h.Set("Cache-Control", "no-cache")
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		h.Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

var httpMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true, "head": true, "options": true}

// operation is an operation of the document.
type operation struct {
	// ID is the operationId, as the document and the Authorizer name it.
	ID string
	// Method and Path, relative to BasePath, locate it.
	Method, Path string
	// Public is true when the document declares the operation with
	// `security: []`: only then may an anonymous caller call it.
	Public bool
}

// operationKey makes the document's operationId and the generated code's
// name for it comparable: "getVersion" and "GetVersion" give "getversion".
func operationKey(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			return -1
		}
		return unicode.ToLower(r)
	}, name)
}

// operations returns the operations of the document, by operationKey.
var operations = sync.OnceValue(func() map[string]operation {
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapi.Document, &doc); err != nil {
		panic("rest: the embedded OpenAPI document: " + err.Error())
	}
	ops := map[string]operation{}
	for path, item := range doc.Paths {
		for method, node := range item {
			if !httpMethods[method] {
				continue
			}
			var op struct {
				OperationID string                 `yaml:"operationId"`
				Security    *[]map[string][]string `yaml:"security"`
			}
			if err := node.Decode(&op); err != nil {
				panic("rest: the embedded OpenAPI document: " + err.Error())
			}
			ops[operationKey(op.OperationID)] = operation{
				ID:     op.OperationID,
				Method: strings.ToUpper(method),
				Path:   path,
				Public: op.Security != nil && len(*op.Security) == 0,
			}
		}
	}
	return ops
})
