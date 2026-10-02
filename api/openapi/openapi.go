// Package openapi embeds the OpenAPI document of the public API, which the
// server serves and from which it learns which operations are public.
package openapi

import _ "embed"

// Document is openapi.yaml, as the binary was built with it.
//
//go:embed openapi.yaml
var Document []byte
