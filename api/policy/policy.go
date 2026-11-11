// Package policy embeds the request schema of the decision profile, against
// which an enforcement point checks every request before it evaluates
// (contracts, section 6.6), and the schema of the catalog file, against which
// it parses a bundle's catalog file (section 7.4, step V7).
package policy

import "embed"

// Files holds decision-request.schema.json and catalog.schema.json, by their
// paths in this directory.
//
//go:embed decision-request.schema.json catalog.schema.json
var Files embed.FS
