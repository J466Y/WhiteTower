// Package policy embeds the request schema of the decision profile, against
// which an enforcement point checks every request before it evaluates
// (contracts, section 6.6).
package policy

import "embed"

// Files holds decision-request.schema.json, by its path in this directory.
//
//go:embed decision-request.schema.json
var Files embed.FS
