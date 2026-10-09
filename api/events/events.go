// Package events embeds the event catalog of the module contracts, against
// which the core checks every event it records (contracts, section 8).
package events

import "embed"

// Files holds catalog.json, cloudevent.schema.json and the schemas of the
// types' data, by their paths in this directory.
//
//go:embed catalog.json cloudevent.schema.json schemas/*.json
var Files embed.FS
