//go:build embedui

package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Embedded reports whether the console build is embedded in this binary.
const Embedded = true

func assets() fs.FS {
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("webui: " + err.Error())
	}
	return files
}
