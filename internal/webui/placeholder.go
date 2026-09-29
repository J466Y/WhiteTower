//go:build !embedui

package webui

import (
	"embed"
	"io/fs"
)

//go:embed placeholder
var placeholder embed.FS

// Embedded reports whether the console build is embedded in this binary.
const Embedded = false

func assets() fs.FS {
	files, err := fs.Sub(placeholder, "placeholder")
	if err != nil {
		panic("webui: " + err.Error())
	}
	return files
}
