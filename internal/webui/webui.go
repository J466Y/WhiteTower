// Package webui serves the web console: the build output of web/, embedded in
// the binary when it is built with the embedui tag. Builds without the tag
// serve a placeholder page, so the Go code builds and tests without Node.js.
package webui

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// ContentSecurityPolicy applies to every console response. The console loads
// nothing from outside the deployment (requirement NFR-14).
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Handler serves the console. Paths without a file extension that match no
// file are client-side routes and receive index.html; missing assets are 404s.
func Handler() http.Handler {
	files := assets()
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		panic("webui: the console has no index.html: " + err.Error())
	}
	loaded := time.Now()
	fileServer := http.FileServerFS(files)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		header := w.Header()
		header.Set("Content-Security-Policy", ContentSecurityPolicy)
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if info, err := fs.Stat(files, name); err == nil && !info.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					// Vite puts a content hash in every asset name.
					header.Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
			if path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
		}
		header.Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "index.html", loaded, bytes.NewReader(index))
	})
}
