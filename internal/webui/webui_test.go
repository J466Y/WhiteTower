package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// Plan P1-01, step 9: deep links reach the console, hashed assets are cached
// for good, and index.html is revalidated, so a new release shows at once.
func TestHandler(t *testing.T) {
	h := newHandler(fstest.MapFS{
		"index.html":                  {Data: []byte("<title>White Tower</title>")},
		"assets/index-CYca2rJ0.js":    {Data: []byte("console.log(1)")},
		"assets/index-dNuNrSQe.css":   {Data: []byte("body{}")},
		"favicon.svg":                 {Data: []byte("<svg/>")},
		"assets/images/logo-1a2b.svg": {Data: []byte("<svg/>")},
	})
	for _, tt := range []struct {
		method, path string
		status       int
		cacheControl string
		bodyContains string
		checkAllow   bool
	}{
		{"GET", "/", 200, "no-cache", "<title>White Tower</title>", false},
		{"GET", "/index.html", 200, "no-cache", "<title>White Tower</title>", false},
		{"GET", "/agents/42", 200, "no-cache", "<title>White Tower</title>", false},
		{"GET", "/policies/7/versions/3", 200, "no-cache", "<title>White Tower</title>", false},
		{"HEAD", "/agents/42", 200, "no-cache", "", false},
		{"GET", "/assets/index-CYca2rJ0.js", 200, "public, max-age=31536000, immutable", "console.log", false},
		{"GET", "/assets/images/logo-1a2b.svg", 200, "public, max-age=31536000, immutable", "<svg/>", false},
		{"GET", "/favicon.svg", 200, "", "<svg/>", false},
		{"GET", "/assets/missing.js", 404, "", "", false},
		{"GET", "/missing.png", 404, "", "", false},
		{"POST", "/", 405, "", "", true},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d", rec.Code, tt.status)
			}
			if got := rec.Header().Get("Cache-Control"); got != tt.cacheControl {
				t.Errorf("Cache-Control %q, want %q", got, tt.cacheControl)
			}
			if !strings.Contains(rec.Body.String(), tt.bodyContains) {
				t.Errorf("body %q lacks %q", rec.Body.String(), tt.bodyContains)
			}
			if tt.checkAllow && rec.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("Allow %q", rec.Header().Get("Allow"))
			}
			if tt.status < 400 && rec.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
				t.Errorf("Content-Security-Policy %q", rec.Header().Get("Content-Security-Policy"))
			}
		})
	}
}

// The policy allows nothing from another origin (requirement NFR-14).
func TestContentSecurityPolicyAllowsNoOtherOrigin(t *testing.T) {
	for directive := range strings.SplitSeq(ContentSecurityPolicy, ";") {
		for _, source := range strings.Fields(directive)[1:] {
			switch source {
			case "'self'", "'none'", "data:":
			default:
				t.Errorf("%q allows %s", strings.TrimSpace(directive), source)
			}
		}
	}
	if !strings.Contains(ContentSecurityPolicy, "frame-ancestors 'none'") {
		t.Error("the console can be framed")
	}
}
