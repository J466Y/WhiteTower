// Package golden compares what a test produces with a file that holds what
// it should be, and rewrites the file when the test runs with -update (plan
// P1-01, step 10). A test package that imports it gets the -update flag, and
// must not define its own.
package golden

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files with what the tests produce")

// Assert fails the test unless got equals the file at path. With -update, it
// writes got to the file instead, so that a reviewer sees the change in the
// diff. The file's line endings compare as LF, whatever the checkout made of
// them.
func Assert(t testing.TB, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: the test names its golden file
	if err != nil {
		t.Fatalf("%v: run the test with -update to create it", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from what the test produced; once the difference is right, run the test with -update:\n%s",
			path, difference(string(want), string(got)))
	}
}

// AssertJSON is Assert for v, written as indented JSON.
func AssertJSON(t testing.TB, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	Assert(t, path, append(b, '\n'))
}

// difference shows where want and got first differ, with the two lines
// before.
func difference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	i := 0
	for i < len(w) && i < len(g) && w[i] == g[i] {
		i++
	}
	var b strings.Builder
	for _, line := range w[max(i-2, 0):i] {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	for _, line := range w[i:min(i+3, len(w))] {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	for _, line := range g[i:min(i+3, len(g))] {
		fmt.Fprintf(&b, "+ %s\n", line)
	}
	fmt.Fprintf(&b, "(first difference at line %d; - is the file, + the test)", i+1)
	return b.String()
}
