package golden

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// recorder is a testing.TB that keeps the failure of the assertion it runs.
type recorder struct {
	testing.TB
	failure string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) { r.failure = fmt.Sprintf(format, args...) }

func (r *recorder) Fatalf(format string, args ...any) {
	r.failure = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (r *recorder) Fatal(args ...any) {
	r.failure = fmt.Sprint(args...)
	runtime.Goexit()
}

// check runs Assert as a test would, and returns its failure, if any.
func check(path string, got []byte) string {
	r := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Assert(r, path, got)
	}()
	<-done
	return r.failure
}

func TestAssert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "page.golden")
	if err := os.WriteFile(path, []byte("one\r\ntwo\r\nthree\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if failure := check(path, []byte("one\ntwo\nthree\n")); failure != "" {
		t.Errorf("the same text, with CRLF in the file: %s", failure)
	}
	failure := check(path, []byte("one\ntwo\nfour\n"))
	for _, want := range []string{path, "- three", "+ four", "first difference at line 3", "-update"} {
		if !strings.Contains(failure, want) {
			t.Errorf("the failure lacks %q:\n%s", want, failure)
		}
	}
	if failure := check(filepath.Join(dir, "missing.golden"), nil); !strings.Contains(failure, "run the test with -update") {
		t.Errorf("a missing file: %q", failure)
	}
}

func TestUpdateWritesTheFile(t *testing.T) {
	*update = true
	t.Cleanup(func() { *update = false })
	path := filepath.Join(t.TempDir(), "new", "page.golden")
	if failure := check(path, []byte("fresh\n")); failure != "" {
		t.Fatal(failure)
	}
	*update = false
	if failure := check(path, []byte("fresh\n")); failure != "" {
		t.Fatalf("the written file does not match: %s", failure)
	}
}

func TestAssertJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value.json")
	if err := os.WriteFile(path, []byte("{\n  \"name\": \"Olivia\",\n  \"roles\": [\n    \"owner\"\n  ]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		AssertJSON(r, path, map[string]any{"name": "Olivia", "roles": []string{"owner"}})
	}()
	<-done
	if r.failure != "" {
		t.Fatal(r.failure)
	}
}
