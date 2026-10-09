// Package security checks the security test catalog against the code. Each
// automated test of the catalog names its entry in the comment above it, as
// "Security test ST-05": so that the catalog's promise holds, that a
// finished plan's tests run in CI from then on, every automated entry of a
// finished plan must have one, and every name must be an entry.
package security

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	root    = "../.."
	catalog = root + "/docs/security/security-tests.md"
	plans   = root + "/docs/plans/README.md"
)

// automated are the kinds of catalog entries that a test implements; scans,
// reviews and exercises are not code.
var automated = []string{"unit", "integration", "e2e", "fuzz"}

var (
	planRow    = regexp.MustCompile(`^\| \[(P\d-\d+)\]\([^)]*\) \|.*\| ([^|]+?) \|$`)
	planTitle  = regexp.MustCompile(`^## (P\d-\d+): `)
	catalogRow = regexp.MustCompile(`^\| (ST-\d+) \|.*\| ([a-z0-9-]+) \|$`)
	entryID    = regexp.MustCompile(`ST-\d+`)
)

// lines returns the lines of a file.
func lines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	for s := bufio.NewScanner(f); s.Scan(); {
		out = append(out, strings.TrimRight(s.Text(), "\r"))
	}
	return out
}

// finished returns the plans that the plans index marks done.
func finished(t *testing.T) map[string]bool {
	t.Helper()
	done := map[string]bool{}
	for _, line := range lines(t, plans) {
		if m := planRow.FindStringSubmatch(line); m != nil && strings.HasPrefix(m[2], "Done") {
			done[m[1]] = true
		}
	}
	return done
}

// entry is an entry of the catalog.
type entry struct{ plan, kind string }

func entries(t *testing.T) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	plan := ""
	for _, line := range lines(t, catalog) {
		if m := planTitle.FindStringSubmatch(line); m != nil {
			plan = m[1]
		}
		if m := catalogRow.FindStringSubmatch(line); m != nil {
			out[m[1]] = entry{plan: plan, kind: m[2]}
		}
	}
	if len(out) == 0 {
		t.Fatal("no entry found in the catalog")
	}
	return out
}

// tests returns the files of tests that name each entry: Go tests, the
// console's and the Python enforcement point's.
func tests(t *testing.T) map[string][]string {
	t.Helper()
	named := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && slices.Contains([]string{".git", "node_modules", "docs", "dist"}, d.Name()):
			return filepath.SkipDir
		case d.IsDir():
			return nil
		}
		if !isTest(d.Name()) {
			return nil
		}
		for _, line := range lines(t, path) {
			if strings.Contains(line, "Security test") {
				for _, id := range entryID.FindAllString(line, -1) {
					named[id] = append(named[id], filepath.ToSlash(path))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return named
}

// isTest reports whether a file holds tests.
func isTest(name string) bool {
	switch {
	case strings.HasSuffix(name, "_test.go"), strings.HasSuffix(name, ".spec.ts"),
		strings.HasSuffix(name, ".test.ts"), strings.HasSuffix(name, ".test.tsx"):
		return true
	default:
		return strings.HasPrefix(name, "test_") && strings.HasSuffix(name, ".py")
	}
}

func TestFinishedPlansRunTheirSecurityTests(t *testing.T) {
	done, all, named := finished(t), entries(t), tests(t)
	for id, e := range all {
		if done[e.plan] && slices.Contains(automated, e.kind) && len(named[id]) == 0 {
			t.Errorf("%s, an %s test of %s, which is done, has no test whose comment says \"Security test %s\"",
				id, e.kind, e.plan, id)
		}
	}
	for id, files := range named {
		if _, ok := all[id]; !ok {
			t.Errorf("%v name %s, which the catalog does not hold", files, id)
		}
	}
}
