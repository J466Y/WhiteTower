package auditverify_test

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/J466Y/WhiteTower/pkg/auditverify"
)

func TestOpenCheckpoint(t *testing.T) {
	s := newSigner(t)
	root := tlog.RecordHash([]byte("root"))
	signed := s.sign(t, checkpointText(origin, 42, root))
	cp, err := auditverify.OpenCheckpoint(signed, s.keys(t))
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin != origin || cp.Size != 42 || cp.Root != root || !bytes.Equal(cp.Note, signed) {
		t.Fatalf("%+v", cp)
	}
	// Extension lines carry nothing that verification needs.
	if _, err := auditverify.OpenCheckpoint(s.sign(t, checkpointText(origin, 42, root)+"an extension\n"), s.keys(t)); err != nil {
		t.Fatalf("with an extension line: %v", err)
	}
}

func TestOpenCheckpointRefuses(t *testing.T) {
	s := newSigner(t)
	root := tlog.RecordHash([]byte("root"))
	text := checkpointText(origin, 42, root)
	encoded := strings.Split(text, "\n")[2]
	for name, signed := range map[string][]byte{
		"another key":       newSigner(t).sign(t, text),
		"another log":       s.sign(t, checkpointText("whitetower.test/other", 42, root)),
		"a changed size":    bytes.Replace(s.sign(t, text), []byte("\n42\n"), []byte("\n43\n"), 1),
		"no root":           s.sign(t, origin+"\n42\n"),
		"no origin":         s.sign(t, "\n42\n"+encoded+"\n"),
		"a leading zero":    s.sign(t, origin+"\n042\n"+encoded+"\n"),
		"a sign":            s.sign(t, origin+"\n+42\n"+encoded+"\n"),
		"a negative size":   s.sign(t, origin+"\n-42\n"+encoded+"\n"),
		"a size too large":  s.sign(t, origin+"\n9223372036854775808\n"+encoded+"\n"),
		"a short root":      s.sign(t, origin+"\n42\nAAAA\n"),
		"a root not base64": s.sign(t, origin+"\n42\n"+strings.ReplaceAll(encoded, "=", "!")+"\n"),
		"not a note":        []byte(text),
		"empty":             nil,
	} {
		if cp, err := auditverify.OpenCheckpoint(signed, s.keys(t)); err == nil {
			t.Errorf("%s: opened %+v", name, cp)
		}
	}
	if _, err := auditverify.OpenCheckpoint(s.sign(t, text), nil); err == nil {
		t.Error("opened without keys")
	}
}

// Checkpoints come from outside: whatever their bytes, opening one fails or
// gives what was signed, and never panics.
func FuzzOpenCheckpoint(f *testing.F) {
	s := newSigner(f)
	keys := s.keys(f)
	f.Add(s.sign(f, checkpointText(origin, 42, tlog.RecordHash([]byte("root")))))
	f.Add(s.sign(f, origin+"\n0\n"+strings.Repeat("A", 43)+"=\nextension\n"))
	f.Fuzz(func(t *testing.T, signed []byte) {
		cp, err := auditverify.OpenCheckpoint(signed, keys)
		if err == nil && (cp.Size < 0 || cp.Origin != origin || !bytes.Equal(cp.Note, signed)) {
			t.Fatalf("opened %+v", cp)
		}
	})
}
