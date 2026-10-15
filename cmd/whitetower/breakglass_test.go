package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/J466Y/WhiteTower/internal/authn"
)

func TestBreakglassInitCommand(t *testing.T) {
	tempDir := t.TempDir()
	hashFile := filepath.Join(tempDir, "breakglass.hash")

	var stdout, stderr bytes.Buffer
	code := run([]string{"breakglass", "init", "--out", hashFile}, devEnv, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %q", code, stderr.String())
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "EMERGENCY BREAK-GLASS CREDENTIAL INITIALIZED") {
		t.Errorf("expected header in output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "Credential: wt_bg_") {
		t.Errorf("expected credential in output, got:\n%s", outStr)
	}

	// Read generated hash file
	data, err := os.ReadFile(hashFile)
	if err != nil {
		t.Fatalf("reading generated hash file: %v", err)
	}
	hashStr := strings.TrimSpace(string(data))
	if !strings.HasPrefix(hashStr, "$wt$1$") {
		t.Errorf("expected hash to start with $wt$1$, got %q", hashStr)
	}

	// Extract credential from stdout
	var rawCred string
	for _, line := range strings.Split(outStr, "\n") {
		if strings.HasPrefix(line, "Credential: ") {
			rawCred = strings.TrimSpace(strings.TrimPrefix(line, "Credential: "))
			break
		}
	}
	if rawCred == "" {
		t.Fatal("could not extract credential from output")
	}

	// Verify extracted credential matches stored hash
	if !authn.VerifyCredential(hashStr, rawCred) {
		t.Errorf("authn.VerifyCredential failed with generated credential and hash")
	}
}

func TestBreakglassInitRequiresPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"breakglass", "init"}, devEnv, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "credential hash file path must be specified") {
		t.Errorf("expected path requirement error, got %q", stderr.String())
	}
}
