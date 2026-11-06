package tlsclient

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// get makes a request to url through a client with the TLS configuration of
// caFile.
func get(t *testing.T, caFile, url string) error {
	t.Helper()
	cfg, err := Config(caFile)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

func TestAClientTrustsTheAuthoritiesOfItsCAFileOnly(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := get(t, caFile, srv.URL); err != nil {
		t.Errorf("with the CA file: %v", err)
	}
	// The request passes with the system's authorities in the pool too, since
	// the test server's certificate chains to none of them: only the pool shows
	// that the file's are the only ones.
	cfg, err := Config(caFile)
	if err != nil {
		t.Fatal(err)
	}
	fileOnly := x509.NewCertPool()
	fileOnly.AppendCertsFromPEM(caPEM)
	if !cfg.RootCAs.Equal(fileOnly) {
		t.Error("with the CA file, the client trusts other authorities than the file's")
	}
	// The system does not know the test server's authority.
	if err := get(t, "", srv.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("without the CA file: %v, want a certificate error", err)
	}
	if cfg, err := Config(""); err != nil || cfg.RootCAs != nil || cfg.MinVersion == 0 {
		t.Errorf("without a CA file: %+v, %v; want the system's authorities, and a minimum version", cfg, err)
	}
}

func TestACAFileThatCannotBeUsedIsRefused(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("no certificate here"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a file without certificates": notPEM,
		"a file that does not exist":  filepath.Join(t.TempDir(), "missing.pem"),
	} {
		if _, err := Config(path); err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: %v, want an error that names it", name, err)
		}
	}
}
