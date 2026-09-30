package servertls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a self-signed certificate for commonName and its key.
func writePair(t *testing.T, certFile, keyFile, commonName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	write(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// write replaces a file and moves its modification time forward, so a
// change is seen even on file systems with coarse timestamps.
func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Duration(len(data)) * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
}

func commonName(t *testing.T, r *Reloader) string {
	t.Helper()
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return cert.Leaf.Subject.CommonName
}

func TestReloaderPicksUpNewCertificates(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writePair(t, certFile, keyFile, "first")

	r, err := NewReloader(certFile, keyFile, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	r.now = func() time.Time { return clock }
	if got := commonName(t, r); got != "first" {
		t.Fatalf("serving %q, want first", got)
	}

	writePair(t, certFile, keyFile, "second")
	if got := commonName(t, r); got != "first" {
		t.Fatalf("serving %q before the check interval, want first", got)
	}
	clock = clock.Add(CheckInterval)
	if got := commonName(t, r); got != "second" {
		t.Fatalf("serving %q after the files changed, want second", got)
	}

	// A broken pair is ignored, and the last good certificate stays.
	write(t, certFile, []byte("not a certificate"))
	clock = clock.Add(CheckInterval)
	if got := commonName(t, r); got != "second" {
		t.Fatalf("serving %q after a broken update, want second", got)
	}
}

func TestNewReloaderRefusesAnInvalidPair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if _, err := NewReloader(certFile, keyFile, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("missing files: want an error")
	}
	write(t, certFile, []byte("garbage"))
	write(t, keyFile, []byte("garbage"))
	if _, err := NewReloader(certFile, keyFile, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("invalid files: want an error")
	}
}

func TestSelfSigned(t *testing.T) {
	cert, err := SelfSigned("whitetower")
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname("localhost"); err != nil {
		t.Error(err)
	}
	if err := cert.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Error(err)
	}
	if err := cert.Leaf.VerifyHostname("whitetower"); err != nil {
		t.Error(err)
	}
}

func TestConfigRefusesOldVersions(t *testing.T) {
	if _, err := Config(tls.VersionTLS11, nil); err == nil {
		t.Fatal("TLS 1.1: want an error")
	}
	cfg, err := Config(tls.VersionTLS12, nil)
	if err != nil || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("got %v, %v", cfg, err)
	}
}
