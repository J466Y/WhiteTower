// Package servertls provides the certificates of the core's HTTPS
// listeners: read from files and reloaded when the files change, so that
// certificates rotate without a restart, or generated at startup for
// development.
package servertls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CheckInterval is how often a Reloader looks at its files, at most. It
// looks during TLS handshakes, never on a timer.
const CheckInterval = 5 * time.Second

// Reloader serves a certificate read from files, and reloads it when the
// files change. A new pair that fails to load is logged, and the previous
// certificate stays in use.
type Reloader struct {
	certFile, keyFile string
	interval          time.Duration
	logger            *slog.Logger
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   stamp
	checked time.Time
}

// stamp identifies a version of the certificate and key files.
type stamp struct {
	certMod, keyMod   time.Time
	certSize, keySize int64
}

// NewReloader loads the certificate and key files; it fails when they do
// not form a valid pair.
func NewReloader(certFile, keyFile string, logger *slog.Logger) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile, interval: CheckInterval, logger: logger, now: time.Now}
	st, err := r.stat()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading %s and %s: %w", certFile, keyFile, err)
	}
	r.cert, r.stamp, r.checked = &cert, st, r.now()
	return r, nil
}

// GetCertificate is the tls.Config callback.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.checked) >= r.interval {
		r.checked = now
		r.reloadLocked()
	}
	return r.cert, nil
}

// reloadLocked loads the files again if they changed. Callers hold r.mu.
func (r *Reloader) reloadLocked() {
	st, err := r.stat()
	if err != nil {
		r.logger.Error("cannot read the TLS certificate files; keeping the current certificate", "error", err)
		return
	}
	if st == r.stamp {
		return
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// Probably half-written: the next handshake tries again.
		r.logger.Error("the new TLS certificate does not load; keeping the current one", "cert_file", r.certFile, "error", err)
		return
	}
	r.cert, r.stamp = &cert, st
	r.logger.Info("reloaded the TLS certificate", "cert_file", r.certFile)
}

func (r *Reloader) stat() (stamp, error) {
	cert, err := os.Stat(r.certFile)
	if err != nil {
		return stamp{}, err
	}
	key, err := os.Stat(r.keyFile)
	if err != nil {
		return stamp{}, err
	}
	return stamp{certMod: cert.ModTime(), keyMod: key.ModTime(), certSize: cert.Size(), keySize: key.Size()}, nil
}

// SelfSigned returns a certificate for localhost and the given hosts, with a
// new ECDSA P-256 key, valid for 30 days. It is for development only.
func SelfSigned(hosts ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "White Tower development certificate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range append([]string{"localhost", "127.0.0.1", "::1"}, hosts...) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Config returns the TLS configuration of an HTTPS listener: the minimum
// version, and certificates from getCertificate. The HTTP server adds the
// ALPN protocols it serves.
func Config(minVersion uint16, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*tls.Config, error) {
	if minVersion < tls.VersionTLS12 {
		return nil, errors.New("TLS versions older than 1.2 are not allowed")
	}
	return &tls.Config{MinVersion: minVersion, GetCertificate: getCertificate}, nil
}
