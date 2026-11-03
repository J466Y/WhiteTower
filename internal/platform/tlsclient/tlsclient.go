// Package tlsclient makes the TLS configuration of the core's clients of
// other services, such as an OTLP receiver or the identity provider, from the
// certificate authorities that a setting ending in ca_file names.
package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Config returns the TLS configuration of a client: TLS 1.2 at least, and the
// certificate authorities of caFile, a PEM file, as the only ones it trusts.
// With no caFile, the client trusts the system's.
func Config(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile) //nolint:gosec // G304: the operator chooses the file
	if err != nil {
		return nil, err
	}
	cfg.RootCAs = x509.NewCertPool()
	if !cfg.RootCAs.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificate in %s", caFile)
	}
	return cfg, nil
}
