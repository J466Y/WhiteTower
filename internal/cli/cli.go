// Package cli implements wtctl, the command-line client of White Tower.
package cli

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// options are the flags every command shares.
type options struct {
	insecureSkipTLSVerify bool
}

// NewRootCommand returns the wtctl command tree.
func NewRootCommand() *cobra.Command {
	opts := &options{}
	root := &cobra.Command{
		Use:           "wtctl",
		Short:         "Command-line client for the White Tower governance core",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&opts.insecureSkipTLSVerify, "insecure-skip-tls-verify", false,
		"do not verify the server's certificate; only for development servers with a self-signed certificate")
	root.AddCommand(newVersionCommand(opts))
	return root
}

// httpClient returns the client commands use to reach the server.
func (o *options) httpClient(cmd *cobra.Command) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if o.insecureSkipTLSVerify {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: not verifying the server's TLS certificate (--insecure-skip-tls-verify)")
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // G402: only when the user asks, for development servers
		}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}
