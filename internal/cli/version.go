package cli

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/J466Y/WhiteTower/internal/version"
	"github.com/J466Y/WhiteTower/pkg/apiclient"
)

func newVersionCommand(opts *options) *cobra.Command {
	var server string
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version of wtctl, and of a server with --server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := version.Get()
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "client: %s (commit %s)\n", v.Version, v.Commit); err != nil {
				return err
			}
			if server == "" {
				return nil
			}

			base, err := url.Parse(server)
			if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
				return fmt.Errorf("invalid --server %q: want a URL such as https://localhost:8443", server)
			}
			client, err := apiclient.NewClientWithResponses(
				strings.TrimRight(server, "/")+"/api/v1",
				apiclient.WithHTTPClient(opts.httpClient(cmd)),
			)
			if err != nil {
				return err
			}
			resp, err := client.GetVersionWithResponse(cmd.Context())
			if err != nil {
				return fmt.Errorf("contacting the server: %w", err)
			}
			if resp.JSON200 == nil {
				return fmt.Errorf("unexpected response from the server: %s", resp.Status())
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "server: %s (commit %s, API %s)\n",
				resp.JSON200.Version, resp.JSON200.Commit, resp.JSON200.ApiVersion)
			return err
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "URL of a White Tower server, for example https://localhost:8443")
	return cmd
}
