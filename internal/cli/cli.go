// Package cli implements wtctl, the command-line client of White Tower.
package cli

import "github.com/spf13/cobra"

// NewRootCommand returns the wtctl command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "wtctl",
		Short:         "Command-line client for the White Tower governance core",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCommand())
	return root
}
