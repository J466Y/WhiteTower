package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/J466Y/WhiteTower/internal/authn"
	"github.com/J466Y/WhiteTower/internal/platform/config"
)

func newBreakglassCommand(load func() (config.Config, error), stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "breakglass",
		Short: "Manage emergency break-glass credentials (plan P1-03, step 9; HUM-06, KIL-08)",
	}
	cmd.AddCommand(newBreakglassInitCommand(load, stdout))
	return cmd
}

func newBreakglassInitCommand(load func() (config.Config, error), stdout io.Writer) *cobra.Command {
	var outFile string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate an emergency break-glass credential and write its salted hash",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			targetFile := outFile
			if targetFile == "" {
				targetFile = cfg.Auth.Breakglass.CredentialHashFile
			}
			if targetFile == "" {
				return fmt.Errorf("credential hash file path must be specified via --out or auth.breakglass.credential_hash_file")
			}

			rawCred, hashStr, err := authn.GenerateBreakglassCredential()
			if err != nil {
				return fmt.Errorf("generating credential: %w", err)
			}

			if err := os.WriteFile(targetFile, []byte(hashStr+"\n"), 0o600); err != nil {
				return fmt.Errorf("writing hash file %s: %w", targetFile, err)
			}

			out := stdout
			if out == nil {
				out = cmd.OutOrStdout()
			}
			fmt.Fprintln(out, "EMERGENCY BREAK-GLASS CREDENTIAL INITIALIZED")
			fmt.Fprintf(out, "Credential: %s\n", rawCred)
			fmt.Fprintf(out, "Hash file:  %s\n\n", targetFile)
			fmt.Fprintln(out, "IMPORTANT:")
			fmt.Fprintln(out, "- This credential will NOT be displayed again.")
			fmt.Fprintln(out, "- Store it in a sealed physical or digital safe.")
			fmt.Fprintln(out, "- It is strongly recommended to split this credential between two independent custodians.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&outFile, "out", "o", "", "Path to write the credential hash file (defaults to config)")
	return cmd
}
