package cmd

import (
	"github.com/spf13/cobra"
)

// revocationCmd represents the revoke command
var revocationCmd = &cobra.Command{
	Use:   "revocation",
	Short: "Revoke credentials and manage revocation database",
}

func init() {
	issuerCmd.AddCommand(revocationCmd)
}
