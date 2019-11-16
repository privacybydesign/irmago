package cmd

import (
	"github.com/spf13/cobra"
)

// revocationCmd represents the revocation command
var revocationCmd = &cobra.Command{
	Use:   "revocation",
	Short: "Revocation",
}

func init() {
	issuerCmd.AddCommand(revocationCmd)
}
