package cmd

import "github.com/sietseringers/cobra"

// revocationCmd represents the revocation command
var revocationCmd = &cobra.Command{
	Use:   "revocation",
	Short: "Revocation",
}

func init() {
	issuerCmd.AddCommand(revocationCmd)
}
