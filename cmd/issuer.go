package cmd

import "github.com/spf13/cobra"

// issuerCmd represents the issuer command
var issuerCmd = &cobra.Command{
	Use:   "issuer",
	Short: "Manage IRMA issuers within an IRMA scheme",
}

func init() {
	schemeCmd.AddCommand(issuerCmd)
	RootCmd.AddCommand(issuerCmd)
}
