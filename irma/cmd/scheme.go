package cmd

import "github.com/spf13/cobra"

// schemeCmd represents the scheme command
var schemeCmd = &cobra.Command{
	Use:   "scheme",
	Short: "Manage IRMA schemes",
}

func init() {
	RootCmd.AddCommand(schemeCmd)
}
