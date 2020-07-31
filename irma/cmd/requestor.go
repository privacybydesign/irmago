package cmd

import (
	"github.com/spf13/cobra"
)

// schemeCmd represents the scheme command
var requestorCmd = &cobra.Command{
	Use:   "requestor",
	Short: "Manage requestor scheme",
}

func init() {
	RootCmd.AddCommand(requestorCmd)
}
