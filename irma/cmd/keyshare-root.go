package cmd

import "github.com/spf13/cobra"

var keyshareRoot = &cobra.Command{
	Use:   "keyshare",
	Short: "Irma keyshare server",
}

func init() {
	RootCmd.AddCommand(keyshareRoot)
}
