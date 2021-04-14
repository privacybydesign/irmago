package cmd

import "github.com/sietseringers/cobra"

var keyshareRoot = &cobra.Command{
	Use:   "keyshare",
	Short: "IRMA keyshare server components",
}

func init() {
	RootCmd.AddCommand(keyshareRoot)
}
