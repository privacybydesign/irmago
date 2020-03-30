package cmd

import (
	"github.com/spf13/cobra"
)

var serverRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run server (same as specifying no command)",
	Run:   serverCmd.Run,
}

func init() {
	serverCmd.AddCommand(serverRunCmd)

	if err := setFlags(serverRunCmd, productionMode()); err != nil {
		die("Failed to attach flags to "+serverRunCmd.Name()+" command", err)
	}
}
