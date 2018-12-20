package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "irma",
	Short: "IRMA toolkit",
	Long:  `IRMA toolkit`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func die(message string, err error) {
	var m string
	if message != "" {
		m = message + ": "
	}
	if err != nil {
		m = m + err.Error()
	}
	fmt.Println(m)
	os.Exit(1)
}
