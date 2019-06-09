package cmd

import (
	"fmt"
	"os"
	"runtime"

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
		os.Exit(-1)
	}
}

func init() {
	RootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print irma version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("irma")
			fmt.Println("Version: ", "0.3.0")
			fmt.Println("OS/Arg:  ", runtime.GOOS+"/"+runtime.GOARCH)
		},
	})
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
