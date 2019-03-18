package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
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

func init() {
	RootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print irma version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("irma")
			fmt.Println("Version: ", "0.1.1")
			fmt.Println("OS/Arg:  ", runtime.GOOS+"/"+runtime.GOARCH)
		},
	})
}

func die(err *errors.Error) {
	msg := err.Error()
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		msg += "\nStack trace:\n" + string(err.Stack())
	}
	logger.Fatal(msg)
}
