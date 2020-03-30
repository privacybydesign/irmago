package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "irma",
	Short: "IRMA toolkit",
	Long:  "IRMA toolkit v" + irma.Version + "\nDocumentation: https://irma.app/docs",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print irma version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(RootCmd.Long)
		fmt.Println()
		fmt.Println("Version: ", irma.Version)
		fmt.Println("OS/Arg:  ", runtime.GOOS+"/"+runtime.GOARCH)
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

func die(message string, err error) {
	var m string
	if message != "" {
		m = message
	}
	if err != nil {
		if message != "" {
			m += ": "
		}
		if e, ok := err.(*errors.Error); ok && logger.IsLevelEnabled(logrus.DebugLevel) {
			m += e.ErrorStack()
		} else {
			m += err.Error()
		}
	}

	logger.Error(m)
	os.Exit(1)
}
