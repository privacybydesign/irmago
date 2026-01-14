package irmacli

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Logger *logrus.Logger

// RootCmd represents the base command when called without any subcommands
var IrmaRootCmd = &cobra.Command{
	Use:   "irma [command]",
	Short: "IRMA toolkit",
}
