package irmacli

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Logger *logrus.Logger

var IrmaRootCmd = &cobra.Command{
	Use:   "irma [command]",
	Short: "IRMA toolkit",
}
