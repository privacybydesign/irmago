// Package eudicli is the `yivi eudi` command group: tooling for the EUDI side of
// the wallet, as opposed to the IRMA side in package irmacli.
package eudicli

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Logger is set by the root command; the subcommands report through it.
var Logger = logrus.New()

var EudiRootCmd = &cobra.Command{
	Use:   "eudi [command]",
	Short: "EUDI toolkit",
}
