package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/yivi/cli/internal/clihelpers"
	"github.com/privacybydesign/irmago/yivi/cli/irmacli"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var logger = logrus.New()

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "yivi",
	Short: "Yivi toolkit",
	Long:  "Yivi toolkit v" + irmago.Version + "\nDocumentation: https://yivi.app/docs",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print Yivi version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(RootCmd.Long)
		fmt.Println()
		fmt.Println("Version: ", irmago.Version)
		fmt.Println("OS/Arg:  ", runtime.GOOS+"/"+runtime.GOARCH)
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	logger.Formatter = &prefixed.TextFormatter{FullTimestamp: true}

	irmacli.Logger = logger

	RootCmd.AddCommand(versionCmd)
	RootCmd.AddCommand(irmacli.IrmaRootCmd)

	cobra.AddTemplateFunc("insertHeaders", clihelpers.InsertHeaders)
}
