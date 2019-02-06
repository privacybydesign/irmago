package cmd

import (
	"encoding/json"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/spf13/cobra"
)

var CheckCommand = &cobra.Command{
	Use:   "check",
	Short: "Check server configuration correctness",
	Long: `check reads the server configuration like the main command does, from a
configuration file, command line flags, or environmental variables, and checks
that the configuration is valid.

Specify -v to see the configuration.`,
	Run: func(command *cobra.Command, args []string) {
		if err := configure(command); err != nil {
			die(errors.WrapPrefix(err, "Failed to read configuration from file, args, or env vars", 0))
		}
		interval := conf.SchemeUpdateInterval
		download := conf.DownloadDefaultSchemes
		conf.SchemeUpdateInterval = 0       // Hack: put this to 0 to prevent verifyConfiguration() from immediately updating schemes
		conf.DownloadDefaultSchemes = false // and this to false to prevent default scheme downloading
		if _, err := requestorserver.New(conf); err != nil {
			die(errors.WrapPrefix(err, "Invalid configuration", 0))
		}
		conf.SchemeUpdateInterval = interval // restore previous values before printing configuration
		conf.DownloadDefaultSchemes = download
		bts, _ := json.MarshalIndent(conf, "", "   ")
		conf.Logger.Debug("Configuration: ", string(bts), "\n")
	},
}

func init() {
	RootCommand.AddCommand(CheckCommand)

	if err := setFlags(CheckCommand); err != nil {
		die(errors.WrapPrefix(err, "Failed to attach flags to "+CheckCommand.Name()+" command", 0))
	}
}
