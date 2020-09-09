package cmd

import (
	"encoding/json"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/sietseringers/cobra"
)

var serverCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check server configuration correctness",
	Long: `check reads the server configuration like the main command does, from a
configuration file, command line flags, or environmental variables, and checks
that the configuration is valid.

Specify -v to see the configuration.`,
	Run: func(command *cobra.Command, args []string) {
		if err := configureServer(command); err != nil {
			die("", errors.WrapPrefix(err, "Failed to read configuration from file, args, or env vars", 0))
		}

		// Hack: temporarily disable scheme updating to prevent verifyConfiguration() from immediately updating schemes
		enabled := conf.DisableSchemesUpdate
		conf.DisableSchemesUpdate = true

		if _, err := requestorserver.New(conf); err != nil {
			die("", errors.WrapPrefix(err, "Invalid configuration", 0))
		}

		conf.DisableSchemesUpdate = enabled // restore previous value before printing configuration
		bts, _ := json.MarshalIndent(conf, "", "   ")
		conf.Logger.Debug("Configuration: ", string(bts), "\n")
	},
}

func init() {
	serverCmd.AddCommand(serverCheckCmd)

	if err := setFlags(serverCheckCmd, productionMode()); err != nil {
		die("", errors.WrapPrefix(err, "Failed to attach flags to "+serverCheckCmd.Name()+" command", 0))
	}
}
