package irmacli

import (
	"encoding/json"
	"fmt"

	"github.com/privacybydesign/irmago/irma/server/requestorserver"
	"github.com/privacybydesign/irmago/yivi/cli/internal/clihelpers"
	"github.com/spf13/cobra"
)

var serverCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check server configuration correctness",
	Long: `check reads the server configuration like the main command does, from a
configuration file, command line flags, or environmental variables, and checks
that the configuration is valid.

Specify -v to see the configuration.`,
	Run: func(command *cobra.Command, args []string) {
		conf, err := configureServer(command)
		if err != nil {
			clihelpers.Die("", fmt.Errorf("Failed to read configuration from file, args, or env vars: %w", err), Logger)
		}

		// Hack: temporarily disable scheme updating to prevent verifyConfiguration() from immediately updating schemes
		enabled := conf.DisableSchemesUpdate
		conf.DisableSchemesUpdate = true

		if _, err := requestorserver.New(conf); err != nil {
			clihelpers.Die("", fmt.Errorf("Invalid configuration: %w", err), Logger)
		}

		conf.DisableSchemesUpdate = enabled // restore previous value before printing configuration
		bts, _ := json.MarshalIndent(conf, "", "   ")
		conf.Logger.Debug("Configuration: ", string(bts), "\n")
	},
}

func init() {
	serverCmd.AddCommand(serverCheckCmd)

	if err := setFlags(serverCheckCmd, productionMode()); err != nil {
		clihelpers.Die("", fmt.Errorf("Failed to attach flags to %s command: %w", serverCheckCmd.Name(), err), Logger)
	}
}
