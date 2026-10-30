package irmacli

import (
	"fmt"

	"github.com/privacybydesign/irmago/irma/server/usage"
	"github.com/privacybydesign/irmago/yivi/cli/internal/clihelpers"
	"github.com/spf13/cobra"
)

var serverUsageKeyCmd = &cobra.Command{
	Use:   "usage-key",
	Short: "Print the usage reporting public key to register in the Yivi Portal",
	Long: `usage-key loads the account key the server signs its usage reports with, creating it in the
state dir if it does not exist yet, and prints its public key and JWK thumbprint. Register the
public key with your organisation in the Yivi Portal before starting the server in production mode.`,
	Args: cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		flags := command.Flags()
		stateDir, _ := flags.GetString("usage-reporting-state-dir")
		keyFile, _ := flags.GetString("usage-reporting-account-key-file")

		key, err := usage.LoadOrCreateKey(keyFile, stateDir)
		if err != nil {
			clihelpers.Die("", err, Logger)
		}
		pub, err := usage.PublicKeyPEM(key)
		if err != nil {
			clihelpers.Die("", err, Logger)
		}
		fmt.Print(pub)
		fmt.Println("JWK thumbprint:", usage.Thumbprint(key))
	},
}

func init() {
	serverCmd.AddCommand(serverUsageKeyCmd)

	flags := serverUsageKeyCmd.Flags()
	flags.String("usage-reporting-state-dir", "", "directory holding the account key (it is created there if absent)")
	flags.String("usage-reporting-account-key-file", "", "PEM file with the account key")
}
