package cmd

import (
	irma "github.com/privacybydesign/irmago"
	"github.com/spf13/cobra"
)

var revokeEnableCmd = &cobra.Command{
	Use:   "enable CREDENTIALTYPE",
	Short: "Enable revocation for a credential type",
	Long: `Enable revocation for a given credential type.

Must be done (and can only be done) by the issuer of the specified credential type, if enable in the
scheme.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()
		schemespath, _ := flags.GetString("schemes-path")
		authmethod, _ := flags.GetString("auth-method")
		key, _ := flags.GetString("key")
		name, _ := flags.GetString("name")
		verbosity, _ := cmd.Flags().GetCount("verbose")

		request := &irma.RevocationRequest{
			LDContext:      irma.LDContextRevocationRequest,
			CredentialType: irma.NewCredentialTypeIdentifier(args[0]),
			Enable:         true,
		}

		postRevocation(request, schemespath, authmethod, key, name, verbosity)
	},
}

func init() {
	flags := revokeEnableCmd.Flags()
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.StringP("auth-method", "a", "none", "Authentication method to server (none, token, rsa, hmac)")
	flags.String("key", "", "Key to sign request with")
	flags.String("name", "", "Requestor name")
	flags.CountP("verbose", "v", "verbose (repeatable)")

	revocationCmd.AddCommand(revokeEnableCmd)
}
