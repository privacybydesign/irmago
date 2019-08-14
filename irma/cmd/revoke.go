package cmd

import (
	irma "github.com/privacybydesign/irmago"
	"github.com/spf13/cobra"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke CREDENTIALTYPE KEY [PATH]",
	Short: "Revoke a previously issued credential identified by a given key",
	Args:  cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		irmaconf := irma.DefaultSchemesPath()
		if len(args) == 3 {
			irmaconf = args[2]
		} else if irmaconf == "" {
			die("Failed to find default irma_configuration path", nil)
		}

		conf, err := irma.NewConfigurationReadOnly(irmaconf)
		if err != nil {
			die("", err)
		}
		if err = conf.ParseFolder(); err != nil {
			die("", err)
		}
		cred := irma.NewCredentialTypeIdentifier(args[0])
		if _, known := conf.CredentialTypes[cred]; !known {
			die("unknown credential type", nil)
		}

		flags := cmd.Flags()
		authmethod, _ := flags.GetString("authmethod")
		key, _ := flags.GetString("key")
		name, _ := flags.GetString("name")

		_ = &irma.RevocationRequest{
			LDContext:      irma.LDContextRevocationRequest,
			CredentialType: cred,
			Key:            args[1],
		}
	},
}

func init() {
	flags := revocationCmd.Flags()
	flags.StringP("authmethod", "a", "none", "Authentication method to server (none, token, rsa, hmac)")
	flags.String("key", "", "Key to sign request with")
	flags.String("name", "", "Requestor name")

	revocationCmd.AddCommand(revokeCmd)
}
