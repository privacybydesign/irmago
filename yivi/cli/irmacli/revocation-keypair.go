package irmacli

import (
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/irmago/yivi/cli/internal/clihelpers"
	"github.com/spf13/cobra"
)

var revokeKeypairCmd = &cobra.Command{
	Use:   "revocation-keypair <privatekey> <publickey>",
	Short: "Augment an IRMA private-public keypair with revocation key material",
	Long: `Augment an IRMA private-public keypair with newly generated revocation key material.
This is required before credential types requiring revocation can be issued under this keypair.
(New keypairs generated with "irma scheme issuer keygen" already support revocation.)`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sk, err := gabikeys.NewPrivateKeyFromFile(args[0], false)
		if err != nil {
			clihelpers.Die("failed to read private key", err, Logger)
		}
		if sk.RevocationSupported() {
			clihelpers.Die("private key already supports revocation", nil, Logger)
		}

		pk, err := gabikeys.NewPublicKeyFromFile(args[1])
		if err != nil {
			clihelpers.Die("failed to read public key", err, Logger)
		}
		if pk.RevocationSupported() {
			clihelpers.Die("public key already supports revocation", nil, Logger)
		}

		if err = gabikeys.GenerateRevocationKeypair(sk, pk); err != nil {
			clihelpers.Die("failed to generate revocation keys", err, Logger)
		}

		if _, err = sk.WriteToFile(args[0], true); err != nil {
			clihelpers.Die("failed to write private key", err, Logger)
		}
		if _, err = pk.WriteToFile(args[1], true); err != nil {
			clihelpers.Die("failed to write public key", err, Logger)
		}

	},
}

func init() {
	issuerCmd.AddCommand(revokeKeypairCmd)
}
