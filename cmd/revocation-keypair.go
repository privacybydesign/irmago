package cmd

import (
	"github.com/privacybydesign/gabi/gabikeys"
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
			die("failed to read private key", err)
		}
		if sk.RevocationSupported() {
			die("private key already supports revocation", nil)
		}

		pk, err := gabikeys.NewPublicKeyFromFile(args[1])
		if err != nil {
			die("failed to read public key", err)
		}
		if pk.RevocationSupported() {
			die("public key already supports revocation", nil)
		}

		if err = gabikeys.GenerateRevocationKeypair(sk, pk); err != nil {
			die("failed to generate revocation keys", err)
		}

		if _, err = sk.WriteToFile(args[0], true); err != nil {
			die("failed to write private key", err)
		}
		if _, err = pk.WriteToFile(args[1], true); err != nil {
			die("failed to write public key", err)
		}

	},
}

func init() {
	issuerCmd.AddCommand(revokeKeypairCmd)
}
