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
		path := irma.DefaultDataPath()
		if len(args) > 2 {
			path = args[2]
		}

		db, sk := configureRevocation(cmd, path, args[0])
		if err := db.Revoke(sk, []byte(args[1])); err != nil {
			die("failed to revoke", err)
		}
	},
}

func init() {
	revokeCmd.Flags().StringP("privatekey", "s", "", `Issuer private key for specified credential type`)
	revocationCmd.AddCommand(revokeCmd)
}
