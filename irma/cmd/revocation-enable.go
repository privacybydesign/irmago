package cmd

import (
	"path/filepath"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

var revokeEnableCmd = &cobra.Command{
	Use:   "enable CREDENTIALTYPE [PATH]",
	Short: "Enable revocation for a credential type",
	Long: `Enable revocation for a given credential type.

Must be done (and can only be done) by the issuer of the specified credential type, if enable in the
scheme. The revocation database is written to or updated from PATH, or the default IRMA storage path
(` + irma.DefaultDataPath() + `).`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		path := irma.DefaultDataPath()
		if len(args) > 1 {
			path = args[1]
		}
		db, nonrevKey := configureRevocation(cmd, path, args[0])

		if err := db.EnableRevocation(nonrevKey); err != nil {
			die("failed to enable revocation", err)
		}
	},
}

func configureRevocation(cmd *cobra.Command, path, credtype string) (*revocation.DB, *revocation.PrivateKey) {
	var err error
	if err = fs.EnsureDirectoryExists(filepath.Join(path, "revocation")); err != nil {
		die("failed to create revocation database folder", err)
	}

	// parse irma_configuration and lookup credential type
	irmaconf, err := irma.NewConfiguration(filepath.Join(path, "irma_configuration"))
	if err != nil {
		die("failed to open irma_configuration", err)
	}
	if err = irmaconf.ParseFolder(); err != nil {
		die("failed to parse irma_configuration", err)
	}

	id := irma.NewCredentialTypeIdentifier(credtype)
	typ := irmaconf.CredentialTypes[id]
	if typ == nil {
		die("unknown credential type", nil)
	}

	// Read private key from either flag or irma_configuration
	var privatekey *gabi.PrivateKey
	privkeypath, _ := cmd.Flags().GetString("privatekey")
	if privkeypath != "" {
		privatekey, err = gabi.NewPrivateKeyFromFile(privkeypath)
	} else {
		privatekey, err = irmaconf.PrivateKey(typ.IssuerIdentifier())
	}
	if err != nil {
		die("failed to read private key", err)
	}
	if privatekey == nil {
		die("no private key specified and none found in irma_configuration", nil)
	}
	nonrevKey, err := privatekey.RevocationKey()
	if err != nil {
		die("failed to load nonrevocation private key from IRMA private key", err)
	}
	db, err := irmaconf.RevocationDB(id)
	if err != nil {
		die("failed to load revocation database", err)
	}

	return db, nonrevKey
}

func init() {
	revokeEnableCmd.Flags().StringP("privatekey", "s", "", `Issuer private key for specified credential type`)
	revocationCmd.AddCommand(revokeEnableCmd)
}
