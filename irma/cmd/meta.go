package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

// metaCmd represents the meta command
var metaCmd = &cobra.Command{
	Use:   "meta irma_configuration attribute",
	Short: "Parse an IRMA metadata attribute and print its contents",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		confpath := args[0]
		metaint := new(big.Int)
		_, ok := metaint.SetString(args[1], 10)
		if !ok {
			bts, err := base64.StdEncoding.DecodeString(args[0])
			if err != nil {
				return errors.WrapPrefix(err, "Could not parse argument as decimal or base64 integer", 0)
			}
			metaint.SetBytes(bts)
		}

		if err := printMetadataAttr(metaint, confpath); err != nil {
			die("", err)
		}
		return nil
	},
}

func printMetadataAttr(metaint *big.Int, confpath string) error {
	if err := fs.AssertPathExists(confpath); err != nil {
		return errors.WrapPrefix(err, "Cannot read irma_configuration", 0)
	}
	conf, err := irma.NewConfigurationReadOnly(confpath)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to parse irma_configuration", 0)
	}
	err = conf.ParseFolder()
	if err != nil {
		return errors.WrapPrefix(err, "Failed to parse irma_configuration", 0)
	}

	meta := irma.MetadataFromInt(metaint, conf)
	typ := meta.CredentialType()
	var key *gabi.PublicKey

	if typ == nil {
		fmt.Println("Unknown credential type, hash:", base64.StdEncoding.EncodeToString(meta.CredentialTypeHash()))
	} else {
		fmt.Println("Identifier      :", typ.Identifier())
		key, err = meta.PublicKey()
		if err != nil {
			fmt.Println("Failed to parse public key", err)
		}
	}
	fmt.Println("Signed          :", meta.SigningDate().String())
	fmt.Println("Expires         :", meta.Expiry().String())
	fmt.Println("IsValid         :", meta.IsValid())
	fmt.Println("Version         :", meta.Version())
	fmt.Println("KeyCounter      :", meta.KeyCounter())
	if key != nil {
		fmt.Println("KeyExpires      :", time.Unix(key.ExpiryDate, 0))
		fmt.Println("KeyModulusBitlen:", key.N.BitLen())
	}

	fmt.Println()
	fmt.Println("CredentialType  :", prettyprint(typ))

	return nil
}

func prettyprint(ob interface{}) string {
	b, err := json.MarshalIndent(ob, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(b)
}

func init() {
	RootCmd.AddCommand(metaCmd)
}
