package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

// metaCmd represents the meta command
var metaCmd = &cobra.Command{
	Use:   "meta <attribute>",
	Short: "Parse an IRMA metadata attribute and print its contents",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		confPath, err := cmd.Flags().GetString("irmaconf")
		if err != nil {
			die("Failed to get irma_configuration flag", err)
		}
		confAssetsPath, err := cmd.Flags().GetString("irmaconf-assets")
		if err != nil {
			die("Failed to get irma_configuration flag", err)
		}

		metaint := new(big.Int)
		_, ok := metaint.SetString(args[0], 10)
		if !ok {
			// Not a base-10 integer, try to parse as base64. This is safe:
			// Since the first byte of a metadata attribute is its version, currently 0x03,
			// the first letter of any baase64'd metadata attribute will be 'A'. So it can never happen
			// that a base64'd metadata attribute consists of only digits.
			bts, err := base64.StdEncoding.DecodeString(args[0])
			if err != nil {
				return errors.WrapPrefix(err, "Could not parse argument as decimal or base64 integer", 0)
			}
			metaint.SetBytes(bts)
		}

		if err := printMetadataAttr(metaint, confPath, confAssetsPath); err != nil {
			die("", err)
		}
		return nil
	},
}

func printMetadataAttr(metaint *big.Int, confPath string, confAssetsPath string) error {
	if err := common.AssertPathExists(confPath); err != nil {
		return errors.WrapPrefix(err, "Cannot read irma_configuration", 0)
	}
	conf, err := irma.NewConfiguration(confPath, irma.ConfigurationOptions{ReadOnly: true, Assets: confAssetsPath})
	if err != nil {
		return errors.WrapPrefix(err, "Failed to parse irma_configuration", 0)
	}
	err = conf.ParseFolder()
	if err != nil {
		return errors.WrapPrefix(err, "Failed to parse irma_configuration", 0)
	}

	meta := irma.MetadataFromInt(metaint, conf)
	typ := meta.CredentialType()
	var key *gabikeys.PublicKey

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

	metaCmd.Flags().StringP("irmaconf", "i", irma.DefaultSchemesPath(), "path to irma_configuration")
	metaCmd.Flags().String("irmaconf-assets", irma.DefaultSchemesAssetsPath(), "if specified, copy schemes from here into irmaconf")
}
