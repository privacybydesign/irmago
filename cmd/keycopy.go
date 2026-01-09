package cmd

import (
	"os"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keycopyCmd = &cobra.Command{
	Use:   "keycopy",
	Short: "Copy ECDSA private key using a new passphrase",
	Long:  `Copy ECDSA private key suitable for signing IRMA scheme managers using a new passphrase.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		inFile, err := cmd.Flags().GetString("in")
		if err != nil {
			return err
		}
		outFile, err := cmd.Flags().GetString("out")
		if err != nil {
			return err
		}
		usePassphrase, err := cmd.Flags().GetBool("pass")
		if err != nil {
			return err
		}

		// For safety we enforce that we never overwrite a file
		if err := common.AssertPathNotExists(outFile); err != nil {
			return errors.Errorf("file %s already exists, not overwriting", outFile)
		}

		key, err := readPrivateKey(inFile)
		if err != nil {
			return err
		}

		var bts []byte
		if usePassphrase {
			passphrase, err := promptForNewPassphrase()
			if err != nil {
				return err
			}
			bts, err = common.MarshalSchemePrivateKeyWithPassphrase(key, passphrase)
			if err != nil {
				return err
			}
		} else {
			bts, err = signed.MarshalPemPrivateKey(key)
			if err != nil {
				return err
			}
		}

		// Save keys
		if err = os.WriteFile(outFile, bts, 0600); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	schemeCmd.AddCommand(keycopyCmd)
	keycopyCmd.Flags().StringP("in", "i", "sk.pem", "filename for private key")
	keycopyCmd.Flags().StringP("out", "o", "sk-copy.pem", "filename for the copy")
	keycopyCmd.Flags().Bool("pass", true, "ask for a passphrase to encrypt the private key")
}
