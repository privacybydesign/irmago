package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io/ioutil"

	"fmt"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate ECDSA private/public keypair",
	Long:  `Generate an ECDSA private/public keypair suitable for signing IRMA scheme managers.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		skfile, err := cmd.Flags().GetString("privatekey")
		if err != nil {
			return err
		}
		pkfile, err := cmd.Flags().GetString("publickey")
		if err != nil {
			return err
		}

		// For safety we enforce that we never overwrite a file
		if err := common.AssertPathNotExists(skfile); err != nil {
			return errors.Errorf("File %s already exists, not overwriting", skfile)
		}
		if err := common.AssertPathNotExists(pkfile); err != nil {
			return errors.Errorf("File %s already exists, not overwriting", pkfile)
		}

		// Generate keys
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		// Marshal keys
		pemEncoded, err := signed.MarshalPemPrivateKey(key)
		if err != nil {
			return err
		}
		pemEncodedPub, err := signed.MarshalPemPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}

		// Save keys
		if err = ioutil.WriteFile(skfile, pemEncoded, 0600); err != nil {
			return err
		}
		fmt.Println("Private key written at", skfile)
		if err = ioutil.WriteFile(pkfile, pemEncodedPub, 0644); err != nil {
			return err
		}
		fmt.Println("Public key written at", pkfile)

		return nil
	},
}

func init() {
	schemeCmd.AddCommand(keygenCmd)
	keygenCmd.Flags().StringP("privatekey", "s", "sk.pem", "filename for private key")
	keygenCmd.Flags().StringP("publickey", "p", "pk.pem", "filename for public key")
}
