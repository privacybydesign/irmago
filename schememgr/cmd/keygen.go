package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"

	"io/ioutil"

	"fmt"

	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/go-errors/errors"
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
		if err := fs.AssertPathNotExists(skfile); err != nil {
			return errors.Errorf("File %s already exists, not overwriting", skfile)
		}
		if err := fs.AssertPathNotExists(pkfile); err != nil {
			return errors.Errorf("File %s already exists, not overwriting", pkfile)
		}

		// Generate keys
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		// Marshal keys
		bts, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bts})
		bts, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			os.Exit(1)
		}
		pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bts})

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
	RootCmd.AddCommand(keygenCmd)
	keygenCmd.Flags().StringP("privatekey", "s", "sk.pem", "filename for private key")
	keygenCmd.Flags().StringP("publickey", "p", "pk.pem", "filename for public key")
}
