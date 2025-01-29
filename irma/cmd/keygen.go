package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"

	"fmt"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
		usePassphrase, err := cmd.Flags().GetBool("pass")
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
		var pemEncoded []byte
		if usePassphrase {
			passphrase, err := promptForNewPassphrase()
			if err != nil {
				return err
			}
			pemEncoded, err = common.MarshalSchemePrivateKeyWithPassphrase(key, passphrase)
			if err != nil {
				return err
			}
		} else {
			pemEncoded, err = signed.MarshalPemPrivateKey(key)
			if err != nil {
				return err
			}
		}
		pemEncodedPub, err := signed.MarshalPemPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}

		// Save keys
		if err = os.WriteFile(skfile, pemEncoded, 0600); err != nil {
			return err
		}
		fmt.Println("Private key written at", skfile)
		if err = os.WriteFile(pkfile, pemEncodedPub, 0644); err != nil {
			return err
		}
		fmt.Println("Public key written at", pkfile)

		return nil
	},
}

func promptForNewPassphrase() ([]byte, error) {
	fmt.Print("Enter passphrase for new key: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	fmt.Print("Confirm passphrase: ")
	confirmedPassphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(passphrase, confirmedPassphrase) {
		return nil, errors.New("passphrases did not match")
	}
	return passphrase, nil
}

func init() {
	schemeCmd.AddCommand(keygenCmd)
	keygenCmd.Flags().StringP("privatekey", "s", "sk.pem", "filename for private key")
	keygenCmd.Flags().StringP("publickey", "p", "pk.pem", "filename for public key")
	keygenCmd.Flags().Bool("pass", false, "ask for a passphrase to encrypt the private key")
}
