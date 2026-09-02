package eudicli

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/spf13/cobra"
)

var configSignCmd = &cobra.Command{
	Use:   "sign <config.json>",
	Short: "Sign a wallet configuration as a compact JWS",
	Long: `Sign a wallet configuration as a compact JWS (typ yivi-wallet-config+jwt,
alg ES256), the form the wallet fetches and verifies.

Before signing, the payload is read strictly — a member the model does not know
is refused, since signing would silently drop it — and validated as the wallet
validates it, so a file that did not come out of 'build' cannot be signed into
a config the wallet refuses. The signing key must be P-256 and match the first
certificate in --cert; the whole of --cert becomes the x5c header, so give the
leaf followed by the intermediates up to, and excluding, the root the wallets
pin.

After signing, the result is re-verified with the wallet's own verifier. Pass
--root to check the chain as the wallet will; without it the signature, the
headers and the payload are checked but the chain is not.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		keyPath, _ := cmd.Flags().GetString("key")
		certPath, _ := cmd.Flags().GetString("cert")
		rootPath, _ := cmd.Flags().GetString("root")
		out, _ := cmd.Flags().GetString("output")

		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var config walletconfig.Config
		if err := strictUnmarshal(raw, &config); err != nil {
			return fmt.Errorf("parse %s: %w", args[0], err)
		}

		chain, err := readCertificateChain(certPath)
		if err != nil {
			return err
		}
		key, err := readSigningKey(keyPath)
		if err != nil {
			return err
		}

		var root *x509.Certificate
		if rootPath != "" {
			if root, err = readCertificate(rootPath); err != nil {
				return err
			}
		}

		signed, err := signConfig(&config, key, chain, root)
		if err != nil {
			return err
		}
		if root == nil {
			Logger.Warn("no --root given: the signature and payload were checked, but not the chain to the wallet's root")
		}

		if out == "" || out == "-" {
			_, err = cmd.OutOrStdout().Write(signed)
			return err
		}
		if err := os.WriteFile(out, signed, 0o644); err != nil {
			return err
		}
		Logger.Infof("signed %s as %s (%s for %s, version %d)", args[0], out, config.ID, config.Environment, config.Version)
		return nil
	},
}

// signConfig signs and re-verifies. A publisher that emits a document its own
// wallet rejects has published nothing, so the check happens before anything is
// written. With no root the leaf stands in as its own, which exercises the
// signature, the headers and the payload but says nothing about the chain.
func signConfig(config *walletconfig.Config, key crypto.Signer, chain []*x509.Certificate, root *x509.Certificate) ([]byte, error) {
	signed, err := walletconfig.Sign(config, key, chain)
	if err != nil {
		return nil, err
	}

	verifyAgainst := root
	if verifyAgainst == nil {
		verifyAgainst = chain[0]
	}
	env := walletconfig.Environment{Name: config.Environment, ConfigID: config.ID, SigningRoot: verifyAgainst}
	if _, err := walletconfig.Verify(signed, env, time.Now()); err != nil {
		return nil, fmt.Errorf("the signed config does not verify: %w", err)
	}
	return signed, nil
}

func init() {
	configCmd.AddCommand(configSignCmd)

	configSignCmd.Flags().String("key", "signer.key", "PEM private key to sign with (P-256)")
	configSignCmd.Flags().String("cert", "chain.pem", "PEM certificate chain, leaf first, without the root; becomes the x5c header")
	configSignCmd.Flags().String("root", "", "PEM root the wallet pins, to check the chain against after signing")
	configSignCmd.Flags().StringP("output", "o", "", "write the signed config here (default stdout)")
}
