package eudicli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var configKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a throwaway config signing chain for testing (never for publishing)",
	Long: `Generate a throwaway wallet config signing chain: a self-signed root, an
intermediate CA under it, and a signing certificate under that, all with P-256
keys — the shape the real Yivi Wallet Config CA has, so what is tested with it
exercises the same chain building.

**This is for testing only.** The keys are written to disk unencrypted and the
root anchors nothing a released wallet trusts, so a config signed with it
verifies only in a wallet built with this root as an environment's signing root.
A published config is signed under the Yivi Wallet Config CA.

Its purpose is to let a pull-request check answer "would this config sign and
verify?" without the real key, and to let a developer run a wallet against a
config of their own.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, _ := cmd.Flags().GetString("out-dir")
		organization, _ := cmd.Flags().GetString("organization")
		days, _ := cmd.Flags().GetInt("days")

		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeThrowawayChain(dir, organization, days); err != nil {
			return err
		}

		Logger.Warn("`config keygen` produces a throwaway chain for testing; a published config is signed under the Yivi Wallet Config CA")
		Logger.Infof("wrote root.crt, ca.crt, signer.crt, chain.pem and their .key files to %s (O=%s, valid %d days)",
			dir, organization, days)
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", filepath.Join(dir, "chain.pem"))
		return nil
	},
}

func init() {
	configCmd.AddCommand(configKeygenCmd)

	configKeygenCmd.Flags().String("out-dir", ".", "directory to write the certificates and keys into")
	configKeygenCmd.Flags().String("organization", "Yivi Throwaway", "subject Organization of the generated certificates")
	configKeygenCmd.Flags().Int("days", 1, "certificate validity in days")
}

// writeThrowawayChain generates root -> ca -> signer and writes them as PEM.
func writeThrowawayChain(dir, organization string, days int) error {
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().AddDate(0, 0, days)

	rootKey, root, err := throwawayCA("Throwaway Wallet Config Root CA", organization, notBefore, notAfter, nil, nil)
	if err != nil {
		return err
	}
	caKey, ca, err := throwawayCA("Throwaway Wallet Config CA", organization, notBefore, notAfter, root, rootKey)
	if err != nil {
		return err
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "throwaway-wallet-config-signer", Organization: []string{organization}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		// Checked explicitly by the wallet, so a chain generated here has to carry it.
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: subjectKeyIdentifier(signerKey.Public()),
	}
	signer, err := x509.CreateCertificate(rand.Reader, signerTemplate, ca, signerKey.Public(), caKey)
	if err != nil {
		return err
	}

	keys := map[string]*ecdsa.PrivateKey{"root.key": rootKey, "ca.key": caKey, "signer.key": signerKey}
	for name, key := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, name), &pem.Block{Type: "PRIVATE KEY", Bytes: der}, 0o600); err != nil {
			return err
		}
	}
	certificates := map[string][]byte{"root.crt": root.Raw, "ca.crt": ca.Raw, "signer.crt": signer}
	for name, der := range certificates {
		if err := writePEM(filepath.Join(dir, name), &pem.Block{Type: "CERTIFICATE", Bytes: der}, 0o644); err != nil {
			return err
		}
	}
	// chain.pem is what `sign --cert` takes: leaf first, then the intermediate,
	// without the root the wallets pin.
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	return os.WriteFile(filepath.Join(dir, "chain.pem"), chain, 0o644)
}

func throwawayCA(commonName, organization string, notBefore, notAfter time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{organization}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyIdentifier(key.Public()),
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, certificate, nil
}

// subjectKeyIdentifier derives a subject key identifier from a public key: the
// truncated SHA-256 of its encoding, as RFC 7093 method 1 describes.
func subjectKeyIdentifier(public crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(der)
	return digest[:20]
}
