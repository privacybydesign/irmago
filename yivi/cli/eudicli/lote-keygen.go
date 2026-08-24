package eudicli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

var loteKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a throwaway signing chain for testing (never for publishing)",
	Long: `Generate a throwaway trust-list signing chain: a self-signed CA and a signing
certificate under it, with a P-256 key.

**This is for testing only.** The key is written to disk unencrypted and the chain
anchors nothing a wallet trusts, so a list signed with it verifies only against the
CA generated alongside it. A published list is signed under the Yivi Trust List CA.

Its purpose is to let a pull-request check answer "would this document sign?"
without the real key. Clause 6.8.0 binds the signing certificate's subject to the
document it signs, so a curation change that breaks that binding should fail in
review rather than at release; the generated certificate carries --country and
--organization for exactly that, and they must match the scheme's SchemeTerritory
and one of its SchemeOperatorName values.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, _ := cmd.Flags().GetString("out-dir")
		country, _ := cmd.Flags().GetString("country")
		organization, _ := cmd.Flags().GetString("organization")
		days, _ := cmd.Flags().GetInt("days")

		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}

		notBefore := time.Now().Add(-time.Hour)
		notAfter := time.Now().AddDate(0, 0, days)

		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "lote throwaway root"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
		if err != nil {
			return err
		}
		caCert, err := x509.ParseCertificate(caDer)
		if err != nil {
			return err
		}

		signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		signerTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			// Clause 6.8.0: `sign` checks these against the document's
			// SchemeTerritory and SchemeOperatorName, so they are the whole reason
			// this command takes flags at all.
			Subject: pkix.Name{
				CommonName:   "lote throwaway signer",
				Country:      []string{country},
				Organization: []string{organization},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,
			// Checked explicitly by the wallet, so a chain generated here has to
			// carry it or `sign`'s own re-verification fails.
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		signerDer, err := x509.CreateCertificate(rand.Reader, signerTemplate, caCert, signerKey.Public(), caKey)
		if err != nil {
			return err
		}

		signerKeyDer, err := x509.MarshalPKCS8PrivateKey(signerKey)
		if err != nil {
			return err
		}

		files := []struct {
			name  string
			block *pem.Block
			mode  os.FileMode
		}{
			{"ca.crt", &pem.Block{Type: "CERTIFICATE", Bytes: caDer}, 0o644},
			{"signer.crt", &pem.Block{Type: "CERTIFICATE", Bytes: signerDer}, 0o644},
			{"signer.key", &pem.Block{Type: "PRIVATE KEY", Bytes: signerKeyDer}, 0o600},
		}
		for _, file := range files {
			path := filepath.Join(dir, file.name)
			if err := os.WriteFile(path, pem.EncodeToMemory(file.block), file.mode); err != nil {
				return err
			}
		}

		Logger.Warn("`lote keygen` produces a throwaway chain for testing; a published list is signed under the Yivi Trust List CA")
		Logger.Infof("wrote ca.crt, signer.crt and signer.key to %s (C=%s, O=%s, valid %d days)",
			dir, country, organization, days)
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n", filepath.Join(dir, "signer.crt"))
		return nil
	},
}

func init() {
	loteCmd.AddCommand(loteKeygenCmd)

	loteKeygenCmd.Flags().String("out-dir", ".", "directory to write ca.crt, signer.crt and signer.key into")
	loteKeygenCmd.Flags().String("country", "NL", "subject Country; must equal the scheme's SchemeTerritory")
	loteKeygenCmd.Flags().String("organization", "Yivi", "subject Organization; must be one of the scheme's SchemeOperatorName values")
	loteKeygenCmd.Flags().Int("days", 1, "certificate validity in days")
}
