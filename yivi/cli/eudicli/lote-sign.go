package eudicli

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/eudi/jades"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loteSignCmd = &cobra.Command{
	Use:   "sign <list.json>",
	Short: "Sign a LoTE as a compact JAdES Baseline B signature",
	Long: `Sign a List of Trusted Entities as a compact JAdES Baseline B signature.

The signature encapsulates the document rather than sitting inside it, which is
the form clause 6.8.0 permits for a JSON LoTE and the reason Annex A's schema has
no Signature member.

Before signing, the certificate is checked against the document it is about to
sign, per clause 6.8.0:

  * subject Country must equal the scheme's SchemeTerritory
  * subject Organization must be one of the SchemeOperatorName values
  * the certificate must carry the digitalSignature key usage

Nothing at runtime checks the first two — the wallet validates the chain, not the
distinguished name — so this is the only place a mismatch can be caught.

After signing, the result is re-verified with the wallet's own verifier. Pass
--anchor to check the chain as the wallet will; without it the signature, the typ
guard and the document are checked but the chain is not.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		keyPath, _ := cmd.Flags().GetString("key")
		certPath, _ := cmd.Flags().GetString("cert")
		anchorPath, _ := cmd.Flags().GetString("anchor")
		out, _ := cmd.Flags().GetString("output")

		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var document lote.Document
		if err := json.Unmarshal(raw, &document); err != nil {
			return fmt.Errorf("parse %s: %w", args[0], err)
		}

		chain, err := readCertificateChain(certPath)
		if err != nil {
			return err
		}
		leaf := chain[0]

		key, err := readSigningKey(keyPath)
		if err != nil {
			return err
		}
		alg, err := jades.SignatureAlgorithmFor(key)
		if err != nil {
			return err
		}

		// lote.Sign enforces clause 6.8.0 and clause 6.6.5 and produces the
		// Baseline B signature; this command is the plumbing around it.
		signed, err := lote.Sign(document, chain, key, time.Now())
		if err != nil {
			return err
		}

		// A publisher that emits a document its own wallet rejects has published
		// nothing, so the check happens before the file is written.
		anchors, checksChain, err := verificationAnchors(anchorPath, leaf)
		if err != nil {
			return err
		}
		if _, err := lote.VerifySigned(signed, anchors); err != nil {
			return fmt.Errorf("the signed document does not verify: %w", err)
		}
		if !checksChain {
			Logger.Warn("no --anchor given: the signature and document were checked, but not the chain to a trust anchor")
		}

		if out == "" || out == "-" {
			_, err = os.Stdout.Write(signed)
			return err
		}
		if err := os.WriteFile(out, signed, 0o644); err != nil {
			return err
		}
		Logger.Infof("signed %s as %s (%s, sequence number %d)", args[0], out,
			alg, document.LoTE.SchemeInformation.SequenceNumber)
		return nil
	},
}

func init() {
	loteCmd.AddCommand(loteSignCmd)

	loteSignCmd.Flags().String("key", "signer.key", "PEM private key to sign with")
	loteSignCmd.Flags().String("cert", "signer.crt", "PEM signing certificate, leaf first; intermediates are carried in x5c")
	loteSignCmd.Flags().String("anchor", "", "PEM trust anchor to check the chain against, as the wallet will")
	loteSignCmd.Flags().StringP("output", "o", "", "write the signed document here (default stdout)")
}

// verificationAnchors builds the pool the freshly signed document is checked
// against, reporting whether the chain is genuinely being verified. With no
// anchor the leaf stands in as its own root, which still exercises the signature,
// the typ guard, the single-signature rule and the payload, but says nothing
// about the chain — the caller warns. leaf is read only in that case.
func verificationAnchors(anchorPath string, leaf *x509.Certificate) (eudi_jwt.X509VerificationContext, bool, error) {
	pool := x509.NewCertPool()
	checksChain := false

	if anchorPath != "" {
		anchors, err := readCertificateChain(anchorPath)
		if err != nil {
			return nil, false, err
		}
		for _, anchor := range anchors {
			pool.AddCert(anchor)
		}
		checksChain = true
	} else {
		pool.AddCert(leaf)
	}

	return &eudi_jwt.StaticVerificationContext{VerifyOpts: x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}}, checksChain, nil
}

func readCertificateChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	chain, err := utils.ParsePemCertificateChain(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if len(chain) == 0 {
		// No PEM at all: try raw DER.
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("%s holds neither PEM nor DER certificates", path)
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}

// readSigningKey reads a PEM private key, prompting for a passphrase when the PEM
// is encrypted.
//
// RFC 1423 PEM encryption (what `openssl ec -aes256` writes) is supported because
// operators have such files, but its key derivation is one round of MD5 and Go has
// deprecated it. A stopgap for a key that can vouch for any party at the top rung
// — the intended end state is a key that never leaves hardware, which is why
// `sign` is a separate command from `build`.
func readSigningKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file", path)
	}

	der := block.Bytes
	//nolint:staticcheck // RFC 1423 is deprecated; see the doc comment.
	if x509.IsEncryptedPEMBlock(block) {
		Logger.Warn("the signing key uses RFC 1423 PEM encryption, whose key derivation is one round of MD5")
		fmt.Fprint(os.Stderr, "Enter passphrase: ")
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		//nolint:staticcheck // as above
		der, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", path, err)
		}
	}

	return parsePrivateKey(der, path)
}

func parsePrivateKey(der []byte, path string) (crypto.Signer, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s holds a %T, which cannot sign", path, parsed)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("%s holds no EC, PKCS#8 or PKCS#1 private key", path)
}

// signingCertificateOf reads the end-entity certificate out of a signed document's
// `x5c` header, for the commands that need it before they have an anchor.
func signingCertificateOf(signed []byte) (*x509.Certificate, error) {
	message, err := jws.Parse(signed)
	if err != nil {
		return nil, fmt.Errorf("parse the signed document: %w", err)
	}
	signatures := message.Signatures()
	if len(signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(signatures))
	}

	chain, ok := signatures[0].ProtectedHeaders().X509CertChain()
	if !ok || chain.Len() == 0 {
		return nil, fmt.Errorf("the signed document carries no x5c chain")
	}
	encoded, ok := chain.Get(0)
	if !ok {
		return nil, fmt.Errorf("the x5c chain is empty")
	}
	der, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode the x5c leaf: %w", err)
	}
	return x509.ParseCertificate(der)
}
