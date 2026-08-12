package eudicli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"slices"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
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
		if err := checkSigningCertificate(leaf, document.LoTE.SchemeInformation); err != nil {
			return err
		}

		key, err := readSigningKey(keyPath)
		if err != nil {
			return err
		}
		alg, err := signatureAlgorithm(key)
		if err != nil {
			return err
		}

		signed, err := signDocument(document, chain, key, alg)
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

// signDocument produces the compact JAdES-B-B. Baseline B means everything needed
// to validate is in the protected header: no timestamps, no archival material.
func signDocument(
	document lote.Document,
	chain []*x509.Certificate,
	key crypto.Signer,
	alg jwa.SignatureAlgorithm,
) ([]byte, error) {
	payload, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}

	// RFC 7515 x5c is *standard* base64, not base64url — one of the two places a
	// hand-rolled signer characteristically diverges from a library one.
	x5c := &cert.Chain{}
	for _, certificate := range chain {
		if err := x5c.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw))); err != nil {
			return nil, err
		}
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, lote.LoteTyp); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.X509CertChainKey, x5c); err != nil {
		return nil, err
	}

	return jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
}

// checkSigningCertificate enforces clause 6.8.0 plus the key usage the wallet
// checks. The DN rules bind the certificate to the scheme it signs for: without
// them any certificate under the anchor could sign any scheme's list.
func checkSigningCertificate(leaf *x509.Certificate, scheme lote.SchemeInformation) error {
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("signing certificate does not carry the digitalSignature key usage")
	}

	if scheme.SchemeTerritory == "" {
		return fmt.Errorf("the document declares no SchemeTerritory, so the certificate's country cannot be checked")
	}
	if !slices.Contains(leaf.Subject.Country, scheme.SchemeTerritory) {
		return fmt.Errorf(
			"clause 6.8.0: certificate subject country %v does not include the scheme territory %q",
			leaf.Subject.Country, scheme.SchemeTerritory)
	}

	operatorNames := make([]string, 0, len(scheme.SchemeOperatorName))
	for _, name := range scheme.SchemeOperatorName {
		operatorNames = append(operatorNames, name)
	}
	if len(operatorNames) == 0 {
		return fmt.Errorf("the document declares no SchemeOperatorName, so the certificate's organization cannot be checked")
	}
	for _, organization := range leaf.Subject.Organization {
		if slices.Contains(operatorNames, organization) {
			return nil
		}
	}
	return fmt.Errorf(
		"clause 6.8.0: certificate subject organization %v is not one of the scheme operator names %v",
		leaf.Subject.Organization, operatorNames)
}

// verificationAnchors builds the pool the freshly signed document is checked
// against, reporting whether the chain is genuinely being verified.
//
// With no anchor the leaf stands in as its own root, which still exercises the
// signature, the typ guard, the single-signature rule and the payload — but says
// nothing about whether a wallet would trust the chain. The caller warns.
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

// readCertificateChain reads one or more concatenated PEM certificates, or a
// single raw DER certificate, leaf first.
func readCertificateChain(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var chain []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		chain = append(chain, certificate)
	}

	if len(chain) == 0 {
		// No PEM at all: try raw DER, so a .der file works without conversion.
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
// operators have such files, but its key derivation is one round of MD5 and Go
// has deprecated it. For a key that can vouch for any party at the top rung it is
// a stopgap: the intended end state is a key that never leaves hardware, which is
// why `sign` is a separate command from `build`.
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

// signatureAlgorithm picks the JWS algorithm the key requires. The curve decides
// it for an EC key, so there is nothing for an operator to choose — and nothing
// to get wrong.
func signatureAlgorithm(key crypto.Signer) (jwa.SignatureAlgorithm, error) {
	switch typed := key.(type) {
	case *ecdsa.PrivateKey:
		switch typed.Curve {
		case elliptic.P256():
			return jwa.ES256(), nil
		case elliptic.P384():
			return jwa.ES384(), nil
		case elliptic.P521():
			return jwa.ES512(), nil
		}
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported EC curve %s", typed.Curve.Params().Name)
	case *rsa.PrivateKey:
		return jwa.RS256(), nil
	}
	return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported key type %T", key)
}

// signingCertificateOf reads the end-entity certificate out of a signed
// document's `x5c` header, for the commands that need it before they have an
// anchor to check it against.
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
