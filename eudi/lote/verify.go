package lote

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jws"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// signatureAlgorithms are the algorithms a signed list may use. The header
// names the algorithm and the certificate carries the key, so the allow-list is
// what keeps `alg` from being an attacker-chosen knob: without it a list could
// name a MAC algorithm and be "verified" against a public key everybody has.
var signatureAlgorithms = []string{
	"ES256", "ES384", "ES512",
	"PS256", "PS384", "PS512",
	"RS256", "RS384", "RS512",
}

// verifyList checks a signed list the way the profile requires — one signature,
// the profile's `typ`, an `x5c` chain that verifies against this list's anchors
// — and returns the list it carries.
//
// The certificate is checked before the signature: a chain that does not reach
// the anchors makes the signature irrelevant, and doing it in that order keeps
// an unanchored key from ever being handed to the verifier.
func verifyList(raw []byte, anchors eudi_jwt.X509VerificationContext) (*List, error) {
	if anchors == nil {
		return nil, fmt.Errorf("no trust anchors configured for this list")
	}

	msg, err := jws.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed trust list: %v", err)
	}
	// A JAdES-B-B trust list carries exactly one signature. Several would leave
	// the wallet picking which signer to believe.
	if len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(msg.Signatures()))
	}
	headers := msg.Signatures()[0].ProtectedHeaders()

	typ, ok := headers.Type()
	if !ok || typ != Typ {
		return nil, fmt.Errorf("invalid 'typ' header: %q, expected %q", typ, Typ)
	}

	alg, ok := headers.Algorithm()
	if !ok || !slices.Contains(signatureAlgorithms, alg.String()) {
		return nil, fmt.Errorf("unsupported 'alg' header: %q", alg)
	}

	signerCert, err := signerCertificate(headers)
	if err != nil {
		return nil, err
	}
	// The chain, its key usage and the revocation lists of its issuers: the
	// same check every other Yivi-anchored certificate goes through. No
	// hostname — a list signer is identified by its chain, not by where the
	// list happens to be hosted.
	if err := eudi_jwt.VerifyCertificate(anchors, signerCert, nil); err != nil {
		return nil, fmt.Errorf("trust list signing certificate is not trusted: %v", err)
	}

	payload, err := jws.Verify(raw, jws.WithKey(alg, signerCert.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("trust list signature does not verify: %v", err)
	}

	return parseList(payload)
}

// signerCertificate returns the end-entity certificate from the `x5c` header.
// A list must be signed with a certificate: `kid` and the DID resolution behind
// it are not accepted here, because a signer the wallet resolves over the
// network is not an anchor it can pin.
func signerCertificate(headers jws.Headers) (*x509.Certificate, error) {
	chain, ok := headers.X509CertChain()
	if !ok || chain == nil || chain.Len() == 0 {
		return nil, fmt.Errorf("signed trust list carries no 'x5c' header")
	}
	leaf, ok := chain.Get(0)
	if !ok {
		return nil, fmt.Errorf("'x5c' header carries no end-entity certificate")
	}
	der, err := base64.StdEncoding.DecodeString(string(leaf))
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'x5c' end-entity certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse 'x5c' end-entity certificate: %v", err)
	}
	return cert, nil
}
