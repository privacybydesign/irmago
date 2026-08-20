package eudi_jwt

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ErrAttestationKeyMismatch marks the one way an x5c present on a key is
// actively wrong rather than merely absent: the leaf certificate does not
// certify the key it is attached to. RFC 7517 §4.7 forbids that combination
// normatively, so a caller treats it as a broken document rather than as
// missing evidence.
var ErrAttestationKeyMismatch = errors.New("attesting certificate does not match the key it is attached to")

// AttestingCertificate returns the X.509 certificate a JWK carries in its x5c
// (RFC 7517 §4.7) — the certificate that vouches for the key, distinct from
// how the party authenticated. A DID document's verification method holds its
// attestation this way.
//
// Three outcomes, deliberately distinct:
//
//   - no x5c at all → (nil, nil): the key carries no attestation, which is not
//     an error. The party ranks by whatever other channels say about it.
//   - an x5c that does not hold up → (nil, err): unparseable, or a leaf whose
//     public key is not the key it is attached to (ErrAttestationKeyMismatch).
//     A document asserting a chain for a key it does not hold is malformed, and
//     the caller refuses it.
//   - a well-formed x5c → (leaf, nil): the end-entity certificate, its key
//     equal to the JWK's. Whether any anchor stands behind it is the trust
//     ladder's question, not this function's — key equality is the only
//     property checked here, because it is the only one that does not need the
//     wallet's anchors or clock.
//
// Validity window and revocation are deliberately left to the caller, which
// holds the verification context: they are the same CheckCertificateValidAt /
// CheckCertificateNotRevoked checks the x5c-header path applies, so the DID
// path and the certificate path share one policy.
func AttestingCertificate(key jwk.Key) (*x509.Certificate, error) {
	chain, ok := key.X509CertChain()
	if !ok || chain == nil || chain.Len() == 0 {
		return nil, nil // no x5c: no attestation, not an error
	}

	leaf, err := leafCertFromChain(chain)
	if err != nil {
		return nil, err
	}

	if err := assertKeyMatches(key, leaf); err != nil {
		return nil, err
	}
	return leaf, nil
}

// assertKeyMatches enforces RFC 7517 §4.7: the leaf's public key must be the
// key the x5c is attached to. The public keys are compared as their PKIX DER
// encodings, which is exact across key types and needs no per-algorithm
// Equal assertion.
func assertKeyMatches(key jwk.Key, leaf *x509.Certificate) error {
	var raw any
	if err := jwk.Export(key, &raw); err != nil {
		return fmt.Errorf("failed to export key for attestation binding check: %w", err)
	}
	keyDer, err := x509.MarshalPKIXPublicKey(raw)
	if err != nil {
		return fmt.Errorf("failed to encode key for attestation binding check: %w", err)
	}
	leafDer, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode leaf key for attestation binding check: %w", err)
	}
	if !bytes.Equal(keyDer, leafDer) {
		return ErrAttestationKeyMismatch
	}
	return nil
}
