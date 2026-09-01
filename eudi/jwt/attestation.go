package eudi_jwt

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// ErrAttestationKeyMismatch marks the one way an x5c present on a key is actively
// wrong rather than merely absent: the leaf does not certify the key it is
// attached to, which RFC 7517 §4.7 forbids. A broken document, not missing
// evidence.
var ErrAttestationKeyMismatch = errors.New("attesting certificate does not match the key it is attached to")

// AttestingCertificate returns the X.509 certificate a JWK carries in its x5c
// (RFC 7517 §4.7): the certificate that vouches for the key, distinct from how
// the party authenticated. A DID document's verification method holds its
// attestation this way.
//
// Three distinct outcomes:
//
//   - no x5c → (nil, nil): no attestation, which is not an error.
//   - an x5c that does not hold up → (nil, err): unparseable, or a leaf whose
//     public key is not the key it is attached to (ErrAttestationKeyMismatch).
//   - a well-formed x5c → (leaf, nil): the end-entity certificate, its key equal
//     to the JWK's.
//
// Key equality is the only property checked here, being the only one that needs
// neither the wallet's anchors nor its clock. Validity window and revocation are
// the caller's CheckCertificateValidAt / CheckCertificateNotRevoked, so the DID
// path and the x5c-header path share one policy.
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

// assertKeyMatches enforces RFC 7517 §4.7: the leaf's public key must be the key
// the x5c is attached to. Compared as PKIX DER, which is exact across key types.
func assertKeyMatches(key jwk.Key, leaf *x509.Certificate) error {
	raw, err := jwk.Export[any](key)
	if err != nil {
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
