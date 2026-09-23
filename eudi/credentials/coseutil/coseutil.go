// Package coseutil holds the COSE_Sign1 handling shared by the formats that
// verify one: the mdoc issuerAuth/deviceAuth signatures, and the CWT encoding of
// a Token Status List. It exists so both apply one allow-list and one decoder,
// and so mdoc and statuslist do not have to import each other.
package coseutil

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// MustDecMode builds a CBOR decoder from options written in code, which can
// only be wrong at build time, so it panics rather than returning the error.
func MustDecMode(opts cbor.DecOptions) cbor.DecMode {
	mode, err := opts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("invalid CBOR decoder options: %v", err))
	}
	return mode
}

// SignatureAlgorithms are the algorithms a COSE_Sign1 may be signed with.
//
// It is the set ISO/IEC 18013-5 permits for the two signatures an mdoc carries.
// 9.1.2.4 obliges a reader to handle the whole set when verifying, not a subset
// of its choosing — ES256, ES384, ES512 and EdDSA — and 9.1.3.6 restates the
// same list for device authentication. A CWT Status List Token for an mdoc
// ecosystem is held to the same list.
//
// cose.AlgorithmEdDSA and the deprecated cose.AlgorithmEd25519 are the same value
// (-8), so EdDSA appears once.
var SignatureAlgorithms = []cose.Algorithm{
	cose.AlgorithmES256,
	cose.AlgorithmES384,
	cose.AlgorithmES512,
	cose.AlgorithmEdDSA,
}

// VerifierFor builds a verifier for the algorithm the message itself declares,
// rather than for one assumed in advance. what names the signature in errors.
//
// Reading `alg` from the protected header is not a relaxation. The header is
// inside Sig_structure, so the algorithm is covered by the signature and cannot
// be substituted; go-cose re-checks that the verifier's algorithm matches it
// before verifying. What this replaces is a hardcoded ES256 verifier, which made
// every other permitted algorithm fail as an opaque mismatch — a conformant
// ES384 issuer looked like a broken one.
//
// The allow-list is what keeps this from being "whatever the document says":
// go-cose implements RSA-PSS and others that 18013-5 does not permit, and a
// signer is only authorised to use the four in SignatureAlgorithms.
func VerifierFor(msg *cose.Sign1Message, key crypto.PublicKey, what string) (cose.Verifier, error) {
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("%s has no usable alg in its protected header: %w", what, err)
	}
	if !slices.Contains(SignatureAlgorithms, alg) {
		return nil, fmt.Errorf(
			"%s is signed with %v, which is not one of the four algorithms ISO/IEC 18013-5 permits (ES256, ES384, ES512, EdDSA)",
			what, alg)
	}
	verifier, err := cose.NewVerifier(alg, key)
	if err != nil {
		// Reached when the algorithm and the key disagree — an ES384 header over a
		// P-256 certificate, or EdDSA over an ECDSA key. Naming both halves,
		// because either one could be the wrong half.
		return nil, fmt.Errorf("%s declares %v, which does not match its %T signing key: %w", what, alg, key, err)
	}
	return verifier, nil
}

// DecodeSign1 decodes either COSE_Sign1 serialization into the same message
// type.
//
// ISO 18013-5 puts the bare four-element array at issuerAuth and
// deviceSignature, which is what the mdoc package writes. Reading is
// deliberately more permissive than writing: go-cose's Sign1Message insists on
// the tag-18 prefix and UntaggedSign1Message refuses it, so accepting only one
// form would make the verifier reject real documents from whichever party
// disagrees with us. The tag is outside Sig_structure and carries no security
// meaning, so accepting both costs nothing — everything that matters is still
// checked against the signature afterwards.
func DecodeSign1(data []byte) (*cose.Sign1Message, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty COSE_Sign1")
	}
	// 0xd2 = tag 18, the COSE_Sign1_Tagged prefix.
	if data[0] == 0xd2 {
		var tagged cose.Sign1Message
		if err := tagged.UnmarshalCBOR(data); err != nil {
			return nil, err
		}
		return &tagged, nil
	}
	var untagged cose.UntaggedSign1Message
	if err := untagged.UnmarshalCBOR(data); err != nil {
		return nil, err
	}
	msg := cose.Sign1Message(untagged)
	return &msg, nil
}

// X5Chain parses the certificate chain in the message's x5chain header
// (label 33, RFC 9360), leaf first. RFC 9360 lets the header sit in either
// the protected or the unprotected bucket. When both carry one, the
// protected one wins, because the signature covers it.
//
// It only parses. Whether the chain is trusted is for the caller to decide,
// against its own trust anchors.
func X5Chain(msg *cose.Sign1Message) ([]*x509.Certificate, error) {
	if raw, ok := msg.Headers.Protected[cose.HeaderLabelX5Chain]; ok {
		return parseX5Chain(raw)
	}
	return UnprotectedX5Chain(msg)
}

// UnprotectedX5Chain is like X5Chain but only looks in the unprotected
// header. ISO/IEC 18013-5 requires the mdoc issuerAuth chain to sit there.
func UnprotectedX5Chain(msg *cose.Sign1Message) ([]*x509.Certificate, error) {
	raw, ok := msg.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		return nil, fmt.Errorf("no x5chain in header 33")
	}
	return parseX5Chain(raw)
}

// parseX5Chain accepts both encodings RFC 9360 allows: an array of
// certificates, and a single bare certificate.
func parseX5Chain(raw any) ([]*x509.Certificate, error) {
	var ders []any
	switch v := raw.(type) {
	case []any:
		ders = v
	case []byte:
		ders = []any{v}
	default:
		return nil, fmt.Errorf("x5chain wrong type: %T", raw)
	}
	if len(ders) == 0 {
		return nil, fmt.Errorf("x5chain is empty")
	}

	certs := make([]*x509.Certificate, 0, len(ders))
	for i, d := range ders {
		der, ok := d.([]byte)
		if !ok {
			return nil, fmt.Errorf("x5chain[%d] wrong type: %T", i, d)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse x5chain[%d]: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
