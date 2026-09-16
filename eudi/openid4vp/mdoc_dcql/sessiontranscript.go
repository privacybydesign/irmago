package mdoc_dcql

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

// newOpenID4VPSessionTranscript builds a real, spec-shaped SessionTranscript
// for an mdoc presented over OpenID4VP through a URL (Annex B.2.6.1).
//
// This is one of the two handovers OpenID4VP defines; a request delivered
// through the Digital Credentials API signs the other one, see
// newDcApiSessionTranscript. Which one applies is decided by the transport, not
// by what the values look like, so the caller passes it explicitly: an
// origin-prefixed audience and an empty responseUri would otherwise be accepted
// here as an ordinary unencrypted URL session.
//
// Construction (matches Multipaz's vpSessionTranscript in
// org.multipaz.verification.VerificationUtil — the AV Blueprint itself only
// specifies the OpenID4VP request-level requirements, not this byte-level
// formula):
//
//	HandoverInfo      = [clientId, nonce, jwkThumbprint, responseUri]
//	Handover          = ["OpenID4VPHandover", SHA-256(CBOR(HandoverInfo))]
//	SessionTranscript = [null, null, Handover]
//
// clientId, nonce, and responseUri must be the exact same values sent in
// the OpenID4VP Authorization Request — the holder and verifier each derive
// this independently, so any mismatch produces a different digest and
// deviceAuth's signature check fails.
//
// jwkThumbprint is the SHA-256 JWK thumbprint of the verifier's response
// encryption public key, and nil when the response is sent unencrypted, which
// puts a CBOR null in that slot. Both cases are real: the AV Blueprint's crypto
// suite has the verifier publish a recipient encryption key and the response
// come back encrypted, while plenty of verifiers (and every one of this
// package's own tests) use plain direct_post. Getting this wrong is silent in
// the wallet and fatal at the verifier — the response transmits fine and the
// deviceAuth signature simply does not verify — so the caller must pass the
// thumbprint of the key the response is actually encrypted to, not merely one
// the verifier advertised.
func newOpenID4VPSessionTranscript(clientId, nonce, responseUri string, jwkThumbprint []byte) (mdoc.SessionTranscript, error) {
	handoverInfo := []any{clientId, nonce, encryptionKeyElement(jwkThumbprint), responseUri}
	handoverInfoBytes, err := cbor.Marshal(handoverInfo)
	if err != nil {
		return mdoc.SessionTranscript{}, fmt.Errorf("marshal handoverInfo: %w", err)
	}
	digest := sha256.Sum256(handoverInfoBytes)

	return mdoc.SessionTranscript{
		Handover: []any{"OpenID4VPHandover", digest[:]},
	}, nil
}

// newDcApiSessionTranscript builds the SessionTranscript for an mdoc presented
// through the W3C Digital Credentials API (Annex B.2.6.2):
//
//	HandoverInfo      = [origin, nonce, jwkThumbprint]
//	Handover          = ["OpenID4VPDCAPIHandover", SHA-256(CBOR(HandoverInfo))]
//	SessionTranscript = [null, null, Handover]
//
// Three differences from the URL flow, all of which change the digest: a
// different label, three elements rather than four (the response never travels
// to a response_uri, so there is none to sign over), and the bare origin the
// platform authenticated in place of the verifier's client identifier. The
// origin is the one the platform reports, not one the verifier claims -- for a
// signed request the two are reconciled earlier, by checking expected_origins.
//
// jwkThumbprint follows the same rule as in the URL flow: the thumbprint of the
// key the response is actually encrypted to, nil for dc_api (unencrypted),
// which puts a CBOR null in that slot.
//
// Matches Multipaz's OpenID4VP.kt for DRAFT_29, which is the draft the URL-flow
// handover here was written against.
func newDcApiSessionTranscript(origin, nonce string, jwkThumbprint []byte) (mdoc.SessionTranscript, error) {
	handoverInfo := []any{origin, nonce, encryptionKeyElement(jwkThumbprint)}
	handoverInfoBytes, err := cbor.Marshal(handoverInfo)
	if err != nil {
		return mdoc.SessionTranscript{}, fmt.Errorf("marshal dc api handoverInfo: %w", err)
	}
	digest := sha256.Sum256(handoverInfoBytes)

	return mdoc.SessionTranscript{
		Handover: []any{"OpenID4VPDCAPIHandover", digest[:]},
	}, nil
}

// encryptionKeyElement renders the third HandoverInfo element: the thumbprint
// when the response is encrypted, CBOR null when it is not. A nil []byte would
// encode as null anyway; spelling it out keeps the encoded shape independent of
// that detail, and keeps both handover variants agreeing on it.
func encryptionKeyElement(jwkThumbprint []byte) any {
	if len(jwkThumbprint) == 0 {
		return nil
	}
	return jwkThumbprint
}
