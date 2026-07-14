package mdoc

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// NewOpenID4VPSessionTranscript builds a real, spec-shaped SessionTranscript
// for an mdoc presented over OpenID4VP with response_mode=direct_post — the
// only mode the AV Blueprint's Annex A §A.6 OpenID4VP requirements allow
// (response_mode MUST be direct_post, never direct_post.jwt). Because the
// response is therefore never encrypted, there is no response-encryption
// key to thumbprint, hence the CBOR null in HandoverInfo below.
//
// Construction (matches Multipaz's vpSessionTranscript in
// org.multipaz.verification.VerificationUtil, cross-checked against the
// local clone at D:\Yivi\multipaz — the AV Blueprint itself only specifies
// the OpenID4VP request-level requirements, not this byte-level formula):
//
//	HandoverInfo      = [clientId, nonce, null, responseUri]
//	Handover          = ["OpenID4VPHandover", SHA-256(CBOR(HandoverInfo))]
//	SessionTranscript = [null, null, Handover]
//
// clientId, nonce, and responseUri must be the exact same values sent in
// the OpenID4VP Authorization Request (see openid4vp.AuthorizationRequest's
// ClientId/Nonce/ResponseUri fields in this repo's eudi/openid4vp package)
// — the holder and verifier each derive this independently, so any
// mismatch produces a different digest and deviceAuth's signature check
// fails.
//
// If Yivi ever needs response_mode=direct_post.jwt (encrypted responses),
// this function will need a jwkThumbprint parameter — the CBOR null below
// would become the SHA-256 JWK thumbprint of the verifier's response
// encryption public key instead.
func NewOpenID4VPSessionTranscript(clientId, nonce, responseUri string) (SessionTranscript, error) {
	handoverInfo := []any{clientId, nonce, nil, responseUri}
	handoverInfoBytes, err := cbor.Marshal(handoverInfo)
	if err != nil {
		return SessionTranscript{}, fmt.Errorf("marshal handoverInfo: %w", err)
	}
	digest := sha256.Sum256(handoverInfoBytes)

	return SessionTranscript{
		Handover: []any{"OpenID4VPHandover", digest[:]},
	}, nil
}
