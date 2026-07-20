package openid4vci

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// ============================================================
// NONCE ENDPOINT — issues a fresh c_nonce for proof-of-possession binding
//
// [OID4VCI] 1.0 §7 "Nonce Endpoint": "This endpoint allows a Client to
// acquire a fresh c_nonce value." A Credential Issuer that requires
// c_nonce values in proofs MUST offer this endpoint. The request is a
// bare POST /nonce with no parameters; the response is JSON carrying
// c_nonce — nothing else.
//
// An earlier OID4VCI draft put c_nonce in the token response instead (see
// tokenrequest.go's file comment) — the final 1.0 spec moved it here.
// Annex A never mentions this endpoint, or c_nonce at all, on the
// issuance side — it's silent on nonce mechanics entirely, unlike §A.5's
// explicit nonce requirement for OpenID4VP presentation. This file models
// the base [OID4VCI] mechanism anyway, since §A.4 defers issuance
// mechanics it doesn't respecify to [OID4VCI] itself, and a real
// proof-of-possession JWT (see proofofpossession.go) needs *some*
// anti-replay value to sign over.
// ============================================================

// NonceResponse is the Nonce Endpoint's JSON response — [OID4VCI] §7.
type NonceResponse struct {
	CNonce string `json:"c_nonce"`
}

// NewNonceResponse wraps a freshly generated c_nonce (see NewCNonce) in
// the Nonce Endpoint's response shape.
func NewNonceResponse(cNonce string) NonceResponse {
	return NonceResponse{CNonce: cNonce}
}

// NewCNonce generates a fresh opaque c_nonce — 16 random bytes,
// hex-encoded, the same construction NewPreAuthorizedCode/NewAccessToken
// already use. This is the anti-replay value the holder's
// proof-of-possession JWT (see proofofpossession.go) must sign over,
// playing the same role nonce plays in NewOpenID4VPSessionTranscript on
// the presentation side.
func NewCNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate c_nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}
