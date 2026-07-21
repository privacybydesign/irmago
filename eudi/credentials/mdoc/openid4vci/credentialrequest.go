package openid4vci

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"mdoc"
)

// ============================================================
// CREDENTIAL ENDPOINT — where a verified proof of possession finally
// becomes a real, signed mdoc
//
// Annex A §A.10's Credential Request example:
//
//	POST /credential
//	Content-Type: application/json
//	Authorization: Bearer <access_token>
//
//	{"proofs": {"jwt": ["<PoP JWT>", ...]}}
//
// access_token travels in the Authorization header, not the JSON body —
// nothing new to model for it here beyond what NewAccessToken/
// TokenResponse.AccessToken already provide (see tokenrequest.go).
//
// Annex A §A.10's Credential Response:
//
//	{"credentials": [{"credential": "..."}, ...]}
//
// The worked example doesn't state the credential string's encoding
// explicitly, so this package uses the same base64url(CBOR(...)) shape
// openid4vp's vptoken.go already established for mso_mdoc credentials on
// the presentation side (NewVPTokenJSON) — the standard OpenID4VP/VCI
// encoding for this format, not a guess specific to this file.
//
// IssueFromCredentialRequest is where this whole VCI effort actually
// pays off: it verifies the proof of possession first, and only then
// calls Issue() using the key VerifyProofOfPossession just PROVED the
// holder controls — replacing Issue()'s current holderPub parameter,
// which today is simply trusted with no such proof (see
// proofofpossession.go's file comment). It's a free function taking
// *mdoc.Issuer, not a method on it — Go doesn't allow defining methods
// on a type from another package, and Issuer must stay in the root mdoc
// package. Its body only ever touches Issuer through its already-exported
// Issue method, so this needed no changes to Issuer itself.
// ============================================================

// CredentialRequest is the Credential Endpoint's JSON request body —
// Annex A §A.10's {"proofs": {"jwt": [...]}} shape. JWT is an array
// (batch-capable per [OID4VCI]) even though this profile only ever
// issues one credential to one device key at a time.
type CredentialRequest struct {
	Proofs Proofs `json:"proofs"`
}

// Proofs carries the jwt proof type this profile uses — see
// proofofpossession.go for the JWT's own shape.
type Proofs struct {
	JWT []string `json:"jwt"`
}

// NewCredentialRequest builds a Credential Request carrying one or more
// proof-of-possession JWTs (see SignProofOfPossession).
func NewCredentialRequest(proofJWTs ...string) CredentialRequest {
	return CredentialRequest{Proofs: Proofs{JWT: proofJWTs}}
}

// SingleProof extracts the one proof JWT this profile expects — this
// package only ever issues to a single device key per request, unlike
// [OID4VCI]'s general batch-issuance case. Errors if the request carries
// zero or more than one proof, rather than silently picking the first.
func (r CredentialRequest) SingleProof() (string, error) {
	if len(r.Proofs.JWT) != 1 {
		return "", fmt.Errorf("expected exactly one proof jwt, got %d", len(r.Proofs.JWT))
	}
	return r.Proofs.JWT[0], nil
}

// CredentialResponse is the Credential Endpoint's JSON response body —
// Annex A §A.10's {"credentials": [{"credential": "..."}, ...]} shape.
type CredentialResponse struct {
	Credentials []IssuedCredential `json:"credentials"`
}

// IssuedCredential carries one issued credential, base64url(CBOR(MDoc))
// encoded — see file comment above.
type IssuedCredential struct {
	Credential string `json:"credential"`
}

// NewCredentialResponse wraps one or more issued mdocs into the
// Credential Response shape, CBOR-encoding and base64url-encoding each —
// the same encoding openid4vp's NewVPTokenJSON already uses for mso_mdoc
// credentials.
func NewCredentialResponse(mdocs ...mdoc.MDoc) (CredentialResponse, error) {
	creds := make([]IssuedCredential, len(mdocs))
	for i, m := range mdocs {
		encoded, err := cbor.Marshal(m)
		if err != nil {
			return CredentialResponse{}, fmt.Errorf("marshal mdoc %d: %w", i, err)
		}
		creds[i] = IssuedCredential{Credential: base64.RawURLEncoding.EncodeToString(encoded)}
	}
	return CredentialResponse{Credentials: creds}, nil
}

// SingleCredential decodes the one credential this profile expects back
// into an MDoc — the wallet-side counterpart to NewCredentialResponse.
// Errors if the response carries zero or more than one credential.
func (r CredentialResponse) SingleCredential() (mdoc.MDoc, error) {
	if len(r.Credentials) != 1 {
		return mdoc.MDoc{}, fmt.Errorf("expected exactly one credential, got %d", len(r.Credentials))
	}
	encoded, err := base64.RawURLEncoding.DecodeString(r.Credentials[0].Credential)
	if err != nil {
		return mdoc.MDoc{}, fmt.Errorf("base64url-decode credential: %w", err)
	}
	var m mdoc.MDoc
	if err := cbor.Unmarshal(encoded, &m); err != nil {
		return mdoc.MDoc{}, fmt.Errorf("decode mdoc: %w", err)
	}
	return m, nil
}

// IssueFromCredentialRequest is the full issuer-side handler for a
// Credential Request: extracts and verifies the proof of possession
// against expectedAud/expectedNonce, and — only once that succeeds —
// issues the mdoc using the key VerifyProofOfPossession just proved the
// holder controls, rather than an untrusted holderPub parameter. Rejects
// a request with the wrong number of proofs, or a proof that doesn't
// verify, before ever calling iss.Issue().
func IssueFromCredentialRequest(iss *mdoc.Issuer, req CredentialRequest, docType, namespace string, claims map[string]any, expectedAud, expectedNonce string) (*mdoc.MDoc, error) {
	proofJWT, err := req.SingleProof()
	if err != nil {
		return nil, fmt.Errorf("extract proof: %w", err)
	}
	holderPub, err := VerifyProofOfPossession(proofJWT, expectedAud, expectedNonce)
	if err != nil {
		return nil, fmt.Errorf("verify proof of possession: %w", err)
	}
	return iss.Issue(docType, namespace, claims, holderPub)
}
