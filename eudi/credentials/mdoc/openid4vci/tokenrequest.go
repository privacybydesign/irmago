package openid4vci

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
)

// ============================================================
// TOKEN ENDPOINT — the pre-authorized_code grant's token request/response
//
// Annex A §A.4 mandates the pre-authorized_code grant "as defined in
// Section 4.1.1 in [OID4VCI]", and §A.10 gives a worked example of the
// actual wire shapes this file matches:
//
//	POST /token
//	Content-Type: application/x-www-form-urlencoded
//
//	grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
//	&scope=proof_of_age
//	&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
//	&tx_code=493536
//
//	HTTP/1.1 200 OK
//	Content-Type: application/json
//
//	{"access_token": "czZCaGRSa3F0MzpnWDFmQmF0M2JW", "token_type": "Bearer", "expires_in": 86400}
//
// Per §A.5, there is no client authentication anywhere in this exchange
// (see credentialoffer.go's file comment) — the wallet's only credentials
// are the pre-authorized_code (from the Credential Offer) and tx_code
// (delivered out-of-band).
//
// No c_nonce here, deliberately: the final [OID4VCI] 1.0 spec moved nonce
// issuance out of the token response into a separate Nonce Endpoint (§7)
// — see nonceendpoint.go. An earlier OID4VCI draft did put c_nonce in the
// token response, which is why Annex A's silence on nonce mechanics
// entirely could be misread as an oversight rather than reflecting the
// current spec.
// ============================================================

// preAuthorizedCodeGrantType is the exact grant type URN this profile
// mandates in Annex A §A.4, and the value NewPreAuthorizedTokenRequest
// sends/ParsePreAuthorizedTokenRequest checks.
const preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// proofOfAgeScope is the token request's scope value in Annex A §A.10's
// worked example. Kept distinct from proofOfAgeCredentialConfigId
// (credentialoffer.go) even though both happen to be "proof_of_age" in
// this profile — scope and credential_configuration_ids are different
// OpenID4VCI concepts that only coincide in value here.
const proofOfAgeScope = "proof_of_age"

// bearerTokenType is the token_type value in Annex A §A.10's worked
// example — capitalized "Bearer", matched exactly.
const bearerTokenType = "Bearer"

// TokenResponse is the issuer's reply to a token request. Matches Annex A
// §A.10's worked example exactly — AccessToken, TokenType, ExpiresIn only.
// No c_nonce here: the final [OID4VCI] 1.0 spec moved nonce issuance to a
// separate Nonce Endpoint (§7) rather than the token response (an earlier
// draft's mechanic) — see nonceendpoint.go.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// NewTokenResponse builds the issuer's token response for a redeemed
// pre-authorized_code grant, with token_type fixed to "Bearer" matching
// Annex A §A.10's worked example.
func NewTokenResponse(accessToken string, expiresIn int) TokenResponse {
	return TokenResponse{
		AccessToken: accessToken,
		TokenType:   bearerTokenType,
		ExpiresIn:   expiresIn,
	}
}

// NewAccessToken generates a fresh opaque access token — 16 random bytes,
// hex-encoded, the same construction NewPreAuthorizedCode and this
// package's OpenID4VP state value already use.
func NewAccessToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate access_token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// NewPreAuthorizedTokenRequest builds the application/x-www-form-urlencoded
// body a wallet POSTs to the token endpoint to redeem a pre-authorized_code
// grant, matching Annex A §A.10's worked example field-for-field
// (grant_type, scope, pre-authorized_code, tx_code).
func NewPreAuthorizedTokenRequest(preAuthorizedCode, txCode string) string {
	values := url.Values{
		"grant_type":          {preAuthorizedCodeGrantType},
		"scope":               {proofOfAgeScope},
		"pre-authorized_code": {preAuthorizedCode},
		"tx_code":             {txCode},
	}
	return values.Encode()
}

// ParsePreAuthorizedTokenRequest is the issuer-side inverse of
// NewPreAuthorizedTokenRequest: decodes the form body and returns the
// pre-authorized_code and tx_code the wallet presented. Rejects a body
// with the wrong (or missing) grant_type, or a missing pre-authorized_code,
// rather than silently returning zero values — tx_code itself is returned
// as-is (including empty), the same way ParseDirectPostForm preserves an
// empty state rather than conflating it with "field absent".
func ParsePreAuthorizedTokenRequest(body string) (preAuthorizedCode, txCode string, err error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return "", "", fmt.Errorf("decode form body: %w", err)
	}
	if got := values.Get("grant_type"); got != preAuthorizedCodeGrantType {
		return "", "", fmt.Errorf("unexpected grant_type %q, expected %q", got, preAuthorizedCodeGrantType)
	}
	preAuthorizedCode = values.Get("pre-authorized_code")
	if preAuthorizedCode == "" {
		return "", "", fmt.Errorf("form body has no pre-authorized_code field")
	}
	return preAuthorizedCode, values.Get("tx_code"), nil
}
