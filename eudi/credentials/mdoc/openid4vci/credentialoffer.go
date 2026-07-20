package openid4vci

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

// ============================================================
// CREDENTIAL OFFER — how an issuer hands a wallet the means to fetch a
// credential, over OpenID4VCI's pre-authorized_code grant
//
// The AV Blueprint's Annex A §A.4 mandates OpenID4VCI for issuance
// ("The Grant Type pre-authorized_code MUST be used as defined in Section
// 4.1.1 in [OID4VCI]") and §A.10 gives a worked example of exactly this
// shape: identity verification happens out-of-band (bank, notary, citizen
// service centre, or equivalent), then the user receives a Credential
// Offer — typically as a QR code — plus a tx_code: a short PIN/OTP
// delivered over a *separate* channel (e.g. email), proving they're the
// same person the identity check was done for. The wallet redeems both at
// the token endpoint (not modeled in this file) to get an access token,
// then presents that token plus a proof of possession at the credential
// endpoint to actually receive the mdoc.
//
// Annex A §A.5 states client authentication is out of scope for this
// profile, and §A.9 explains PAR (RFC 9126)/HAIP-style wallet attestation
// is deliberately, permanently not used — this profile has no
// trust-list infrastructure for it to authenticate against ("Using a
// self-signed certificate does not offer any value"). So unlike
// PAR-based profiles, trust here rests entirely on tx_code possession
// plus TLS/Web PKI — not on any pre-registered or attested wallet
// identity. Nothing in this file models client authentication as a
// result — there is none to model.
//
// authorization_code is Annex A's other mandated grant type, but isn't
// modeled here: it requires an actual interactive browser login redirect
// at the issuer, a different kind of thing than a pure wire-format
// struct, and has no AV-specific worked example to match against the way
// pre-authorized_code does. Phase 2, not this file.
// ============================================================

// proofOfAgeCredentialConfigId is the credential_configuration_ids value
// Annex A §A.10's worked example uses for this profile's one credential
// type.
const proofOfAgeCredentialConfigId = "proof_of_age"

// CredentialOffer is the object an issuer hands a wallet — as a QR code
// or deep link in practice — to start OpenID4VCI issuance. Matches Annex
// A §A.10's worked example field-for-field.
type CredentialOffer struct {
	CredentialIssuer           string   `json:"credential_issuer"`
	CredentialConfigurationIds []string `json:"credential_configuration_ids"`
	Grants                     Grants   `json:"grants"`
}

// Grants carries the pre-authorized_code grant under its full URN key.
// OpenID4VCI defines authorization_code as a sibling key of this same
// object — not modeled here, see the file comment above.
type Grants struct {
	PreAuthorized PreAuthorizedCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code"`
}

// PreAuthorizedCodeGrant carries the opaque pre-authorized_code the
// wallet must present at the token endpoint, plus the tx_code
// requirement describing the out-of-band PIN/OTP it must present
// alongside it.
type PreAuthorizedCodeGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
	TxCode            TxCode `json:"tx_code"`
}

// TxCode describes — but does not carry — the second-factor PIN/OTP the
// issuer delivers out-of-band (e.g. email, SMS), matching Annex A
// §A.10's worked example. The actual code value never appears in the
// offer; NewTxCode returns it separately for the issuer to deliver over
// its own out-of-band channel.
type TxCode struct {
	Length      int    `json:"length"`
	InputMode   string `json:"input_mode"`
	Description string `json:"description"`
}

// NewCredentialOffer builds the Credential Offer object for this
// profile's single credential_configuration_ids value ("proof_of_age"),
// carrying preAuthorizedCode and txCode under the pre-authorized_code
// grant.
func NewCredentialOffer(credentialIssuer, preAuthorizedCode string, txCode TxCode) CredentialOffer {
	return CredentialOffer{
		CredentialIssuer:           credentialIssuer,
		CredentialConfigurationIds: []string{proofOfAgeCredentialConfigId},
		Grants: Grants{
			PreAuthorized: PreAuthorizedCodeGrant{
				PreAuthorizedCode: preAuthorizedCode,
				TxCode:            txCode,
			},
		},
	}
}

// PreAuthorizedGrant extracts the pre-authorized_code grant from a
// received offer — the wallet-side counterpart to NewCredentialOffer.
// Errors if the offer carries no pre-authorized_code (e.g. a zero-value
// or malformed offer), rather than silently returning an empty grant.
func (o CredentialOffer) PreAuthorizedGrant() (PreAuthorizedCodeGrant, error) {
	if o.Grants.PreAuthorized.PreAuthorizedCode == "" {
		return PreAuthorizedCodeGrant{}, fmt.Errorf("credential offer has no pre-authorized_code grant")
	}
	return o.Grants.PreAuthorized, nil
}

// NewPreAuthorizedCode generates a fresh opaque pre-authorized_code — 16
// random bytes, hex-encoded, the same construction this package already
// uses for the OpenID4VP state value (see cmd/demo/main.go). Nothing
// about its value is meaningful to the wallet; it's a single-use lookup
// key the issuer uses to recall which identity-verification session this
// offer belongs to.
func NewPreAuthorizedCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate pre-authorized_code: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// NewTxCode generates a fresh random numeric tx_code of the given length
// (Annex A §A.10's worked example uses length 4) and the TxCode metadata
// describing it. Returns the code itself — which the issuer must deliver
// to the user over its own out-of-band channel (e.g. email, matching
// description) before or alongside handing over the Credential Offer —
// separately from the offer-embedded metadata, since the code value
// itself never appears in the offer.
func NewTxCode(length int, description string) (code string, meta TxCode, err error) {
	if length <= 0 {
		return "", TxCode{}, fmt.Errorf("tx_code length must be positive, got %d", length)
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", TxCode{}, fmt.Errorf("generate tx_code: %w", err)
	}
	code = fmt.Sprintf("%0*d", length, n)
	return code, TxCode{Length: length, InputMode: "numeric", Description: description}, nil
}
