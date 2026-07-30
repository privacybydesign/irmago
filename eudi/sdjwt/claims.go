package sdjwt

import iana "github.com/privacybydesign/irmago/internal/crypto/hashing"

const (
	Key_Subject         string = "sub"
	Key_ExpiryTime      string = "exp"
	Key_IssuedAt        string = "iat"
	Key_Issuer          string = "iss"
	Key_Sd              string = "_sd"
	Key_SdAlg           string = "_sd_alg"
	Key_Confirmationkey string = "cnf"
	Key_NotBefore       string = "nbf"
	Key_Typ             string = "typ"
	Key_X5c             string = "x5c"
	Key_Kid             string = "kid"
	Key_Ellipsis        string = "..."

	KbJwtTyp string = "kb+jwt"
)

// RegisteredClaims holds the registered JWT claims and SD-JWT-specific
// claims (`_sd`, `_sd_alg`, `cnf`) that make up the core of an issuer-signed
// SD-JWT payload, independent of any SD-JWT VC extensions.
type RegisteredClaims struct {
	// OPTIONAL: The identifier of the Subject of the credential.
	// The Issuer MAY use it to provide the Subject identifier known by the Issuer.
	// There is no requirement for a binding to exist between sub and cnf claims
	Subject string

	// OPTIONAL. As defined in Section 4.1.1 of [RFC7519] this claim explicitly indicates the Issuer of the credential
	// when it is not conveyed by other means (e.g., the subject of the end-entity certificate of an x5c header)
	Issuer string

	// OPTIONAL: list of hashed -> base64url encoded disclosures
	// hashing algorithm is defined by `_sd_alg` field
	// is allowed to be omitted, and is not allowed to be empty (should be omitted in that case)
	Sd []HashedDisclosure

	// OPTIONAL: hashing algorithm to be used for the disclosure hashes in `_sd` and the hash over
	// the complete SD-JWT that can be found in the key binding JWT
	SdAlg iana.HashingAlgorithm

	// OPTIONAL: Public key (JWK or kid with did:jwk method) of the holder, which can be used to verify the key binding jwt
	Confirm *CnfField

	// OPTIONAL: expiry time, must not be accepted after this moment
	Expiry *int64

	// OPTIONAL: time of issuance
	IssuedAt *int64

	// OPTIONAL: The time before which the credential MUST NOT be accepted before validating
	NotBefore *int64
}
