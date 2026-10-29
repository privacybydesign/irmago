package sdjwt

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
)

const (
	SdKey           string = "_sd"
	SdAlgKey        string = "_sd_alg"
	ConfirmationKey string = "cnf" // cnf is part of RFC7800, not part of SD-JWT spec. We could/should move this to a separate package, but for now we keep it here for convenience.
	TypHeaderKey    string = "typ"
	X5cHeaderKey    string = "x5c"
	KidHeaderKey    string = "kid"
	EllipsisKey     string = "..."

	KbJwtTyp string = "kb+jwt"
)

// RegisteredClaims holds the registered JWT claims and SD-JWT-specific
// claims (`_sd`, `_sd_alg`, `cnf`) that make up the core of an issuer-signed
// SD-JWT payload, independent of any SD-JWT VC extensions.
type RegisteredClaims struct {
	// OPTIONAL: The identifier of the Subject of the credential.
	// The Issuer MAY use it to provide the Subject identifier known by the Issuer.
	// There is no requirement for a binding to exist between sub and cnf claims
	Subject *string

	// OPTIONAL. As defined in Section 4.1.1 of [RFC7519] this claim explicitly indicates the Issuer of the credential
	// when it is not conveyed by other means (e.g., the subject of the end-entity certificate of an x5c header)
	// Although the claim is optional, the issuer should always be known in one way or another, either through the iss claim or through the x5c header.
	Issuer *string

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

// ExtractRegisteredClaims reads the registered claims from a verified
// issuer-signed JWT. `_sd_alg` defaults to SHA-256 when absent; Issuer is set
// only when the token carries `iss`.
func ExtractRegisteredClaims(token jwt.Token) (*RegisteredClaims, error) {
	claims := &RegisteredClaims{SdAlg: iana.SHA256}

	if token.Has(SdAlgKey) {
		h, _ := jwt.Get[string](token, SdAlgKey)
		if !iana.IsSupportedHashingAlgorithm(iana.HashingAlgorithm(h)) {
			return nil, fmt.Errorf("unsupported _sd_alg: %s", h)
		}
		claims.SdAlg = iana.HashingAlgorithm(h)
	}

	if sdRaw, err := jwt.Get[any](token, SdKey); err == nil {
		if claims.Sd, err = ParseSdField(sdRaw); err != nil {
			return nil, fmt.Errorf("failed to parse sd field: %v", err)
		}
	}

	if cnfRaw, err := jwt.Get[any](token, ConfirmationKey); err == nil {
		if claims.Confirm, err = ParseConfirmField(cnfRaw); err != nil {
			return nil, fmt.Errorf("failed to parse cnf field: %v", err)
		}
	}

	if sub, ok := token.Subject(); ok {
		claims.Subject = &sub
	}
	if iss, ok := token.Issuer(); ok {
		claims.Issuer = &iss
	}
	if exp, ok := token.Expiration(); ok {
		claims.Expiry = unixOrZero(exp)
	}
	if iat, ok := token.IssuedAt(); ok {
		claims.IssuedAt = unixOrZero(iat)
	}
	if nbf, ok := token.NotBefore(); ok {
		claims.NotBefore = unixOrZero(nbf)
	}
	return claims, nil
}

// unixOrZero returns 0 for the zero time (a missing claim), so that
// time.Time{}.Unix() (-62135596800) is not taken for a real timestamp.
func unixOrZero(t time.Time) *int64 {
	v := int64(0)
	if !t.IsZero() {
		v = t.Unix()
	}
	return &v
}

// VerifyTimes checks the nbf, iat and exp claims against now, allowing skew
// either way.
func (c *RegisteredClaims) VerifyTimes(now time.Time, skew time.Duration) error {
	nowUnix, skewSeconds := now.Unix(), int64(skew.Seconds())
	minSkewNow, maxSkewNow := nowUnix-skewSeconds, nowUnix+skewSeconds

	if c.NotBefore != nil && maxSkewNow < *c.NotBefore {
		return fmt.Errorf("verification before nbf: now: %v + skew: %v < nbf: %v", nowUnix, skewSeconds, *c.NotBefore)
	}
	if c.IssuedAt != nil && maxSkewNow < *c.IssuedAt {
		return fmt.Errorf("verification before issued at: %v + skew: %v < %v", nowUnix, skewSeconds, *c.IssuedAt)
	}
	if c.Expiry != nil && minSkewNow > *c.Expiry {
		return fmt.Errorf("verification after expiry of issuer signed jwt: %v - skew: %v > %v", nowUnix, skewSeconds, *c.Expiry)
	}
	return nil
}
