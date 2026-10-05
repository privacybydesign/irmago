package sdjwtvc

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// SdJwtVc represents an encoded SD-JWT VC as a string, be it with or without disclosures, without a key binding jwt.
// It is a defined type (not an alias) over sdjwt.SdJwt so that the compiler flags any place a raw
// SD-JWT is used where an SD-JWT VC is expected.
type SdJwtVc sdjwt.SdJwt

// SdJwtVcKb represents an encoded SD-JWT VC as a string, be it with or without disclosures, potentially
// with a key binding jwt (which needs to be determined by processing). See SdJwtVc for why this is a
// defined type rather than an alias.
type SdJwtVcKb sdjwt.SdJwtKb

const (
	VerifiableCredentialTypeKey          string = "vct"
	VerifiableCredentialTypeIntegrityKey string = "vct#integrity"
	StatusKey                            string = "status"
	FederationKey                        string = "fed"

	SdJwtVcTyp        string = "dc+sd-jwt"
	SdJwtVcTyp_Legacy string = "vc+sd-jwt"
)

// LookupVctIntegrityClaim returns the vct#integrity claim string from the
// processed SD-JWT payload if present and a non-empty string. A claim present
// with a non-string (or empty) value is an error: the JWT shape for
// vct#integrity is defined as a string, so a non-string here is either an
// issuer bug or a downgrade attempt that shouldn't silently bypass integrity
// verification.
func LookupVctIntegrityClaim(payload sdjwt.ProcessedPayload) (string, bool, error) {
	raw, ok := payload[VerifiableCredentialTypeIntegrityKey]
	if !ok {
		return "", false, nil
	}
	str, ok := raw.(string)
	if !ok {
		return "", false, fmt.Errorf("claim %q has non-string value", VerifiableCredentialTypeIntegrityKey)
	}
	if str == "" {
		return "", false, fmt.Errorf("claim %q is an empty string", VerifiableCredentialTypeIntegrityKey)
	}
	return str, true, nil
}

// StandardClaims contains JWT-registered and SD-JWT-specific claims that are not user data.
// Use this to distinguish issuer/protocol metadata from actual credential attributes.
var StandardClaims = map[string]struct{}{
	jwt.IssuerKey:               {},
	jwt.SubjectKey:              {},
	jwt.IssuedAtKey:             {},
	jwt.NotBeforeKey:            {},
	jwt.ExpirationKey:           {},
	sdjwt.ConfirmationKey:       {},
	sdjwt.SdKey:                 {},
	sdjwt.SdAlgKey:              {},
	FederationKey:               {},
	VerifiableCredentialTypeKey: {},
	StatusKey:                   {},
}
