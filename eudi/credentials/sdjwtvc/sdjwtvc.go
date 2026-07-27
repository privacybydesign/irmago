package sdjwtvc

import "fmt"

const (
	Key_VerifiableCredentialType          string = "vct"
	Key_VerifiableCredentialTypeIntegrity string = "vct#integrity"
	Key_Status                            string = "status"
	Key_Federation                        string = "fed"

	SdJwtVcTyp        string = "dc+sd-jwt"
	SdJwtVcTyp_Legacy string = "vc+sd-jwt"
)

// LookupVctIntegrityClaim returns the vct#integrity claim string from the
// processed SD-JWT payload if present and a non-empty string. A claim present
// with a non-string (or empty) value is an error: the JWT shape for
// vct#integrity is defined as a string, so a non-string here is either an
// issuer bug or a downgrade attempt that shouldn't silently bypass integrity
// verification.
func LookupVctIntegrityClaim(payload ProcessedSdJwtPayload) (string, bool, error) {
	raw, ok := payload[Key_VerifiableCredentialTypeIntegrity]
	if !ok {
		return "", false, nil
	}
	str, ok := raw.(string)
	if !ok {
		return "", false, fmt.Errorf("claim %q has non-string value", Key_VerifiableCredentialTypeIntegrity)
	}
	if str == "" {
		return "", false, fmt.Errorf("claim %q is an empty string", Key_VerifiableCredentialTypeIntegrity)
	}
	return str, true, nil
}

// StandardClaims contains JWT-registered and SD-JWT-specific claims that are not user data.
// Use this to distinguish issuer/protocol metadata from actual credential attributes.
var StandardClaims = map[string]struct{}{
	Key_Issuer:                   {},
	Key_IssuedAt:                 {},
	Key_ExpiryTime:               {},
	Key_NotBefore:                {},
	Key_Subject:                  {},
	Key_VerifiableCredentialType: {},
	Key_Confirmationkey:          {},
	Key_Status:                   {},
	Key_Sd:                       {},
	Key_SdAlg:                    {},
	Key_Federation:               {},
}
