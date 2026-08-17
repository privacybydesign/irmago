package sdjwtvc

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/stretchr/testify/require"
)

// is `iss` field is required
func TestNoIssuerLinkIsErr(t *testing.T) {
	sub := "subject"
	iss := ""
	payload := IssuerSignedJwtPayload{
		RegisteredClaims: sdjwt.RegisteredClaims{
			Subject:   &sub,
			Expiry:    nil,
			IssuedAt:  nil,
			NotBefore: nil,
			Issuer:    &iss,
		},
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)
	require.Error(t, err)
}

// the `iss` field of the issuer signed jwt is required to have a valid https link
func TestNoHttpsIssuerIsErr(t *testing.T) {
	sub := "subject"
	iss := "http://invalid.com"
	payload := IssuerSignedJwtPayload{
		RegisteredClaims: sdjwt.RegisteredClaims{
			Subject:   &sub,
			Expiry:    nil,
			IssuedAt:  nil,
			NotBefore: nil,
			Issuer:    &iss,
		},
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)
	require.Error(t, err)
}

func TestIssuerSignedJwtPayloadToJson(t *testing.T) {
	sub := "subject"
	iss := "https://example.com"
	payload := IssuerSignedJwtPayload{
		RegisteredClaims: sdjwt.RegisteredClaims{
			Subject:   &sub,
			Expiry:    nil,
			IssuedAt:  nil,
			NotBefore: nil,
			Issuer:    &iss,
		},
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
	}

	json, err := IssuerSignedJwtPayload_ToJson(payload)

	require.NoError(t, err)

	values := jsonToMap(t, json)

	require.Equal(t, values[VerifiableCredentialTypeKey], "pbdf.sidn-pbdf.email")
	require.Equal(t, values[jwt.IssuerKey], "https://example.com")
	require.Equal(t, values[jwt.SubjectKey], "subject")

	require.NotContains(t, values, sdjwt.SdKey)
	require.NotContains(t, values, sdjwt.SdAlgKey)
	require.NotContains(t, values, sdjwt.ConfirmationKey)
}

// Now that iss, sub, iat and exp are all optional pointers, an absent claim must
// be left out of the JSON entirely. Serialising it as an explicit null produces
// a JWT that no compliant parser will accept — jwx rejects `"exp": null` with
// "invalid value for NumericDate", and a null `iss`/`sub` is not a string.
func TestIssuerSignedJwtPayloadToJson_AbsentOptionalClaimsAreOmitted(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		RegisteredClaims:         sdjwt.RegisteredClaims{},
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
	}

	json, err := IssuerSignedJwtPayload_ToJson(payload)
	require.NoError(t, err)

	values := jsonToMap(t, json)

	require.Equal(t, values[VerifiableCredentialTypeKey], "pbdf.sidn-pbdf.email")
	require.NotContains(t, values, jwt.IssuerKey)
	require.NotContains(t, values, jwt.SubjectKey)
	require.NotContains(t, values, jwt.IssuedAtKey)
	require.NotContains(t, values, jwt.ExpirationKey)
}
