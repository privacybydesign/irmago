package sdjwtvc

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/stretchr/testify/require"
)

// is `iss` field is required
func TestNoIssuerLinkIsErr(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		RegisteredClaims: sdjwt.RegisteredClaims{
			Subject:   "subject",
			Expiry:    nil,
			IssuedAt:  nil,
			NotBefore: nil,
			Issuer:    "",
		},
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)
	require.Error(t, err)
}

// the `iss` field of the issuer signed jwt is required to have a valid https link
func TestNoHttpsIssuerIsErr(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		RegisteredClaims: sdjwt.RegisteredClaims{
			Subject:   "subject",
			Expiry:    nil,
			IssuedAt:  nil,
			NotBefore: nil,
			Issuer:    "http://invalid.com",
		},
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)
	require.Error(t, err)
}

func TestIssuerSignedJwtPayloadToJson(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		RegisteredClaims: sdjwt.RegisteredClaims{
			Subject:   "subject",
			Expiry:    nil,
			IssuedAt:  nil,
			NotBefore: nil,
			Issuer:    "https://example.com",
		},
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
	}

	json, err := IssuerSignedJwtPayload_ToJson(payload)

	require.NoError(t, err)

	values := jsonToMap(t, json)

	require.Equal(t, values[sdjwt.Key_Subject], "subject")
	require.Equal(t, values[Key_VerifiableCredentialType], "pbdf.sidn-pbdf.email")
	require.Equal(t, values[sdjwt.Key_Issuer], "https://example.com")

	require.NotContains(t, values, sdjwt.Key_Sd)
	require.NotContains(t, values, sdjwt.Key_SdAlg)
	require.NotContains(t, values, sdjwt.Key_Confirmationkey)
}
