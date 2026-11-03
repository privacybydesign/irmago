package openid4vp

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/stretchr/testify/require"
)

// A relying party authorized for one VCDM attribute must not get the whole
// credentialSubject by asking for the root: the wallet expands such a path to
// every subject claim.
func TestVcdmQueryAuthorization(t *testing.T) {
	const credentialType = "https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential"
	validator := scheme.SchemeQueryValidator{
		RelyingParty: &scheme.RelyingParty{
			AuthorizedQueryableAttributeSets: []scheme.AuthorizedAttributeSet{
				{Credential: credentialType, Attributes: []string{"email"}},
			},
		},
	}
	validate := func(paths ...[]any) error {
		claims := make([]dcql.Claim, len(paths))
		for i, path := range paths {
			claims[i] = dcql.Claim{Path: path}
		}
		query := dcql.DcqlQuery{Credentials: []dcql.CredentialQuery{{
			Format: "vc+sd-jwt",
			Meta:   &dcql.Meta{VctValues: []string{credentialType}},
			Claims: claims,
		}}}
		return validator.ValidateCredentialQueries(dcqlQueryToCredentialQueryInfos(query))
	}

	require.NoError(t, validate([]any{"credentialSubject", "email"}),
		"the authorized attribute, under its credentialSubject root")
	require.Error(t, validate([]any{"credentialSubject"}),
		"the whole subject is not authorized by one attribute")
	require.Error(t, validate([]any{"credentialSubject", nil}),
		"nor is every subject of the credential")
	require.Error(t, validate([]any{"credentialSubject", "email"}, []any{"credentialSubject", "given_name"}),
		"an attribute outside the set is still refused")
}
