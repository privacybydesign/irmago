package openid4vci

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

// In dark mode the holder verification path does not surface the issuer's
// certificate, so no channel has anything to say about an OpenID4VCI issuer and
// it ranks low. What matters here is that a rung reaches the permission screen
// at all, on the issuer and on every credential it offers.

func TestConvertToTrustedParty_RanksTheIssuer(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		Display:          metadata.CredentialIssuerDisplays{{Display: metadata.Display{Name: "Test Issuer"}}},
	}

	tp := client.convertToTrustedParty(m, "en", trust.NewView(nil))

	require.Equal(t, clientmodels.TrustLevel_Low, tp.TrustLevel)
	require.False(t, tp.TrustLevel.IsTrusted(), "a low issuer gets no trusted marker")
}

func TestConvertToCredentialInfoList_OfferedCredentialsCarryTheIssuerLevel(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{
			"credential-config-1": {
				Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
				VerifiableCredentialType: "https://issuer.example.com/vct/email",
				CredentialMetadata: &metadata.CredentialMetadata{
					Display: metadata.CredentialDisplays{{Display: metadata.Display{Name: "Email"}}},
				},
			},
		},
	}
	issuer := &clientmodels.TrustedParty{Name: "Test Issuer", TrustLevel: clientmodels.TrustLevel_Medium}

	creds, err := client.convertToCredentialInfoList([]string{"credential-config-1"}, m, issuer, "en")

	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.Equal(t, "Test Issuer", creds[0].Issuer.Name)
	require.Equal(t, clientmodels.TrustLevel_Medium, creds[0].Issuer.TrustLevel,
		"the level the session decided must reach every offered credential")
}
