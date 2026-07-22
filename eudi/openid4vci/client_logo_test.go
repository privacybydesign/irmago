package openid4vci

import (
	"encoding/base64"
	"testing"

	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/stretchr/testify/require"
)

// fakeLogoBytes — a short opaque byte sequence used as the cached "logo image".
// The bytes don't need to form a valid PNG; convertToTrustedParty only round-trips
// them through the LogoManager and base64-encodes them for the wallet.
var fakeLogoBytes = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03}

func TestConvertToTrustedParty_PopulatesImageFromCache_HttpUri(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	const logoUri = "https://issuer.example.com/logo.png"
	logoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	require.NoError(t, logoManager.Save(logoUri, fakeLogoBytes))

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com/tenant",
		Display: metadata.CredentialIssuerDisplays{
			{
				Display: metadata.Display{Name: "Test Issuer"},
				Logo:    &metadata.RemoteImage{Uri: logoUri},
			},
		},
	}

	tp := client.convertToTrustedParty(m)

	require.NotNil(t, tp)
	require.Equal(t, "Test Issuer", tp.Name, "name carried through from display")
	require.Equal(t, "https://issuer.example.com/tenant", tp.Id,
		"Id must mirror CredentialIssuer — the log service uses it as the LogoManager key when persisting the issuer logo")
	require.NotNil(t, tp.Image, "issuer logo should be populated when cached for display.logo.uri")
	decoded, err := base64.StdEncoding.DecodeString(tp.Image.Base64)
	require.NoError(t, err)
	require.Equal(t, fakeLogoBytes, decoded)
}

func TestConvertToTrustedParty_PopulatesImageFromCache_DataUri(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	// The credenco issuer (and the spec) allows display.logo.uri to be a data
	// URI containing the inline image. The cache key is the URI itself, which
	// the LogoManager HMAC-hashes before persisting — long keys are safe.
	logoUri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(fakeLogoBytes)
	logoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	require.NoError(t, logoManager.Save(logoUri, fakeLogoBytes))

	m := &metadata.CredentialIssuerMetadata{
		Display: metadata.CredentialIssuerDisplays{
			{
				Display: metadata.Display{Name: "Test Issuer"},
				Logo:    &metadata.RemoteImage{Uri: logoUri},
			},
		},
	}

	tp := client.convertToTrustedParty(m)

	require.NotNil(t, tp)
	require.NotNil(t, tp.Image, "data URI logos must reach requestorInfo just like HTTP URIs do")
	decoded, err := base64.StdEncoding.DecodeString(tp.Image.Base64)
	require.NoError(t, err)
	require.Equal(t, fakeLogoBytes, decoded)
}

func TestConvertToTrustedParty_NoLogo_LeavesImageNil(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	m := &metadata.CredentialIssuerMetadata{
		Display: metadata.CredentialIssuerDisplays{
			{Display: metadata.Display{Name: "Logoless Issuer"}},
		},
	}

	tp := client.convertToTrustedParty(m)

	require.NotNil(t, tp)
	require.Nil(t, tp.Image, "no logo advertised → Image must stay nil")
}
