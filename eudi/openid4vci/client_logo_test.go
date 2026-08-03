package openid4vci

import (
	"encoding/base64"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

// fakeLogoBytes — a short opaque byte sequence used as the cached "logo image".
// The bytes don't need to form a valid PNG; convertToTrustedParty only round-trips
// them through the LogoManager and base64-encodes them for the wallet.
var fakeLogoBytes = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x01, 0x02, 0x03}

// listedIssuerView is the recognized-list channel granting every issuer it is
// asked about, on an entry that names logoURI as the party's curated logo.
//
// It is what the logo tests below evaluate against, because a curated entry is
// the only source that can put a logo on the issuance screen: an issuer's own
// metadata logo is the issuer's own word and never reaches the user. The entry
// deliberately carries no name, so the name each test asserts is still the one
// resolved from the issuer's display metadata.
type listedIssuerView struct {
	logoURI string
}

func (v listedIssuerView) Issuer(trust.Evidence) trust.Verdict {
	return trust.Verdict{
		Level: clientmodels.TrustLevel_Medium,
		Listing: &trust.Listing{
			ListId:  "urn:yivi:trustlist:openid4vci-test",
			LogoURI: v.logoURI,
		},
	}
}

func (v listedIssuerView) Verifier(ev trust.Evidence) trust.Verdict { return v.Issuer(ev) }

func TestConvertToTrustedParty_PopulatesImageFromCache_HttpUri(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	const logoUri = "https://issuer.example.com/logo.png"
	logoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	require.NoError(t, logoManager.Save(logoUri, fakeLogoBytes, "image/png"))

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com/tenant",
		Display: metadata.CredentialIssuerDisplays{
			{
				Display: metadata.Display{Name: "Test Issuer"},
				Logo:    &metadata.RemoteImage{Uri: logoUri},
			},
		},
	}

	tp := client.convertToTrustedParty(m, "en", listedIssuerView{logoURI: logoUri})

	require.NotNil(t, tp)
	require.Equal(t, "Test Issuer", tp.Name, "name carried through from display")
	require.Equal(t, "https://issuer.example.com/tenant", tp.Id,
		"Id must mirror CredentialIssuer — the log service uses it as the LogoManager key when persisting the issuer logo")
	require.NotNil(t, tp.Image, "the logo the listing names should be populated once cached")
	decoded, err := base64.StdEncoding.DecodeString(tp.Image.Base64)
	require.NoError(t, err)
	require.Equal(t, fakeLogoBytes, decoded)
	require.NotNil(t, tp.Image.MimeType, "MIME type stored alongside the logo must reach the wallet")
	require.Equal(t, "image/png", *tp.Image.MimeType)
}

// Regression test for privacybydesign/irmamobile#674: SVG logos were cached
// without their MIME type, so the wallet had no way to tell it should render
// them with an SVG renderer and they came out blank.
func TestConvertToTrustedParty_PreservesSvgMimeType(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	const logoUri = "https://issuer.example.com/logo.svg"
	svgBytes := []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)
	logoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	require.NoError(t, logoManager.Save(logoUri, svgBytes, "image/svg+xml"))

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com/tenant",
		Display: metadata.CredentialIssuerDisplays{
			{
				Display: metadata.Display{Name: "Test Issuer"},
				Logo:    &metadata.RemoteImage{Uri: logoUri},
			},
		},
	}

	tp := client.convertToTrustedParty(m, "en", listedIssuerView{logoURI: logoUri})

	require.NotNil(t, tp)
	require.NotNil(t, tp.Image)
	require.NotNil(t, tp.Image.MimeType)
	require.Equal(t, "image/svg+xml", *tp.Image.MimeType)
}

// Logos cached by an older version of the app have no stored MIME type;
// they must still load, with MimeType left nil.
func TestConvertToTrustedParty_NoMimeType_LeavesMimeTypeNil(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	const logoUri = "https://issuer.example.com/logo.png"
	logoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	require.NoError(t, logoManager.Save(logoUri, fakeLogoBytes, ""))

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com/tenant",
		Display: metadata.CredentialIssuerDisplays{
			{
				Display: metadata.Display{Name: "Test Issuer"},
				Logo:    &metadata.RemoteImage{Uri: logoUri},
			},
		},
	}

	tp := client.convertToTrustedParty(m, "en", listedIssuerView{logoURI: logoUri})

	require.NotNil(t, tp)
	require.NotNil(t, tp.Image)
	require.Nil(t, tp.Image.MimeType)
}

func TestConvertToTrustedParty_PopulatesImageFromCache_DataUri(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	// The credenco issuer (and the spec) allows display.logo.uri to be a data
	// URI containing the inline image. The cache key is the URI itself, which
	// the LogoManager HMAC-hashes before persisting — long keys are safe.
	logoUri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(fakeLogoBytes)
	logoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	require.NoError(t, logoManager.Save(logoUri, fakeLogoBytes, "image/png"))

	m := &metadata.CredentialIssuerMetadata{
		Display: metadata.CredentialIssuerDisplays{
			{
				Display: metadata.Display{Name: "Test Issuer"},
				Logo:    &metadata.RemoteImage{Uri: logoUri},
			},
		},
	}

	tp := client.convertToTrustedParty(m, "en", listedIssuerView{logoURI: logoUri})

	require.NotNil(t, tp)
	require.NotNil(t, tp.Image, "data URI logos must reach the wallet just like HTTP URIs do")
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

	tp := client.convertToTrustedParty(m, "en", listedIssuerView{})

	require.NotNil(t, tp)
	require.Nil(t, tp.Image, "no logo vouched for → Image must stay nil")
}

func TestConvertToTrustedParty_TheIssuersOwnLogoDoesNotReachTheWallet(t *testing.T) {
	// An issuer's metadata logo is the issuer's own word about who it is, which
	// is the whole of an impersonation. With nobody vouching for the party, the
	// screen shows its name and its identifier and no picture.
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	const logoUri = "https://issuer.example.com/logo.png"
	logoManager := client.Configuration.Storage.FileSystem().Issuers().LogoManager()
	require.NoError(t, logoManager.Save(logoUri, fakeLogoBytes, "image/png"))

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com/tenant",
		Display: metadata.CredentialIssuerDisplays{
			{
				Display: metadata.Display{Name: "Test Issuer"},
				Logo:    &metadata.RemoteImage{Uri: logoUri},
			},
		},
	}

	tp := client.convertToTrustedParty(m, "en", trust.CertificateView{})

	require.Equal(t, clientmodels.TrustLevel_Low, tp.TrustLevel)
	require.Equal(t, "Test Issuer", tp.Name, "the name it chose is the user's to judge, under the warning")
	require.Equal(t, "https://issuer.example.com/tenant", tp.Id)
	require.Nil(t, tp.Image)
}

func TestConvertToTrustedParty_TheCuratedNameOutranksTheIssuersOwn(t *testing.T) {
	s, client := createOpenID4VCiClientForTesting(t)
	defer s.Close()

	m := &metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com/tenant",
		Display:          metadata.CredentialIssuerDisplays{{Display: metadata.Display{Name: "Whatever BV"}}},
	}

	tp := client.convertToTrustedParty(m, "en", listedIssuerNamedView{name: "Listed BV"})

	require.Equal(t, "Listed BV", tp.Name)
	require.Equal(t, clientmodels.TrustLevel_Medium, tp.TrustLevel)
}

// listedIssuerNamedView grants every issuer on an entry that names the party, so
// a test can assert the curated name wins.
type listedIssuerNamedView struct {
	name string
}

func (v listedIssuerNamedView) Issuer(trust.Evidence) trust.Verdict {
	return trust.Verdict{
		Level: clientmodels.TrustLevel_Medium,
		Listing: &trust.Listing{
			ListId: "urn:yivi:trustlist:openid4vci-test",
			Name:   clientmodels.TranslatedString{"en": v.name},
		},
	}
}

func (v listedIssuerNamedView) Verifier(ev trust.Evidence) trust.Verdict { return v.Issuer(ev) }
