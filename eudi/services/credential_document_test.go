package services

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/stretchr/testify/require"
)

// Each format gives the document of a freshly issued credential: an SD-JWT
// VC's images are its data URI claims, a VCDM credential also says how it looks
// and has Open Badges images, and an mdoc says nothing.
func TestParsedCredentialDocument(t *testing.T) {
	logos := newClaimImageCache(t)
	dataURIAttribute := func() []clientmodels.Attribute {
		value := testImageDataURI
		return []clientmodels.Attribute{{ClaimPath: []any{"picture"}, Value: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &value}}}
	}

	sdJwtVc := &ParsedCredential{SdJwtVc: &sdjwtvc.VerifiedSdJwtVc{ProcessedSdJwtPayload: map[string]any{"picture": testImageDataURI}}}
	document := sdJwtVc.Document()
	require.Equal(t, DocumentDisplay{}, document.Display())
	require.Equal(t, clientmodels.AttributeType_Base64Image, document.ShowImages(dataURIAttribute(), logos)[0].Value.Type)

	badge := &ParsedCredential{
		SdJwtVcdm: &vcdmsdjwt.VerifiedSdJwtVcdm{Document: vcdm.Document{
			vcdm.NameKey:              "Badge",
			vcdm.CredentialSubjectKey: map[string]any{"achievement": map[string]any{"image": "https://example.com/badge.png"}},
		}},
		ExpandedTypes: []string{vcdm.OpenBadgeCredentialType},
	}
	display := badge.Document().Display()
	require.Equal(t, clientmodels.TranslatedString{"": "Badge"}, display.CredentialNames)
	require.Equal(t, "https://example.com/badge.png", display.CredentialImage)

	mdocCredential := &ParsedCredential{Mdoc: &ParsedMdoc{}}
	require.Equal(t, CredentialDocument{}, mdocCredential.Document())
	require.Equal(t, dataURIAttribute(), mdocCredential.Document().ShowImages(dataURIAttribute(), logos),
		"an mdoc's attribute builders show its images; its document leaves its attributes alone")
}
