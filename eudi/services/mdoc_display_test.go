package services

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

func strPtr(s string) *string { return &s }

// mdocBatchWithClaims builds a stored mdoc carrying one namespace with two
// elements, whose credential_metadata snapshot declares the given claim paths,
// each labelled "Label i" in English.
func mdocBatchWithClaims(claimPaths ...[]any) *models.MdocBatch {
	cm := metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{{Display: metadata.Display{Name: "Proof of Age", Locale: strPtr("en")}}},
	}
	for i, path := range claimPaths {
		cm.Claims = append(cm.Claims, metadata.ClaimsDescription{
			Path:    metadata.ClaimsPathPointer(path),
			Display: []metadata.Display{{Name: "Label " + strconv.Itoa(i), Locale: strPtr("en")}},
		})
	}
	encoded, _ := json.Marshal(cm)
	return &models.MdocBatch{
		DocType:          "eu.europa.ec.av.1",
		CredentialIssuer: "https://issuer.example",
		Namespaces: models.MdocNamespaces{
			"eu.europa.ec.av.1": {"age_over_18": true, "age_over_21": true},
		},
		IssuerDisplay:      datatypes.JSON(`[{"name":"Issuer EN","locale":"en","logo":{"uri":"https://logo/en.png"}},{"name":"Issuer NL","locale":"nl"}]`),
		CredentialMetadata: datatypes.JSON(encoded),
	}
}

func key(path ...any) string { return clientmodels.ClaimPathKey(path) }

func TestResolveMdocDisplay_ReadsSnapshots(t *testing.T) {
	d := ResolveMdocDisplay(mdocBatchWithClaims([]any{"eu.europa.ec.av.1", "age_over_18"}), "nl")

	require.Equal(t, "https://issuer.example", d.IssuerId)
	require.Equal(t, "Issuer NL", d.IssuerName)
	require.Equal(t, clientmodels.TranslatedString{"en": "Issuer EN", "nl": "Issuer NL"}, d.IssuerNames)
	// No Dutch credential display was published, so the name falls back and says so.
	require.Equal(t, "Proof of Age", d.CredentialName)
	require.True(t, d.DisplayIsFallback)
	require.Equal(t, "Label 0", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_18")])
	require.Equal(t, 0, d.ClaimOrder[key("eu.europa.ec.av.1", "age_over_18")])
}

// An issuer that publishes a bare element identifier still gets its labels
// rendered: OpenID4VCI's mso_mdoc profile specifies no display metadata, so the
// one-component form is not a bug the wallet can refuse to work around.
func TestResolveMdocDisplay_AliasesBareElementPaths(t *testing.T) {
	d := ResolveMdocDisplay(mdocBatchWithClaims([]any{"age_over_18"}, []any{"age_over_21"}), "en")

	require.Equal(t, "Label 0", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_18")])
	require.Equal(t, "Label 1", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_21")])
	require.Equal(t, 0, d.ClaimOrder[key("eu.europa.ec.av.1", "age_over_18")])
	require.Equal(t, 1, d.ClaimOrder[key("eu.europa.ec.av.1", "age_over_21")])
}

// A correctly published two-component path must win, so an issuer that publishes
// both forms is never labelled from the wrong one.
func TestResolveMdocDisplay_ExactPathBeatsBareElementAlias(t *testing.T) {
	d := ResolveMdocDisplay(mdocBatchWithClaims([]any{"eu.europa.ec.av.1", "age_over_18"}, []any{"age_over_18"}), "en")

	require.Equal(t, "Label 0", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_18")])
}

// The alias is only for elements the credential carries: metadata may describe
// claims from namespaces this batch never received.
func TestResolveMdocDisplay_DoesNotAliasElementsTheCredentialLacks(t *testing.T) {
	d := ResolveMdocDisplay(mdocBatchWithClaims([]any{"age_over_65"}), "en")

	require.NotContains(t, d.ClaimNames, key("eu.europa.ec.av.1", "age_over_65"))
}

// Elements the metadata never named render as a derived name where one exists
// and as their identifier otherwise, never nameless. A declared claim with an
// empty published name is treated the same as undeclared.
func TestResolveMdocDisplay_NamesUndeclaredElements(t *testing.T) {
	batch := mdocBatchWithClaims([]any{"eu.europa.ec.av.1", "age_over_18"})
	batch.Namespaces["eu.europa.ec.av.1"]["age_over_91"] = true
	batch.Namespaces["eu.europa.ec.av.1"]["email"] = "a@b.c"

	d := ResolveMdocDisplay(batch, "en")

	require.Equal(t, "Label 0", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_18")], "published text wins")
	require.Equal(t, "Age Over 21", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_21")], "derived where the name carries the meaning")
	require.Equal(t, "Age Over 91", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_91")])
	require.Equal(t, "email", d.ClaimNames[key("eu.europa.ec.av.1", "email")], "identifier where nothing else names it")
}

// No metadata at all is the strongest fallback case: the docType and element
// identifiers are all the wallet has, and DisplayIsFallback must say so.
func TestResolveMdocDisplay_WithoutMetadata(t *testing.T) {
	batch := &models.MdocBatch{
		DocType:          "eu.europa.ec.av.1",
		CredentialIssuer: "https://issuer.example",
		Namespaces:       models.MdocNamespaces{"eu.europa.ec.av.1": {"age_over_18": true}},
	}

	d := ResolveMdocDisplay(batch, "en")

	require.Empty(t, d.CredentialName, "no live name: the caller applies the docType fallback")
	require.Empty(t, d.IssuerName)
	require.True(t, d.DisplayIsFallback)
	require.Equal(t, "Age Over 18", d.ClaimNames[key("eu.europa.ec.av.1", "age_over_18")])
}

// A snapshot that does not parse degrades to "the issuer published none": the
// credential stays listable, with its identifiers as text.
func TestResolveMdocDisplay_MalformedSnapshotsReadAsAbsent(t *testing.T) {
	batch := mdocBatchWithClaims([]any{"eu.europa.ec.av.1", "age_over_18"})
	batch.IssuerDisplay = datatypes.JSON(`not json`)
	batch.CredentialMetadata = datatypes.JSON(`{"display": 1}`)

	d := ResolveMdocDisplay(batch, "en")

	require.Nil(t, MdocIssuerDisplays(batch))
	require.Nil(t, MdocCredentialMetadata(batch))
	require.Empty(t, d.IssuerName)
	require.Empty(t, d.CredentialName)
	require.True(t, d.DisplayIsFallback)
}

func TestMdocDisplayIsFallback(t *testing.T) {
	batch := mdocBatchWithClaims()
	require.False(t, MdocDisplayIsFallback(batch, "en"))
	require.False(t, MdocDisplayIsFallback(batch, "en-GB"), "a regional variant of a published language is not a fallback")
	require.True(t, MdocDisplayIsFallback(batch, "nl"))
	require.True(t, MdocDisplayIsFallback(&models.MdocBatch{}, "en"), "no metadata at all")
}

func TestMdocLogoURIsByLanguage(t *testing.T) {
	batch := mdocBatchWithClaims()
	issuerLogos := MdocIssuerLogoURIsByLanguage(MdocIssuerDisplays(batch))
	require.Equal(t, clientmodels.TranslatedString{"en": "https://logo/en.png"}, issuerLogos, "only displays carrying a logo are mapped")

	cm := MdocCredentialMetadata(batch)
	require.NotNil(t, cm)
	require.Empty(t, MdocCredentialLogoURIsByLanguage(cm.Display))
	cm.Display[0].Logo = &metadata.RemoteImage{Uri: "https://logo/cred.png"}
	require.Equal(t, clientmodels.TranslatedString{"en": "https://logo/cred.png"}, MdocCredentialLogoURIsByLanguage(cm.Display))
}
