package eudi_sdjwt_dcql

import (
	"context"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/stretchr/testify/require"
)

// stubCatalog answers a fixed hit for one vct.
type stubCatalog struct {
	vct    string
	hit    *services.CatalogHit
	locale string
}

func (s *stubCatalog) Lookup(_ context.Context, vct string, locale string) *services.CatalogHit {
	s.locale = locale
	if vct != s.vct {
		return nil
	}
	return s.hit
}

const catalogQuery = `{
	"id": "q1",
	"format": "dc+sd-jwt",
	"meta": {"vct_values": ["https://example.com/vct/email"]},
	"claims": [{"path": ["email"]}]
}`

// A catalogue hit turns the dead end into issuance during disclosure: one
// descriptor per offering, each with the issuance URL for the wallet's locale.
func TestFindCandidates_CatalogHitYieldsObtainableDescriptorsPerOffering(t *testing.T) {
	h, _ := newTestHandler(t)
	h.currentLocale = clientmodels.NewCurrentLocale("nl")
	catalog := &stubCatalog{
		vct: "https://example.com/vct/email",
		hit: &services.CatalogHit{
			Entry: walletconfig.CatalogEntry{VCT: "https://example.com/vct/email"},
			Metadata: &typemetadata.VctTypeMetadata{
				Display: []typemetadata.DisplayEntry{{Locale: "nl", Name: "E-mail"}},
				Claims:  []typemetadata.ClaimMetadata{{Path: []any{"email"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: "nl", Name: "E-mailadres"}}}},
			},
			Offerings: []services.CatalogOffering{
				{IssueURL: "https://issue.example.com/nl/email", Issuer: clientmodels.TrustedParty{Id: "https://issuer.example.com", Name: "Uitgever", TrustLevel: clientmodels.TrustLevel_High}},
				{IssueURL: "https://other.example.org/email"},
			},
		},
	}
	h.catalog = catalog

	result, err := h.FindCandidates(parseDcqlQuery(t, catalogQuery))
	require.NoError(t, err)
	require.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 2)
	require.Equal(t, "nl", catalog.locale, "resolved for the wallet's locale")

	first := result.ObtainableDescriptors[0]
	require.Equal(t, "https://example.com/vct/email", first.CredentialId)
	require.Equal(t, "E-mail", first.Name)
	require.NotNil(t, first.IssueURL, "a non-nil IssueURL is the issue-during-disclosure signal")
	require.Equal(t, "https://issue.example.com/nl/email", *first.IssueURL)
	require.Equal(t, "Uitgever", first.Issuer.Name)
	require.Equal(t, clientmodels.TrustLevel_High, first.Issuer.TrustLevel)
	require.Len(t, first.Attributes, 1, "the requested claims, as for an unobtainable credential")
	require.Equal(t, "E-mailadres", *first.Attributes[0].DisplayName)

	require.Equal(t, "https://other.example.org/email", *result.ObtainableDescriptors[1].IssueURL)
	require.Empty(t, result.ObtainableDescriptors[1].Issuer.Name)
}

// Unresolved metadata renders the raw vct rather than nothing.
func TestFindCandidates_CatalogHitWithoutMetadataUsesTheVct(t *testing.T) {
	h, _ := newTestHandler(t)
	h.catalog = &stubCatalog{
		vct: "https://example.com/vct/email",
		hit: &services.CatalogHit{Offerings: []services.CatalogOffering{{IssueURL: "https://issue.example.com/email"}}},
	}

	result, err := h.FindCandidates(parseDcqlQuery(t, catalogQuery))
	require.NoError(t, err)
	require.Len(t, result.ObtainableDescriptors, 1)
	require.Equal(t, "https://example.com/vct/email", result.ObtainableDescriptors[0].Name)
	require.Len(t, result.ObtainableDescriptors[0].Attributes, 1)
	require.Nil(t, result.ObtainableDescriptors[0].Attributes[0].DisplayName)
}

// A miss keeps today's behaviour: one descriptor without an IssueURL.
func TestFindCandidates_CatalogMissKeepsTheUnobtainableDescriptor(t *testing.T) {
	h, _ := newTestHandler(t)
	h.catalog = &stubCatalog{vct: "https://example.com/vct/other"}
	h.vctFetcher = &stubVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{
		"https://example.com/vct/email": {Display: []typemetadata.DisplayEntry{{Locale: "en", Name: "Email"}}},
	}}

	result, err := h.FindCandidates(parseDcqlQuery(t, catalogQuery))
	require.NoError(t, err)
	require.Len(t, result.ObtainableDescriptors, 1)
	require.Nil(t, result.ObtainableDescriptors[0].IssueURL)
	require.Equal(t, "Email", result.ObtainableDescriptors[0].Name)
}

// Without a catalogue or a fetcher there is nothing to describe the credential
// with, and no descriptor is emitted, as before.
func TestFindCandidates_WithoutCatalogAndFetcherEmitsNothing(t *testing.T) {
	h, _ := newTestHandler(t)
	result, err := h.FindCandidates(parseDcqlQuery(t, catalogQuery))
	require.NoError(t, err)
	require.Empty(t, result.ObtainableDescriptors)
}
