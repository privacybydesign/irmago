package trust

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

func logo(base64 string) *clientmodels.Image {
	return &clientmodels.Image{Base64: base64}
}

// display is a party every source has something to say about, so a test can
// assert which source won rather than which ones were absent.
func display() PartyDisplay {
	return PartyDisplay{
		Id:               "12345",
		Attested:         PartyMetadata{Name: "Certified BV", Logo: logo("attested")},
		SelfAssertedName: "Anything BV",
		CuratedLogo:      logo("curated"),
	}
}

func listed(level clientmodels.TrustLevel) Verdict {
	return Verdict{
		Level:   level,
		Listing: &Listing{ListId: "yivi", Name: clientmodels.TranslatedString{"en": "Listed BV", "nl": "Vermeld BV"}},
	}
}

func TestTrustedParty_CuratedNameOutranksEverything(t *testing.T) {
	party := display().TrustedParty(listed(clientmodels.TrustLevel_Medium), "en")

	require.Equal(t, "Listed BV", party.Name, "a curated name outranks the certificate's and the party's own")
	require.Equal(t, logo("curated"), party.Image)
	require.Equal(t, clientmodels.TrustLevel_Medium, party.TrustLevel)
	require.Equal(t, "12345", party.Id)
}

func TestTrustedParty_CuratedNameResolvesForTheLocale(t *testing.T) {
	require.Equal(t, "Vermeld BV", display().TrustedParty(listed(clientmodels.TrustLevel_High), "nl").Name)
}

func TestTrustedParty_AttestedNameOutranksTheSelfAssertedOne(t *testing.T) {
	party := display().TrustedParty(Verdict{Level: clientmodels.TrustLevel_High}, "en")

	require.Equal(t, "Certified BV", party.Name)
	require.Equal(t, logo("attested"), party.Image, "with no listing the certificate's logo is the strongest source")
}

func TestTrustedParty_SelfAssertedIsTheLastResort(t *testing.T) {
	d := display()
	d.Attested = PartyMetadata{}

	party := d.TrustedParty(Verdict{Level: clientmodels.TrustLevel_Low}, "en")

	require.Equal(t, "Anything BV", party.Name)
	require.Equal(t, "12345", party.Id, "at low the identifier is the only thing the party did not choose itself")
	require.Nil(t, party.Image, "a logo the party asserts about itself is the whole of an impersonation")
}

func TestTrustedParty_AVouchedForPartyWithNoVouchedForLogoRendersNone(t *testing.T) {
	// An entry that names no logo, on a party with no certificate to carry one,
	// renders none: there is nowhere in a PartyDisplay to put a self-asserted
	// logo.
	d := display()
	d.Attested = PartyMetadata{}
	d.CuratedLogo = nil

	party := d.TrustedParty(listed(clientmodels.TrustLevel_High), "en")

	require.Equal(t, "Listed BV", party.Name)
	require.Nil(t, party.Image)
}

func TestTrustedParty_AListingWithNoNameFallsThrough(t *testing.T) {
	// An entry with no name in any language grants the rung but says nothing about
	// what to call the party.
	verdict := Verdict{Level: clientmodels.TrustLevel_Medium, Listing: &Listing{ListId: "yivi"}}

	require.Equal(t, "Certified BV", display().TrustedParty(verdict, "en").Name)
}

func TestTrustedParty_ALocaleTheListingLacksFallsThrough(t *testing.T) {
	// Resolve falls back across languages, so a listing that names the party at
	// all keeps naming it whatever locale is asked for.
	require.Equal(t, "Listed BV", display().TrustedParty(listed(clientmodels.TrustLevel_Medium), "de").Name)
}

func TestTrustedParty_CuratedLogoNeedsTheListingThatNamedIt(t *testing.T) {
	// The curated logo belongs to the entry that named it: without a verdict
	// carrying that entry, nothing vouches for the picture.
	party := display().TrustedParty(Verdict{Level: clientmodels.TrustLevel_High}, "en")

	require.Equal(t, logo("attested"), party.Image)
}

func TestTrustedParty_NoSourceLeavesAnEmptyName(t *testing.T) {
	// A party nothing is known about still composes: display may no more fail a
	// session than evaluation may.
	party := PartyDisplay{Id: "did:web:verifier.example.com"}.
		TrustedParty(Verdict{Level: clientmodels.TrustLevel_Low}, "en")

	require.Equal(t, "did:web:verifier.example.com", party.Id)
	require.Empty(t, party.Name)
	require.Nil(t, party.Image)
}
