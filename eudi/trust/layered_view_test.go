package trust

import (
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// stubSnapshot grants every party it is asked about, or none.
type stubSnapshot struct {
	listing   *Listing
	grantRole Role
}

func (s stubSnapshot) Lookup(role Role, _ Evidence) *Listing {
	if s.listing == nil || role != s.grantRole {
		return nil
	}
	return s.listing
}

func grantingVerifiers() stubSnapshot {
	return stubSnapshot{listing: &Listing{ListId: "yivi", Name: clientmodels.TranslatedString{"en": "Listed BV"}}, grantRole: RoleVerifier}
}

func TestNewView_NilSnapshotLeavesTheCertificateChannel(t *testing.T) {
	view := NewView(nil)

	require.Equal(t, clientmodels.TrustLevel_High, view.Verifier(Evidence{Certificate: &x509.Certificate{}}).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(Evidence{}).Level)
}

func TestNewView_ListedPartyRanksMedium(t *testing.T) {
	verdict := NewView(grantingVerifiers()).Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

	require.Equal(t, clientmodels.TrustLevel_Medium, verdict.Level)
	require.NotNil(t, verdict.Listing)
	require.Equal(t, "yivi", verdict.Listing.ListId)
}

func TestNewView_UnlistedPartyRanksLow(t *testing.T) {
	verdict := NewView(stubSnapshot{}).Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level)
	require.Nil(t, verdict.Listing)
}

func TestNewView_RoleIsPartOfTheGrant(t *testing.T) {
	// The same party, listed as a verifier, is not thereby listed as an issuer.
	ev := Evidence{Identifiers: []string{"did:web:party.example.com"}}
	view := NewView(grantingVerifiers())

	require.Equal(t, clientmodels.TrustLevel_Medium, view.Verifier(ev).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(ev).Level)
}

func TestNewView_OnboardedByYiviRanksHigh(t *testing.T) {
	// Yivi's own list marking an entry as onboarded by Yivi is Yivi vouching for
	// the party, which is what its scheme certificate would have said too.
	listing := grantingVerifiers()
	listing.listing.OnboardedByYivi = true

	verdict := NewView(listing).Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

	require.Equal(t, clientmodels.TrustLevel_High, verdict.Level)
	require.NotNil(t, verdict.Listing)
}

func TestNewView_ListedWithoutTheMarkingStaysMedium(t *testing.T) {
	// The marking is what separates the two rungs the list channel can grant. A
	// marking Yivi did not make has already been dropped by the list channel, so
	// what arrives here without one is another operator's word: medium.
	verdict := NewView(grantingVerifiers()).Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

	require.Equal(t, clientmodels.TrustLevel_Medium, verdict.Level)
	require.False(t, verdict.Listing.OnboardedByYivi)
}

func TestNewView_ChannelsAreIndependent(t *testing.T) {
	// A certificate under the Yivi anchors already reaches the top rung, so
	// being on a list on top of it changes the rung not at all — but the
	// listing still travels, because it carries the curated display metadata.
	verdict := NewView(grantingVerifiers()).Verifier(Evidence{
		Certificate: &x509.Certificate{},
		Identifiers: []string{"did:web:verifier.example.com"},
	})

	require.Equal(t, clientmodels.TrustLevel_High, verdict.Level, "a listing must not pull a certified party down")
	require.NotNil(t, verdict.Listing)
}
