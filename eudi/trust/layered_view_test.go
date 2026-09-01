package trust

import (
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

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

func grantingVerifiers(level clientmodels.TrustLevel) stubSnapshot {
	return stubSnapshot{
		listing:   &Listing{SourceKey: "yivi", Name: clientmodels.TranslatedString{"en": "Listed BV"}, Level: level},
		grantRole: RoleVerifier,
	}
}

func TestNewView_NilSnapshotLeavesTheCertificateChannel(t *testing.T) {
	view := NewView(nil, stubClassifier(clientmodels.TrustLevel_High), stubClassifier(clientmodels.TrustLevel_High))

	require.Equal(t, clientmodels.TrustLevel_High, view.Verifier(Evidence{Certificate: &x509.Certificate{}}).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(Evidence{}).Level)
}

func TestNewView_ListingConfersItsSourcesLevel(t *testing.T) {
	for _, level := range []clientmodels.TrustLevel{clientmodels.TrustLevel_Medium, clientmodels.TrustLevel_High} {
		verdict := NewView(grantingVerifiers(level), nil, nil).Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

		require.Equal(t, level, verdict.Level)
		require.NotNil(t, verdict.Listing)
		require.Equal(t, "yivi", verdict.Listing.SourceKey)
	}
}

func TestNewView_UnlistedPartyRanksLow(t *testing.T) {
	verdict := NewView(stubSnapshot{}, nil, nil).Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level)
	require.Nil(t, verdict.Listing)
}

func TestNewView_RoleIsPartOfTheGrant(t *testing.T) {
	ev := Evidence{Identifiers: []string{"did:web:party.example.com"}}
	view := NewView(grantingVerifiers(clientmodels.TrustLevel_High), nil, nil)

	require.Equal(t, clientmodels.TrustLevel_High, view.Verifier(ev).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(ev).Level)
}

func TestNewView_AListingWithoutALevelLiftsNothing(t *testing.T) {
	// A source that declares no level is curated display without vouching: the
	// party keeps the other channels' rung, and the listing still travels.
	verdict := NewView(grantingVerifiers(clientmodels.TrustLevel_Unevaluated), nil, nil).
		Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level)
	require.NotNil(t, verdict.Listing)
}

func TestNewView_ChannelsAreIndependent(t *testing.T) {
	// A certificate already at the top rung is not lifted further by a listing,
	// but the listing still travels for its curated display metadata.
	view := NewView(grantingVerifiers(clientmodels.TrustLevel_Medium),
		nil, stubClassifier(clientmodels.TrustLevel_High))
	verdict := view.Verifier(Evidence{
		Certificate: &x509.Certificate{},
		Identifiers: []string{"did:web:verifier.example.com"},
	})

	require.Equal(t, clientmodels.TrustLevel_High, verdict.Level, "a listing must not pull a certified party down")
	require.NotNil(t, verdict.Listing)
	require.Equal(t, clientmodels.TrustLevel_High, verdict.CertificateLevel)
}

func TestStronger(t *testing.T) {
	high := clientmodels.TrustLevel_High
	medium := clientmodels.TrustLevel_Medium
	low := clientmodels.TrustLevel_Low
	unevaluated := clientmodels.TrustLevel_Unevaluated

	require.True(t, Stronger(high, medium))
	require.True(t, Stronger(medium, low))
	require.True(t, Stronger(low, unevaluated))
	require.False(t, Stronger(medium, medium))
	require.False(t, Stronger(unevaluated, low))
}
