package trust

import (
	"crypto/x509"
	"slices"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// stubLister vouches for one identifier, in one role.
type stubLister struct {
	role       Role
	identifier string
	listing    Listing
}

func (l stubLister) Lookup(role Role, ev Evidence) *Listing {
	if role != l.role {
		return nil
	}
	if slices.Contains(ev.Identifiers, l.identifier) {
		listing := l.listing
		return &listing
	}
	return nil
}

func TestView_CertificateEvidenceRanksHigh(t *testing.T) {
	view := NewView(nil)
	ev := Evidence{
		Certificate: &x509.Certificate{},
		Identifiers: []string{"x509_san_dns:verifier.example.com"},
	}

	for role, verdict := range map[string]Verdict{
		"verifier": view.Verifier(ev),
		"issuer":   view.Issuer(ev),
	} {
		require.Equal(t, clientmodels.TrustLevel_High, verdict.Level, role)
		require.Nil(t, verdict.Listing, "%s: the certificate channel grants no listing", role)
	}
}

func TestView_WithoutCertificateRanksLow(t *testing.T) {
	view := NewView(nil)
	ev := Evidence{Identifiers: []string{"did:web:verifier.example.com"}}

	for role, verdict := range map[string]Verdict{
		"verifier": view.Verifier(ev),
		"issuer":   view.Issuer(ev),
	} {
		require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level, role)
		require.Nil(t, verdict.Listing, role)
	}
}

func TestView_EmptyEvidenceRanksLow(t *testing.T) {
	// A party the wallet knows nothing about still gets a verdict rather than
	// an error: no evaluation path may fail a session.
	view := NewView(nil)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Verifier(Evidence{}).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(Evidence{}).Level)
}

func TestView_ListedPartyRanksMedium(t *testing.T) {
	lister := stubLister{
		role:       RoleVerifier,
		identifier: "did:web:verifier.example.com",
		listing:    Listing{ListId: "yivi", Name: clientmodels.TranslatedString{"en": "Curated Name"}},
	}
	view := NewView(lister)
	ev := Evidence{Identifiers: []string{"did:web:verifier.example.com"}}

	verdict := view.Verifier(ev)
	require.Equal(t, clientmodels.TrustLevel_Medium, verdict.Level)
	require.True(t, verdict.Level.IsTrusted())
	require.NotNil(t, verdict.Listing)
	require.Equal(t, "Curated Name", verdict.Listing.Name["en"])
}

func TestView_ListingIsRoleTyped(t *testing.T) {
	// A grant to verify is not a grant to issue: the same party asked about in
	// the other role is not vouched for at all.
	lister := stubLister{role: RoleVerifier, identifier: "did:web:party.example.com"}
	view := NewView(lister)
	ev := Evidence{Identifiers: []string{"did:web:party.example.com"}}

	require.Equal(t, clientmodels.TrustLevel_Medium, view.Verifier(ev).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(ev).Level)
}

func TestView_ChannelsAreIndependent(t *testing.T) {
	lister := stubLister{
		role:       RoleVerifier,
		identifier: "x509_san_dns:verifier.example.com",
		listing:    Listing{ListId: "yivi", Name: clientmodels.TranslatedString{"en": "Curated Name"}},
	}
	view := NewView(lister)

	// A certified party that is also listed keeps the higher rung, and still
	// carries the listing: what the list says it is called outranks what it says
	// about itself at every rung.
	verdict := view.Verifier(Evidence{
		Certificate: &x509.Certificate{},
		Identifiers: []string{"x509_san_dns:verifier.example.com"},
	})
	require.Equal(t, clientmodels.TrustLevel_High, verdict.Level)
	require.NotNil(t, verdict.Listing)

	// And a certified party the list has nothing to say about stays high, which
	// is what keeps a scheme-certified party at its rung while the list is down.
	unlisted := view.Verifier(Evidence{
		Certificate: &x509.Certificate{},
		Identifiers: []string{"x509_san_dns:other.example.com"},
	})
	require.Equal(t, clientmodels.TrustLevel_High, unlisted.Level)
	require.Nil(t, unlisted.Listing)
}
