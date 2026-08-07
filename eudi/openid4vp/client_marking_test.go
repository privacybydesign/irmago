package openid4vp

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The tests below drive whole OpenID4VP sessions to the permission screen and
// assert what the user is shown about the verifier: the rung the onboarded-by-
// Yivi marking lifts it to, and which of the competing accounts of who the
// verifier is wins. They use the bare did:web verifier, whose certificate
// channel says nothing, so the rung reported is the list channel's alone.

func TestNewSession_MarkedOnYivisList_RanksHigh(t *testing.T) {
	authRequestJwt, validator, did := setupDidWebTest(t)
	list := newYiviListFixture(t)
	list.grant(t, 1, did, lote.MarkingOnboardedByYivi)

	client := newTrustTestClientWithLists(validator, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_High, requestor.TrustLevel,
		"an entry Yivi marks as onboarded by Yivi is Yivi vouching for the verifier")
	require.True(t, requestor.TrustLevel.IsTrusted())
}

func TestNewSession_UnmarkedOnYivisList_RanksMedium(t *testing.T) {
	// Yivi publishing a list is not Yivi vouching for everyone on it: the
	// marking is what separates the two rungs the list can grant.
	authRequestJwt, validator, did := setupDidWebTest(t)
	list := newYiviListFixture(t)
	list.grant(t, 1, did)

	client := newTrustTestClientWithLists(validator, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	require.Equal(t, clientmodels.TrustLevel_Medium, handler.awaitRequestor(t).TrustLevel)
}

func TestNewSession_MarkedOnAnotherOperatorsList_StaysMedium(t *testing.T) {
	// The marking on a list Yivi does not operate is that operator claiming Yivi
	// onboarded the verifier, which is not Yivi's word and does not get taken as
	// it. The entry still grants what any recognized list grants: medium.
	authRequestJwt, validator, did := setupDidWebTest(t)
	list := newListFixture(t)
	list.grant(t, 1, did, lote.MarkingOnboardedByYivi)

	client := newTrustTestClientWithLists(validator, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	require.Equal(t, clientmodels.TrustLevel_Medium, handler.awaitRequestor(t).TrustLevel,
		"only Yivi's own list may lift a verifier to high")
}

func TestNewSession_ListedVerifier_RendersTheCuratedName(t *testing.T) {
	// The verifier calls itself after its response URI's host; the list calls it
	// "Listed BV". The curated name is the one somebody vouches for.
	authRequestJwt, validator, did := setupDidWebTest(t)
	list := newYiviListFixture(t)
	list.grant(t, 1, did, lote.MarkingOnboardedByYivi)

	client := newTrustTestClientWithLists(validator, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	require.Equal(t, "Listed BV", handler.awaitRequestor(t).Name)
}

func TestNewSession_LowVerifier_RendersItsOwnNameItsIdentifierAndNoLogo(t *testing.T) {
	authRequestJwt, validator, did := setupDidWebTest(t)

	client := newTrustTestClient(validator)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_Low, requestor.TrustLevel)
	require.Equal(t, "response.uri", requestor.Name,
		"with nobody vouching for it, all the wallet has is what the request says")
	require.Equal(t, did, requestor.Id,
		"the identifier is the one thing on the screen the verifier did not choose itself")
	require.Nil(t, requestor.Image, "a logo at low would be an impersonation the wallet drew itself")
}

func TestNewSession_CertifiedVerifierWithoutAListing_RendersItsRequestorInfo(t *testing.T) {
	// With no list vouching for it, a certificate-authenticated verifier is
	// still shown by name rather than by nothing.
	//
	// The name here reaches the wallet through client_metadata, which the
	// verifier wrote itself; the wallet counts it as attested because the
	// validator hands the requestor info over already collapsed, and telling the
	// certificate's own account of the party apart from the request's needs the
	// validator to surface both (#660).
	authRequestJwt, validator := setupTest(t, withClientName("Test Verifier"), testdata.PkiOption_None)

	client := newTrustTestClient(validator)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_High, requestor.TrustLevel)
	require.Equal(t, "Test Verifier", requestor.Name)
	require.NotEmpty(t, requestor.Id, "a certificate-bearing verifier is known by its serial number")
}
