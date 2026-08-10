package openid4vp

import (
	"context"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The tests below drive whole OpenID4VP sessions against a recognized trust
// list the test controls, and assert the rung the verifier reaches. They use
// the bare did:web verifier, whose certificate channel says nothing, so the
// rung reported is the list channel's alone.

const trustListId = "urn:yivi:trustlist:openid4vp-test"

// listFixture is a recognized list the test publishes and can change.
type listFixture struct {
	signer *lote.TestLoteSigner
	server *lote.TestLoteServer
	source lote.Source
}

// newListFixture is a recognized list that is not Yivi's own: its entries
// confer medium.
func newListFixture(t *testing.T) *listFixture {
	t.Helper()
	return newListFixtureConferring(t, clientmodels.TrustLevel_Medium)
}

// newYiviListFixture is a fixture for Yivi's own list, whose entries confer
// high: being listed there is being onboarded.
func newYiviListFixture(t *testing.T) *listFixture {
	t.Helper()
	return newListFixtureConferring(t, clientmodels.TrustLevel_High)
}

func newListFixtureConferring(t *testing.T, confers clientmodels.TrustLevel) *listFixture {
	t.Helper()
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	return &listFixture{signer: signer, server: server, source: server.Source(trustListId, confers)}
}

// grant publishes a list granting did the verifier role.
func (f *listFixture) grant(t *testing.T, sequenceNumber uint64, did string) {
	t.Helper()
	f.server.Serve(t, f.signer, lote.NewTestList(trustListId, sequenceNumber,
		lote.NewTestEntity("Listed BV", "", lote.NewTestDidService(trust.RoleVerifier, did))))
}

// checker returns a checker over this list, refreshed once.
func (f *listFixture) checker(t *testing.T) *lote.Checker {
	t.Helper()
	checker := lote.NewChecker(lote.Config{
		Sources:     []lote.Source{f.source},
		X509Context: f.signer.X509VerificationContext(),
	})
	// The refresh may well fail — that is the point of the degradation cases —
	// and the session is expected to run either way.
	_, _ = checker.Refresh(context.Background())
	return checker
}

func TestNewSession_ListedVerifier_RanksMedium(t *testing.T) {
	authRequestJwt, validator, did := setupDidWebTest(t)
	list := newListFixture(t)
	list.grant(t, 1, did)

	client := newTrustTestClientWithLists(validator, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	requestor := handler.awaitRequestor(t)
	require.Equal(t, clientmodels.TrustLevel_Medium, requestor.TrustLevel,
		"a verifier granted on a recognized list is vouched for by that list's operator")
	require.True(t, requestor.TrustLevel.IsTrusted())
}

func TestNewSession_UnlistedVerifier_RanksLow(t *testing.T) {
	authRequestJwt, validator, _ := setupDidWebTest(t)
	list := newListFixture(t)
	list.grant(t, 1, "did:web:somebody-else.example.com")

	client := newTrustTestClientWithLists(validator, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	require.Equal(t, clientmodels.TrustLevel_Low, handler.awaitRequestor(t).TrustLevel)
}

// A list the wallet cannot rely on is absent evidence, not a failure: however
// it went bad, the verifier caps at low, the session reaches the permission
// screen, and nothing about the list surfaces to the user.
func TestNewSession_ListDegradations_CapTheVerifierAtLow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		degrade func(t *testing.T, f *listFixture, did string)
	}{
		{
			name: "tampered signature",
			degrade: func(t *testing.T, f *listFixture, did string) {
				impostor := lote.NewTestLoteSigner(t)
				f.server.Serve(t, impostor, lote.NewTestList(trustListId, 1,
					lote.NewTestEntity("Listed BV", "", lote.NewTestDidService(trust.RoleVerifier, did))))
			},
		},
		{
			name: "expired next_update",
			degrade: func(t *testing.T, f *listFixture, did string) {
				list := lote.NewTestList(trustListId, 1,
					lote.NewTestEntity("Listed BV", "", lote.NewTestDidService(trust.RoleVerifier, did)))
				list.SchemeInformation.NextUpdate = time.Now().Add(-time.Hour)
				f.server.Serve(t, f.signer, list)
			},
		},
		{
			name:    "unreachable endpoint",
			degrade: func(t *testing.T, f *listFixture, _ string) { f.server.Close() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authRequestJwt, validator, did := setupDidWebTest(t)
			list := newListFixture(t)
			tc.degrade(t, list, did)

			client := newTrustTestClientWithLists(validator, list.checker(t))
			handler := newSpyHandler()

			defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

			require.Equal(t, clientmodels.TrustLevel_Low, handler.awaitRequestor(t).TrustLevel)
			require.Empty(t, handler.failed, "a bad list may not fail a session")
		})
	}
}

func TestNewSession_ReplayedOlderList_DoesNotGrant(t *testing.T) {
	authRequestJwt, validator, did := setupDidWebTest(t)
	list := newListFixture(t)

	// The wallet holds issue 5, on which this verifier is not listed.
	list.server.Serve(t, list.signer, lote.NewTestList(trustListId, 5))
	checker := list.checker(t)

	// Issue 4 is served in its place: correctly signed, still current, and it
	// does list the verifier. Adopting it would let a captured older list
	// re-grant a party the scheme operator has since removed.
	list.grant(t, 4, did)
	_, refreshErr := checker.Refresh(context.Background())
	require.Error(t, refreshErr)

	client := newTrustTestClientWithLists(validator, checker)
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	require.Equal(t, clientmodels.TrustLevel_Low, handler.awaitRequestor(t).TrustLevel)
	require.Empty(t, handler.failed, "a refused list update may not fail a session")
}

func TestNewSession_X509Verifier_StaysHighWithTheListUnavailable(t *testing.T) {
	// The two channels are independent: Yivi's own certificate does not stop
	// counting because a trust list is down.
	authRequestJwt, validator := setupTest(t, withClientName("Test Verifier"), testdata.PkiOption_None)
	list := newListFixture(t)
	list.server.Close()

	client := newTrustTestClientWithLists(validator, list.checker(t))
	handler := newSpyHandler()

	defer client.NewSession(serveAuthRequest(t, authRequestJwt), handler).Dismiss()

	require.Equal(t, clientmodels.TrustLevel_High, handler.awaitRequestor(t).TrustLevel)
}

func TestVerifierIdentifiers(t *testing.T) {
	// A trust list names the party, so a DID client_id has to contribute the
	// bare DID; anything else travels as it came.
	require.Equal(t,
		[]string{"did:web:verifier.example.com", "decentralized_identifier:did:web:verifier.example.com"},
		verifierIdentifiers("decentralized_identifier:did:web:verifier.example.com"))
	require.Equal(t,
		[]string{"x509_san_dns:verifier.example.com"},
		verifierIdentifiers("x509_san_dns:verifier.example.com"))
}
