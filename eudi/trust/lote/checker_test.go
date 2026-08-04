package lote

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// The wallet's logger is wired by whoever builds the client; a package under
// eudi tested on its own has to set one up, as the neighbouring packages do.
func TestMain(m *testing.M) {
	eudi.Logger = logrus.New()
	os.Exit(m.Run())
}

const testListId = "urn:yivi:trustlist:test"

// fixture wires a checker against a mutable test server publishing one list.
type fixture struct {
	signer *TestLoteSigner
	server *TestLoteServer
	store  Store
	config Config
}

func newFixture(t *testing.T, operatedByYivi bool) *fixture {
	t.Helper()
	signer := NewTestLoteSigner(t)
	server := NewTestLoteServer(t)
	store := NewMemoryStore()
	return &fixture{
		signer: signer,
		server: server,
		store:  store,
		config: Config{
			Sources:     []Source{server.Source(testListId, operatedByYivi)},
			X509Context: signer.X509VerificationContext(),
			Store:       store,
		},
	}
}

// refreshed returns a checker that has pulled whatever the server currently
// publishes, asserting the refresh succeeded.
func (f *fixture) refreshed(t *testing.T) *Checker {
	t.Helper()
	checker := NewChecker(f.config)
	requireRefreshed(t, checker)
	return checker
}

func TestChecker_ListedVerifierIsGranted(t *testing.T) {
	f := newFixture(t, false)
	verifier := f.signer.NewTestPartyCertificate(t, "verifier.example.com", "VATNL-000000001")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "VATNL-000000001",
			NewTestCertificateService(ServiceTypeVerifier, verifier)),
	))

	listing := f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: verifier})

	require.NotNil(t, listing)
	require.Equal(t, testListId, listing.ListId)
	require.Equal(t, "Listed BV", listing.Name["en"])
	require.False(t, listing.OnboardedByYivi, "an unmarked entry is not Yivi's own")
}

func TestChecker_UnlistedVerifierIsNotGranted(t *testing.T) {
	f := newFixture(t, false)
	listed := f.signer.NewTestPartyCertificate(t, "listed.example.com", "")
	stranger := f.signer.NewTestPartyCertificate(t, "stranger.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, listed)),
	))

	snapshot := f.refreshed(t).Snapshot()

	require.Nil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{Certificate: stranger}))
}

func TestChecker_GrantsAreRoleTyped(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Issuing BV", "", NewTestCertificateService(ServiceTypeIssuer, party)),
	))

	snapshot := f.refreshed(t).Snapshot()
	evidence := trust.Evidence{Certificate: party}

	require.NotNil(t, snapshot.Lookup(trust.RoleIssuer, evidence))
	require.Nil(t, snapshot.Lookup(trust.RoleVerifier, evidence),
		"trust as an issuer is not trust as a verifier")
}

func TestChecker_WithdrawnServiceIsNotGranted(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	service := NewTestCertificateService(ServiceTypeVerifier, party)
	service.Status = ServiceStatusWithdrawn
	f.server.Serve(t, f.signer, NewTestList(testListId, 1, NewTestEntity("Former BV", "", service)))

	require.Nil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_EntryKeyedOnSubjectKeyIdentifier(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "VATNL-000000002")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Key BV", "VATNL-000000002", NewTestSkiService(ServiceTypeVerifier, party)),
	))

	require.NotNil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_OrganizationIdentifierIsPartOfTheKey(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "VATNL-000000003")
	// The entry names the right key but the wrong legal entity. Both halves of
	// the key have to hold, so it does not grant.
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Someone Else BV", "VATNL-999999999", NewTestSkiService(ServiceTypeVerifier, party)),
	))

	require.Nil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_DidMatchesThroughOtherId(t *testing.T) {
	f := newFixture(t, false)
	const did = "did:web:verifier.example.com"
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("DID BV", "", NewTestDidService(ServiceTypeVerifier, did)),
	))

	snapshot := f.refreshed(t).Snapshot()

	require.NotNil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{
		Identifiers: []string{did, "decentralized_identifier:" + did},
	}))
	require.Nil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{
		Identifiers: []string{"did:web:someone-else.example.com"},
	}), "a DID is compared verbatim")
}

func TestChecker_MarkingOnlyCountsOnYivisOwnList(t *testing.T) {
	for _, tc := range []struct {
		name           string
		operatedByYivi bool
		expected       bool
	}{
		{"yivi's own list", true, true},
		{"another recognized list", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.operatedByYivi)
			party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
			f.server.Serve(t, f.signer, NewTestList(testListId, 1,
				NewTestEntity("Marked BV", "",
					NewTestCertificateService(ServiceTypeVerifier, party, MarkingOnboardedByYivi)),
			))

			listing := f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party})

			require.NotNil(t, listing)
			require.Equal(t, tc.expected, listing.OnboardedByYivi)
		})
	}
}

func TestChecker_ServiceNameOverridesTheEntityName(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	service := NewTestCertificateService(ServiceTypeVerifier, party)
	service.Name = clientmodels.TranslatedString{"en": "The Service"}
	service.LogoURI = "https://example.com/service.png"
	entity := NewTestEntity("The Operator", "", service)
	entity.LogoURI = "https://example.com/operator.png"
	f.server.Serve(t, f.signer, NewTestList(testListId, 1, entity))

	listing := f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party})

	require.NotNil(t, listing)
	require.Equal(t, "The Service", listing.Name["en"])
	require.Equal(t, "https://example.com/service.png", listing.LogoURI)
}

// The degradation cases below all end the same way: the wallet holds no usable
// list, so nothing is granted and no error reaches a session. They differ only
// in how the list went bad.
func TestChecker_DegradationsLeaveNothingGranted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		degrade func(t *testing.T, f *fixture, party *TestLoteSigner)
	}{
		{
			name: "tampered signature",
			degrade: func(t *testing.T, f *fixture, _ *TestLoteSigner) {
				// Signed by a key that chains to nothing the wallet trusts —
				// the shape a substituted or re-signed list arrives in.
				impostor := NewTestLoteSigner(t)
				f.server.Serve(t, impostor, NewTestList(testListId, 1))
			},
		},
		{
			name: "expired next_update",
			degrade: func(t *testing.T, f *fixture, _ *TestLoteSigner) {
				list := NewTestList(testListId, 1)
				list.SchemeInformation.NextUpdate = time.Now().Add(-time.Hour)
				f.server.Serve(t, f.signer, list)
			},
		},
		{
			name:    "unreachable endpoint",
			degrade: func(t *testing.T, f *fixture, _ *TestLoteSigner) { f.server.Close() },
		},
		{
			name:    "server error",
			degrade: func(t *testing.T, f *fixture, _ *TestLoteSigner) { f.server.SetStatus(503) },
		},
		{
			name: "another list's document",
			degrade: func(t *testing.T, f *fixture, _ *TestLoteSigner) {
				f.server.Serve(t, f.signer, NewTestList("urn:yivi:trustlist:other", 1))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, false)
			party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
			tc.degrade(t, f, f.signer)

			checker := NewChecker(f.config)
			// The refresh reports what went wrong, for the log. Nothing about
			// it reaches a session.
			requireRefreshFailed(t, checker)

			require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
		})
	}
}

func TestChecker_SequenceNumberMayNotRegress(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	granting := NewTestList(testListId, 7,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, party)))
	f.server.Serve(t, f.signer, granting)

	checker := f.refreshed(t)
	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))

	// A correctly signed, still-current older issue of the same list, in which
	// the party was not yet listed. Adopting it would silently un-list
	// everybody added since.
	f.server.Serve(t, f.signer, NewTestList(testListId, 6))
	requireRefreshFailed(t, checker)

	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}),
		"the newer list the wallet already held stays in force")
}

func TestChecker_ReissueWithTheSameSequenceNumberIsAccepted(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 3))

	checker := f.refreshed(t)
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))

	f.server.Serve(t, f.signer, NewTestList(testListId, 3,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, party))))
	requireRefreshed(t, checker)

	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_AListPastItsNextUpdateStopsGranting(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	list := NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, party)))
	list.SchemeInformation.NextUpdate = time.Now().Add(time.Hour)
	f.server.Serve(t, f.signer, list)

	// A clock the test moves past the list's next_update, standing in for a
	// wallet that has not managed to refresh in a while.
	now := time.Now()
	f.config.Now = func() time.Time { return now }
	checker := f.refreshed(t)
	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))

	now = now.Add(2 * time.Hour)

	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}),
		"a list past its next_update is no evidence, not stale evidence")
}

func TestChecker_SnapshotIsPinned(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, party))))

	checker := f.refreshed(t)
	pinned := checker.Snapshot()

	// The party is delisted and the wallet picks that up mid-session.
	f.server.Serve(t, f.signer, NewTestList(testListId, 2))
	requireRefreshed(t, checker)

	require.NotNil(t, pinned.Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}),
		"a refresh landing mid-session may not change that session's verdicts")
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}),
		"the next session sees the delisting")
}

func TestChecker_PersistedListSurvivesARestart(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 4,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, party))))
	f.refreshed(t)

	// A fresh checker over the same store, and the server gone: what the wallet
	// knows now comes off disk alone.
	f.server.Close()
	restarted := NewChecker(f.config)

	require.NotNil(t, restarted.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_PersistedListIsReverifiedAgainstTheCurrentAnchors(t *testing.T) {
	f := newFixture(t, false)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, party))))
	f.refreshed(t)

	// The anchors have moved on and no longer cover the signer, as they would
	// after the list-signing certificate was revoked. What is already on disk
	// has to stop counting, not only the next download.
	f.config.X509Context = NewTestLoteSigner(t).X509VerificationContext()
	restarted := NewChecker(f.config)

	require.Nil(t, restarted.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_NoSourcesGrantsNothing(t *testing.T) {
	checker := NewChecker(Config{})

	requireRefreshed(t, checker)
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{}))
}

func TestChecker_SourcesAreIndependent(t *testing.T) {
	// One list being unreachable must not cost the wallet the other one.
	signer := NewTestLoteSigner(t)
	good := NewTestLoteServer(t)
	bad := NewTestLoteServer(t)
	party := signer.NewTestPartyCertificate(t, "party.example.com", "")
	good.Serve(t, signer, NewTestList("urn:good", 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(ServiceTypeVerifier, party))))
	bad.Close()

	checker := NewChecker(Config{
		Sources:     []Source{bad.Source("urn:bad", false), good.Source("urn:good", false)},
		X509Context: signer.X509VerificationContext(),
	})
	requireRefreshFailed(t, checker)

	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestVerify_RejectsAJwsMintedForSomethingElse(t *testing.T) {
	// The `typ` header is what stops a JWS the same key signed for another
	// purpose from being replayed as a trusted list.
	signer := NewTestLoteSigner(t)
	raw := signer.SignListWithTyp(t, NewTestList(testListId, 1), "statuslist+jwt")

	_, err := verify(raw, signer.X509VerificationContext())

	require.ErrorContains(t, err, "typ")
}

func TestVerify_RejectsAListWithoutANextUpdate(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.NextUpdate = time.Time{}

	_, err := verify(signer.SignList(t, list), signer.X509VerificationContext())

	require.ErrorContains(t, err, "next_update")
}

func TestVerify_RejectsWithoutAnAnchorSet(t *testing.T) {
	signer := NewTestLoteSigner(t)

	_, err := verify(signer.SignList(t, NewTestList(testListId, 1)), nil)

	require.Error(t, err)
}

func TestVerify_RejectsGarbage(t *testing.T) {
	signer := NewTestLoteSigner(t)

	_, err := verify([]byte("not a jws"), signer.X509VerificationContext())

	require.Error(t, err)
}

// requireRefreshed refreshes and asserts every source held up.
func requireRefreshed(t *testing.T, checker *Checker) int {
	t.Helper()
	changed, err := checker.Refresh(context.Background())
	require.NoError(t, err)
	return changed
}

// requireRefreshFailed refreshes and asserts a source did not hold up.
func requireRefreshFailed(t *testing.T, checker *Checker) {
	t.Helper()
	_, err := checker.Refresh(context.Background())
	require.Error(t, err)
}
