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

// memoryStore is a Store for the tests that need one to survive being handed to a
// second Checker. No lock: the checker touches its store only from Refresh and
// loadPersisted, both of which hold c.mu.
type memoryStore map[string][]byte

func (s memoryStore) Get(listId string) ([]byte, bool) {
	raw, ok := s[listId]
	return raw, ok
}

func (s memoryStore) Put(listId string, rawJws []byte) error {
	s[listId] = rawJws
	return nil
}

// fixture wires a checker against a mutable test server publishing one list.
type fixture struct {
	signer *TestLoteSigner
	server *TestLoteServer
	store  Store
	config Config
}

func newFixture(t *testing.T, confers clientmodels.TrustLevel) *fixture {
	t.Helper()
	signer := NewTestLoteSigner(t)
	server := NewTestLoteServer(t)
	store := memoryStore{}
	return &fixture{
		signer: signer,
		server: server,
		store:  store,
		config: Config{
			Sources:     []Source{server.Source(testListId, confers)},
			X509Context: signer.X509VerificationContext(),
			Store:       store,
		},
	}
}

// refreshed returns a checker that has pulled whatever the server publishes.
func (f *fixture) refreshed(t *testing.T) *Checker {
	t.Helper()
	checker := NewChecker(f.config)
	requireRefreshed(t, checker)
	return checker
}

func TestChecker_ListedVerifierIsGranted(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	verifier := f.signer.NewTestPartyCertificate(t, "verifier.example.com", "VATNL-000000001")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "VATNL-000000001",
			NewTestCertificateService(trust.RoleVerifier, verifier)),
	))

	listing := f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: verifier})

	require.NotNil(t, listing)
	require.Equal(t, testListId, listing.SourceKey)
	require.Equal(t, "Listed BV", listing.Name["en"])
	require.Equal(t, clientmodels.TrustLevel_Medium, listing.Level,
		"a listing confers what its source is configured with")
}

func TestChecker_UnlistedVerifierIsNotGranted(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	listed := f.signer.NewTestPartyCertificate(t, "listed.example.com", "")
	stranger := f.signer.NewTestPartyCertificate(t, "stranger.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, listed)),
	))

	snapshot := f.refreshed(t).Snapshot()

	require.Nil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{Certificate: stranger}))
}

func TestChecker_GrantsAreRoleTyped(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Issuing BV", "", NewTestCertificateService(trust.RoleIssuer, party)),
	))

	snapshot := f.refreshed(t).Snapshot()
	evidence := trust.Evidence{Certificate: party}

	require.NotNil(t, snapshot.Lookup(trust.RoleIssuer, evidence))
	require.Nil(t, snapshot.Lookup(trust.RoleVerifier, evidence),
		"trust as an issuer is not trust as a verifier")
}

func TestChecker_WithdrawnServiceIsNotGranted(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	service := NewTestCertificateService(trust.RoleVerifier, party)
	service.Information.Status = ServiceStatusWithdrawn
	f.server.Serve(t, f.signer, NewTestList(testListId, 1, NewTestEntity("Former BV", "", service)))

	require.Nil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

// Clause 6.6.0 NOTE 1, and the shape Yivi publishes. Getting it wrong is silent:
// a conformant list would verify, be stored, and grant nobody without logging.
func TestChecker_AServiceWithNoStatusIsGranted(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")

	service := NewTestCertificateService(trust.RoleVerifier, party)
	require.Empty(t, service.Information.Status, "the builder emits no status")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1, NewTestEntity("Listed BV", "", service)))

	listing := f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party})
	require.NotNil(t, listing, "a service with no status is granted")
	require.Equal(t, clientmodels.TrustLevel_Medium, listing.Level)
}

// Status vocabularies are per-scheme (Annex H's Pub-EAA list spells granted
// differently), so an unknown URI is a word we cannot interpret.
func TestChecker_AServiceWithAnUnrecognizedStatusIsNotGranted(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")

	service := NewTestCertificateService(trust.RoleVerifier, party)
	service.Information.Status = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified"
	f.server.Serve(t, f.signer, NewTestList(testListId, 1, NewTestEntity("Foreign BV", "", service)))

	require.Nil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}),
		"another scheme's granted-URI is not this scheme's")
}

func TestChecker_EntryKeyedOnSubjectKeyIdentifier(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "VATNL-000000002")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Key BV", "VATNL-000000002", NewTestSkiService(trust.RoleVerifier, party)),
	))

	require.NotNil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_OrganizationIdentifierIsPartOfTheKey(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "VATNL-000000003")
	// The entry names the right key but the wrong legal entity. Both halves of
	// the key have to hold, so it does not grant.
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Someone Else BV", "VATNL-999999999", NewTestSkiService(trust.RoleVerifier, party)),
	))

	require.Nil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_DidMatchesThroughOtherId(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	const did = "did:web:verifier.example.com"
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("DID BV", "", NewTestDidService(trust.RoleVerifier, did)),
	))

	snapshot := f.refreshed(t).Snapshot()

	require.NotNil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{
		Identifiers: []string{did, "decentralized_identifier:" + did},
	}))
	require.Nil(t, snapshot.Lookup(trust.RoleVerifier, trust.Evidence{
		Identifiers: []string{"did:web:someone-else.example.com"},
	}), "a DID is compared verbatim")
}

func TestChecker_ListingConfersTheSourcesLevel(t *testing.T) {
	// The identical document from two sources: the rung is the source's word, and
	// markings on an entry change nothing.
	for _, tc := range []struct {
		name     string
		confers  clientmodels.TrustLevel
		expected clientmodels.TrustLevel
	}{
		{"yivi's own list confers high", clientmodels.TrustLevel_High, clientmodels.TrustLevel_High},
		{"another recognized list confers medium", clientmodels.TrustLevel_Medium, clientmodels.TrustLevel_Medium},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.confers)
			party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
			f.server.Serve(t, f.signer, NewTestList(testListId, 1,
				NewTestEntity("Marked BV", "",
					NewTestCertificateService(trust.RoleVerifier, party, "onboarded-by-yivi")),
			))

			listing := f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party})

			require.NotNil(t, listing)
			require.Equal(t, tc.expected, listing.Level)
		})
	}
}

func TestChecker_TheStrongestGrantingListWins(t *testing.T) {
	// A party granted on two lists gets the better of the two words.
	signer := NewTestLoteSigner(t)
	party := signer.NewTestPartyCertificate(t, "party.example.com", "")
	granting := func(listId string) List {
		return NewTestList(listId, 1,
			NewTestEntity("Twice Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party)))
	}

	medium := NewTestLoteServer(t)
	medium.Serve(t, signer, granting("urn:medium"))
	yivis := NewTestLoteServer(t)
	yivis.Serve(t, signer, granting("urn:yivis"))

	checker := NewChecker(Config{
		// The weaker list first, so ordering alone cannot produce the answer.
		Sources: []Source{
			medium.Source("urn:medium", clientmodels.TrustLevel_Medium),
			yivis.Source("urn:yivis", clientmodels.TrustLevel_High),
		},
		X509Context: signer.X509VerificationContext(),
	})
	requireRefreshed(t, checker)

	listing := checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party})
	require.NotNil(t, listing)
	require.Equal(t, clientmodels.TrustLevel_High, listing.Level)
	require.Equal(t, "urn:yivis", listing.SourceKey)
}

func TestChecker_ServiceNameOverridesTheEntityName(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	service := NewTestCertificateService(trust.RoleVerifier, party)
	service.Information.Name = MultiLang{"en": "The Service"}
	service.Information.Extensions = append(service.Information.Extensions,
		YiviExtension{LogoURI: "https://example.com/service.png"})
	entity := NewTestEntity("The Operator", "", service)
	entity.Information.Extensions = append(entity.Information.Extensions,
		YiviExtension{LogoURI: "https://example.com/operator.png"})
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
				// Signed by a key that chains to nothing the wallet trusts.
				impostor := NewTestLoteSigner(t)
				f.server.Serve(t, impostor, NewTestList(testListId, 1))
			},
		},
		{
			name: "expired next_update",
			degrade: func(t *testing.T, f *fixture, _ *TestLoteSigner) {
				list := NewTestList(testListId, 1)
				list.SchemeInformation.NextUpdate = time.Now().Add(-time.Hour)
				// Sign refuses to publish something already expired, so this one is
				// assembled by hand: the wallet still has to cope with meeting it.
				f.server.ServeRaw(t, f.signer, list)
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, clientmodels.TrustLevel_Medium)
			party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
			tc.degrade(t, f, f.signer)

			checker := NewChecker(f.config)
			// Reported for the log; nothing reaches a session.
			requireRefreshFailed(t, checker)

			require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
		})
	}
}

// What a list calls itself is not checked. SchemeName is the operator's to
// reword — the EU's own list puts a whole sentence there — and the wallet files
// documents under Source.Key, which is local and never published. So a document
// naming another list is adopted, and the entities on it grant.
//
// What stops one list standing in for another is the LoTEType check
// (TestChecker_RejectsAListDeclaringAnotherLoTEType) and, between environments,
// their separate signing CAs. Losing this case is the price of a name the
// operator can change without an app release.
func TestChecker_DoesNotCareWhatTheListCallsItself(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	verifier := f.signer.NewTestPartyCertificate(t, "verifier.example.com", "")
	f.server.Serve(t, f.signer, NewTestList("urn:yivi:trustlist:some-other-name", 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, verifier)),
	))

	listing := f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: verifier})

	require.NotNil(t, listing, "the document's own name is not compared against anything")
	require.Equal(t, testListId, listing.SourceKey, "the listing carries the source's key, not the document's name")
}

func TestChecker_SequenceNumberMayNotRegress(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	granting := NewTestList(testListId, 7,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party)))
	f.server.Serve(t, f.signer, granting)

	checker := f.refreshed(t)
	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))

	// A correctly signed, still-current older issue in which the party was not yet
	// listed. Adopting it would silently un-list everybody added since.
	f.server.Serve(t, f.signer, NewTestList(testListId, 6))
	requireRefreshFailed(t, checker)

	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}),
		"the newer list the wallet already held stays in force")
}

func TestChecker_ReissueWithTheSameSequenceNumberIsAccepted(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 3))

	checker := f.refreshed(t)
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))

	f.server.Serve(t, f.signer, NewTestList(testListId, 3,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party))))
	requireRefreshed(t, checker)

	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_AListPastItsNextUpdateStopsGranting(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	list := NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party)))
	list.SchemeInformation.NextUpdate = time.Now().Add(time.Hour)
	f.server.Serve(t, f.signer, list)

	// A clock the test moves past the list's next_update, standing in for a wallet
	// that has not managed to refresh in a while.
	now := time.Now()
	f.config.Now = func() time.Time { return now }
	checker := f.refreshed(t)
	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))

	now = now.Add(2 * time.Hour)

	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}),
		"a list past its next_update is no evidence, not stale evidence")
}

func TestChecker_SnapshotIsPinned(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party))))

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
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 4,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party))))
	f.refreshed(t)

	// A fresh checker over the same store, server gone: everything comes off disk.
	f.server.Close()
	restarted := NewChecker(f.config)

	require.NotNil(t, restarted.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestChecker_PersistedListIsReverifiedAgainstTheCurrentAnchors(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party))))
	f.refreshed(t)

	// The anchors no longer cover the signer, as after a revocation: what is
	// already on disk has to stop counting, not only the next download.
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
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party))))
	bad.Close()

	checker := NewChecker(Config{
		Sources: []Source{
			bad.Source("urn:bad", clientmodels.TrustLevel_Medium),
			good.Source("urn:good", clientmodels.TrustLevel_Medium),
		},
		X509Context: signer.X509VerificationContext(),
	})
	requireRefreshFailed(t, checker)

	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

func TestVerify_RejectsAJwsMintedForSomethingElse(t *testing.T) {
	// The `typ` header stops a JWS the same key signed for another purpose from
	// being replayed as a trusted list.
	signer := NewTestLoteSigner(t)
	raw := signer.SignListWithTyp(t, NewTestList(testListId, 1), "statuslist+jwt")

	_, err := verify(raw, signer.X509VerificationContext(), nil)

	require.ErrorContains(t, err, "typ")
}

// RFC 7515 clause 4.1.11: a `crit` header names parameters the producer insists
// the recipient understands. This verifier reads no JAdES signed parameter, so
// every one of them is unrecognized and the signature is unacceptable.
//
// The test exists because jwx defaults crit validation off: drop
// jws.WithCritValidation from verify() and a document that says "you must
// understand sigT" is accepted by a wallet that does not, silently. Every LoTE the
// European Commission's reference implementation publishes marks its signing time
// critical, so this is the shape of a real third-party list, not a synthetic one.
func TestVerify_RejectsASignatureWithAnUnderstoodExtensionItCannotHonour(t *testing.T) {
	signer := NewTestLoteSigner(t)
	raw := signer.SignListWithHeaders(t, NewTestList(testListId, 1), LoteTyp, map[string]any{
		"sigT": "2026-08-21T09:00:00Z",
		"crit": []string{"sigT"},
	})

	_, err := verify(raw, signer.X509VerificationContext(), nil)

	require.ErrorContains(t, err, "crit")
	require.ErrorContains(t, err, "sigT")
}

// The counterpart: the headers Yivi does emit carry no `crit`, so enabling the
// check costs nothing on our own documents.
func TestVerify_AcceptsOurOwnHeadersWithCritValidationOn(t *testing.T) {
	signer := NewTestLoteSigner(t)

	verified, err := verify(signer.SignList(t, NewTestList(testListId, 1)), signer.X509VerificationContext(), nil)

	require.NoError(t, err)
	require.NotNil(t, verified)
}

func TestVerify_RejectsAListWithoutANextUpdate(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.NextUpdate = time.Time{}

	// Sign refuses this document (clause 6.6.5 has nothing to check against), so
	// the fixture takes the raw path: the point is what verification rejects.
	_, err := verify(signer.SignListRaw(t, list), signer.X509VerificationContext(), nil)

	require.ErrorContains(t, err, "NextUpdate")
}

// The type URI is pinned alongside the identity, so a list of the wrong kind is
// refused even when it names itself as expected.
func TestChecker_RejectsAListDeclaringAnotherLoTEType(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.LoTEType = "https://yivi.app/19602/LoTEType/SomethingElse"
	f.server.Serve(t, f.signer, list)

	_, err := NewChecker(f.config).Refresh(context.Background())

	require.ErrorContains(t, err, "LoTEType")
}

func TestVerify_RejectsWithoutAnAnchorSet(t *testing.T) {
	signer := NewTestLoteSigner(t)

	_, err := verify(signer.SignList(t, NewTestList(testListId, 1)), nil, nil)

	require.Error(t, err)
}

func TestVerify_RejectsGarbage(t *testing.T) {
	signer := NewTestLoteSigner(t)

	_, err := verify([]byte("not a jws"), signer.X509VerificationContext(), nil)

	require.Error(t, err)
}

func requireRefreshed(t *testing.T, checker *Checker) {
	t.Helper()
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)
}

func requireRefreshFailed(t *testing.T, checker *Checker) {
	t.Helper()
	_, err := checker.Refresh(context.Background())
	require.Error(t, err)
}

// The regression the per-handle union exists to prevent. Before it, evidence
// carrying a certificate short-circuited to the certificate branch, which a
// DID-keyed entry never matched, and the party silently lost its rung.
func TestChecker_AttestedDidPartyKeepsItsDidKeyedListing(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_High)
	const did = "did:web:issuer.example.com"
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Listed DID BV", "", NewTestDidService(trust.RoleIssuer, did)),
	))

	// The party now also carries an attesting certificate.
	attestation := f.signer.NewTestPartyCertificate(t, "issuer.example.com", "VATNL-000000010")

	listing := f.refreshed(t).Snapshot().Lookup(trust.RoleIssuer, trust.Evidence{
		Certificate: attestation,
		Identifiers: []string{did},
	})
	require.NotNil(t, listing, "a DID-keyed entry still grants a party that has since attested its key")
	require.Equal(t, "Listed DID BV", listing.Name["en"])
}

// The other direction of the union: a DID party can be listed by the certificate
// it attested with, and its identifier need never appear in the entry.
func TestChecker_CertificateKeyedEntryGrantsADidParty(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_High)
	attestation := f.signer.NewTestPartyCertificate(t, "issuer.example.com", "VATNL-000000011")
	f.server.Serve(t, f.signer, NewTestList(testListId, 1,
		NewTestEntity("Keyed DID BV", "VATNL-000000011",
			NewTestSkiService(trust.RoleIssuer, attestation)),
	))

	listing := f.refreshed(t).Snapshot().Lookup(trust.RoleIssuer, trust.Evidence{
		Certificate: attestation,
		Identifiers: []string{"did:web:issuer.example.com"},
	})
	require.NotNil(t, listing, "a certificate/SKI entry grants a DID party by its attested key")
}

// The mutation guard for the per-handle rule: a failed certificate handle must
// not be rescued into a grant by the mere presence of identifiers.
func TestChecker_ReassignedKeyIsNotRescuedByIdentifiers(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_High)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "VATNL-000000012")
	// Right key, wrong legal entity, and a DID OtherId that does not match the
	// party's identifier.
	entry := NewTestEntity("Someone Else BV", "VATNL-999999999",
		NewTestSkiService(trust.RoleVerifier, party))
	entry.Services[0].Information.DigitalIdentity.OtherIds = []string{"did:web:someone-else.example.com"}
	f.server.Serve(t, f.signer, NewTestList(testListId, 1, entry))

	require.Nil(t, f.refreshed(t).Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{
		Certificate: party,
		Identifiers: []string{"did:web:party.example.com"},
	}), "a reassigned key stays refused; identifiers present in the evidence do not rescue it")
}
