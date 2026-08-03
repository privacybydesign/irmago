package lote

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

const testListId = "yivi-test"

// listedVerifier is the list every test below starts from: one granted verifier,
// identified by its DID.
func listedVerifier(nextUpdate time.Time, sequenceNumber int64) List {
	return NewTestList(TestListOpts{
		Id:             testListId,
		SequenceNumber: sequenceNumber,
		NextUpdate:     nextUpdate,
		Providers: []TrustServiceProvider{
			GrantedVerifier("Listed Verifier", DidIdentity("did:web:verifier.example.com")),
		},
	})
}

func verifierEvidence() trust.Evidence {
	return trust.Evidence{Identifiers: []string{"did:web:verifier.example.com"}}
}

// newTestChecker returns a checker over one list served by server, with a clock
// the test drives. The returned setNow moves that clock, which is how the tests
// reach the validity window and the fetch backoff without sleeping.
func newTestChecker(t *testing.T, server *TestListServer, signer *TestListSigner) (checker *Checker, base time.Time, setNow func(time.Duration)) {
	t.Helper()
	base = time.Now()
	now := base
	checker = NewChecker([]RecognizedList{server.RecognizedList(testListId, signer)}, NewInMemoryStore())
	checker.nowFn = func() time.Time { return now }
	return checker, base, func(offset time.Duration) { now = base.Add(offset) }
}

func TestChecker_GrantedEntryVouchesForTheParty(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, base, _ := newTestChecker(t, server, signer)
	server.Serve(t, signer, listedVerifier(base.Add(time.Hour), 1))

	listing := checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence())

	require.NotNil(t, listing)
	require.Equal(t, testListId, listing.ListId)
	require.Equal(t, "Listed Verifier", listing.Name["en"])
	require.False(t, listing.OnboardedByYivi, "an unmarked entry is not one Yivi vouches for")
}

func TestChecker_UnlistedPartyIsNotVouchedFor(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, base, _ := newTestChecker(t, server, signer)
	server.Serve(t, signer, listedVerifier(base.Add(time.Hour), 1))

	listing := checker.Snapshot(context.Background()).Lookup(
		trust.RoleVerifier,
		trust.Evidence{Identifiers: []string{"did:web:stranger.example.com"}},
	)
	require.Nil(t, listing)
}

func TestChecker_GrantIsRoleTyped(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, base, _ := newTestChecker(t, server, signer)
	server.Serve(t, signer, listedVerifier(base.Add(time.Hour), 1))

	snapshot := checker.Snapshot(context.Background())
	require.NotNil(t, snapshot.Lookup(trust.RoleVerifier, verifierEvidence()))
	require.Nil(t, snapshot.Lookup(trust.RoleIssuer, verifierEvidence()),
		"a grant to verify is not a grant to issue")
}

func TestChecker_WithdrawnEntryVouchesForNothing(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, base, _ := newTestChecker(t, server, signer)

	list := listedVerifier(base.Add(time.Hour), 1)
	list.Providers[0].Services[0].Status = StatusWithdrawn
	server.Serve(t, signer, list)

	require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
}

func TestChecker_NoRecognizedListsVouchesForNothing(t *testing.T) {
	// The wallet as it ships today: no list is recognized, so the channel
	// contributes nothing and never reaches out.
	checker := NewChecker(nil, NewInMemoryStore())
	require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
}

// ========================================================================
// Degradation: every one of these is absent evidence, never an error
// ========================================================================

func TestChecker_DegradationsCapTheParty(t *testing.T) {
	signer := NewTestListSigner(t)

	t.Run("unreachable endpoint", func(t *testing.T) {
		server := NewTestListServer(t)
		checker, base, _ := newTestChecker(t, server, signer)
		server.Serve(t, signer, listedVerifier(base.Add(time.Hour), 1))
		server.Close()

		require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
	})

	t.Run("endpoint erroring", func(t *testing.T) {
		server := NewTestListServer(t)
		checker, _, _ := newTestChecker(t, server, signer)
		server.SetStatus(503)

		require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
	})

	t.Run("tampered signature", func(t *testing.T) {
		server := NewTestListServer(t)
		checker, base, _ := newTestChecker(t, server, signer)
		// Signed by a chain outside the anchors: the content is exactly right
		// and the signature is exactly wrong.
		server.Serve(t, NewTestListSigner(t), listedVerifier(base.Add(time.Hour), 1))

		require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
	})

	t.Run("expired next update", func(t *testing.T) {
		server := NewTestListServer(t)
		checker, base, _ := newTestChecker(t, server, signer)
		server.Serve(t, signer, listedVerifier(base.Add(-time.Minute), 1))

		require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
	})

	t.Run("identifier of another list", func(t *testing.T) {
		server := NewTestListServer(t)
		checker, base, _ := newTestChecker(t, server, signer)
		list := listedVerifier(base.Add(time.Hour), 1)
		list.SchemeInformation.ListIdentifier = "someone-elses-list"
		server.Serve(t, signer, list)

		require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()),
			"a list served at a recognized URL does not become that list")
	})
}

func TestChecker_SequenceRegressIsRejected(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, base, setNow := newTestChecker(t, server, signer)

	// Revision 5 lands and is stored.
	server.Serve(t, signer, listedVerifier(base.Add(time.Hour), 5))
	require.NotNil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))

	// It expires, and what the endpoint now serves is an older revision: a
	// rollback to a state in which some party's grant had not been taken away
	// yet. It is turned away, and the wallet is left with no list at all.
	setNow(2 * time.Hour)
	server.Serve(t, signer, listedVerifier(base.Add(4*time.Hour), 4))

	require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))

	// The same revision number again is not a regress, so a re-signed list with
	// a fresh validity window is accepted.
	setNow(3 * time.Hour)
	server.Serve(t, signer, listedVerifier(base.Add(5*time.Hour), 5))
	require.NotNil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
}

// ========================================================================
// Fetching
// ========================================================================

func TestChecker_StoredCopyIsReusedUntilItExpires(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, base, setNow := newTestChecker(t, server, signer)
	server.Serve(t, signer, listedVerifier(base.Add(time.Hour), 1))

	for range 3 {
		require.NotNil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
	}
	require.Equal(t, int64(1), server.Hits(), "a list still inside its validity window is not re-fetched")

	setNow(2 * time.Hour)
	server.Serve(t, signer, listedVerifier(base.Add(4*time.Hour), 2))
	require.NotNil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))
	require.Equal(t, int64(2), server.Hits(), "a list past its NextUpdate is fetched again")
}

func TestChecker_FailingEndpointIsRetriedOnATimer(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, _, setNow := newTestChecker(t, server, signer)
	server.SetStatus(503)

	for range 5 {
		checker.Snapshot(context.Background())
	}
	require.Equal(t, int64(1), server.Hits(),
		"a wallet whose list endpoint is down must not pay the fetch on every session")

	setNow(2 * fetchBackoff)
	checker.Snapshot(context.Background())
	require.Equal(t, int64(2), server.Hits(), "and must try again once the backoff runs out")
}

func TestChecker_SnapshotIsPinnedForItsSession(t *testing.T) {
	signer := NewTestListSigner(t)
	server := NewTestListServer(t)
	checker, base, setNow := newTestChecker(t, server, signer)
	server.Serve(t, signer, listedVerifier(base.Add(time.Hour), 1))

	session := checker.Snapshot(context.Background())
	require.NotNil(t, session.Lookup(trust.RoleVerifier, verifierEvidence()))

	// The verifier is delisted and the wallet picks the new list up.
	setNow(2 * time.Hour)
	server.Serve(t, signer, NewTestList(TestListOpts{
		Id:             testListId,
		SequenceNumber: 2,
		NextUpdate:     base.Add(4 * time.Hour),
	}))
	require.Nil(t, checker.Snapshot(context.Background()).Lookup(trust.RoleVerifier, verifierEvidence()))

	// The session that started before the refresh still decides the way it did
	// on its first party. Anything else would have the permission screen and the
	// disclosure it authorises disagree about who is being talked to.
	require.NotNil(t, session.Lookup(trust.RoleVerifier, verifierEvidence()))
}

// ========================================================================
// Matching
// ========================================================================

// testCertificate builds a certificate with the given subject key identifier
// and organizationIdentifier attribute. It is never verified here — matching
// reads a certificate the gate already accepted.
func testCertificate(t *testing.T, ski []byte, organizationId string) *x509.Certificate {
	t.Helper()
	subject := pkix.Name{CommonName: "verifier.example.com"}
	if organizationId != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: organizationId},
		}
	}
	raw, err := asn1.Marshal(ski) // stands in for DER: matching compares bytes
	require.NoError(t, err)
	return &x509.Certificate{
		Raw:          raw,
		SubjectKeyId: ski,
		Subject:      pkix.Name{CommonName: subject.CommonName, Names: subject.ExtraNames},
	}
}

func lookup(t *testing.T, provider TrustServiceProvider, evidence trust.Evidence) *trust.Listing {
	t.Helper()
	list := NewTestList(TestListOpts{Id: testListId, Providers: []TrustServiceProvider{provider}})
	snapshot := &Snapshot{entries: flatten(testListId, &list)}
	return snapshot.Lookup(trust.RoleVerifier, evidence)
}

func TestSnapshot_MatchesByCertificate(t *testing.T) {
	certificate := testCertificate(t, []byte{1, 2, 3}, "")
	provider := GrantedVerifier("Listed Verifier", CertificateIdentity(certificate))

	require.NotNil(t, lookup(t, provider, trust.Evidence{Certificate: certificate}))
	require.Nil(t, lookup(t, provider, trust.Evidence{Certificate: testCertificate(t, []byte{9, 9, 9}, "")}))
}

func TestSnapshot_MatchesBySubjectKeyIdentifier(t *testing.T) {
	certificate := testCertificate(t, []byte{1, 2, 3}, "")
	provider := GrantedVerifier("Listed Verifier", SkiIdentity(certificate))

	// A re-issued certificate for the same key: different bytes, same SKI.
	reissued := testCertificate(t, []byte{1, 2, 3}, "")
	reissued.Raw = []byte("a different certificate")
	require.NotNil(t, lookup(t, provider, trust.Evidence{Certificate: reissued}))

	require.Nil(t, lookup(t, provider, trust.Evidence{Certificate: testCertificate(t, []byte{4, 5, 6}, "")}))
}

func TestSnapshot_MatchesByOrganizationIdentifier(t *testing.T) {
	provider := GrantedVerifier("Listed Verifier")
	provider.OrganizationIdentifier = "NTRNL-12345678"

	require.NotNil(t, lookup(t, provider, trust.Evidence{
		Certificate: testCertificate(t, []byte{1, 2, 3}, "NTRNL-12345678"),
	}), "the organization is recognized, not one of its certificates")

	require.Nil(t, lookup(t, provider, trust.Evidence{
		Certificate: testCertificate(t, []byte{1, 2, 3}, "NTRNL-87654321"),
	}))
	require.Nil(t, lookup(t, provider, trust.Evidence{
		Certificate: testCertificate(t, []byte{1, 2, 3}, ""),
	}), "a certificate without an organization identifier matches no organization")
}

func TestSnapshot_MatchesByOtherIdentifier(t *testing.T) {
	provider := GrantedVerifier("Listed Verifier",
		DidIdentity("did:web:verifier.example.com"),
		UriIdentity("https://issuer.example.com"),
	)

	require.NotNil(t, lookup(t, provider, trust.Evidence{
		Identifiers: []string{"did:web:verifier.example.com"},
	}))
	require.NotNil(t, lookup(t, provider, trust.Evidence{
		Identifiers: []string{"https://issuer.example.com"},
	}), "one entry can name the several identifiers one party authenticates with")

	require.Nil(t, lookup(t, provider, trust.Evidence{
		Identifiers: []string{"decentralized_identifier:did:web:verifier.example.com"},
	}), "the entry names the DID, not the protocol framing around it")
	require.Nil(t, lookup(t, provider, trust.Evidence{}))
}

func TestSnapshot_CarriesTheCuratedDisplayMetadata(t *testing.T) {
	list := NewTestList(TestListOpts{Id: testListId, Providers: []TrustServiceProvider{{
		Name: map[string]string{"en": "Provider Name"},
		Services: []Service{{
			Type:                  ServiceTypeVerifier,
			Status:                StatusGranted,
			Name:                  map[string]string{"en": "Service Name", "nl": "Servicenaam"},
			LogoURI:               "https://list.example.com/logo.png",
			Identities:            []DigitalIdentity{DidIdentity("did:web:verifier.example.com")},
			AdditionalInformation: []string{QualifierOnboardedByYivi},
		}},
	}}})
	snapshot := &Snapshot{entries: flatten(testListId, &list)}

	listing := snapshot.Lookup(trust.RoleVerifier, verifierEvidence())
	require.NotNil(t, listing)
	require.Equal(t, "Service Name", listing.Name["en"])
	require.Equal(t, "Servicenaam", listing.Name["nl"])
	require.Equal(t, "https://list.example.com/logo.png", listing.LogoURI)
	require.True(t, listing.OnboardedByYivi, "the marking is parsed even though nothing ranks on it yet")
}

func TestSnapshot_FallsBackToTheProviderName(t *testing.T) {
	list := NewTestList(TestListOpts{Id: testListId, Providers: []TrustServiceProvider{{
		Name: map[string]string{"en": "Provider Name"},
		Services: []Service{{
			Type:       ServiceTypeVerifier,
			Status:     StatusGranted,
			Identities: []DigitalIdentity{DidIdentity("did:web:verifier.example.com")},
		}},
	}}})
	snapshot := &Snapshot{entries: flatten(testListId, &list)}

	listing := snapshot.Lookup(trust.RoleVerifier, verifierEvidence())
	require.NotNil(t, listing)
	require.Equal(t, "Provider Name", listing.Name["en"])
}

func TestFlatten_DropsServiceTypesTheWalletDoesNotImplement(t *testing.T) {
	list := NewTestList(TestListOpts{Id: testListId, Providers: []TrustServiceProvider{{
		Name: map[string]string{"en": "Timestamping Authority"},
		Services: []Service{{
			Type:       "http://uri.etsi.org/TrstSvc/Svctype/TSA",
			Status:     StatusGranted,
			Identities: []DigitalIdentity{DidIdentity("did:web:verifier.example.com")},
		}},
	}}})

	require.Empty(t, flatten(testListId, &list),
		"a grant for something the wallet does not ask about vouches for nothing it does")
}
