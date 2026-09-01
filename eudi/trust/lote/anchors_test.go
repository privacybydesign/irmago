package lote

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The anchor list is a second document the wallet reads for something else: not
// parties to match, but CAs to install. These tests pin the wall between the two
// — a source delivers one kind of thing — and what an anchor entry is worth.

const testAnchorListId = "urn:yivi:trustanchors:test"

func testCa(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName(name+" Root"), testdata.PkiOption_None)
	_, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName(name), rootCert, rootKey, testdata.PkiOption_None, nil)
	return caCert
}

func anchorChecker(t *testing.T, signer *TestLoteSigner, server *TestLoteServer, ceiling clientmodels.TrustLevel) *Checker {
	t.Helper()
	return NewChecker(Config{
		Sources:     []Source{server.AnchorSource(testAnchorListId, signer, ceiling)},
		X509Context: signer.X509VerificationContext(),
	})
}

func TestAnchors_GrantedCaServicesAreDelivered(t *testing.T) {
	signer := NewTestLoteSigner(t)
	issuerCa, verifierCa := testCa(t, "Issuer CA"), testCa(t, "Verifier CA")

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1,
		NewTestEntity("Example CA Operator", "",
			NewTestCaService(trust.RoleIssuer, issuerCa, clientmodels.TrustLevel_Medium, "https://ca.example/issuer.crl"),
			NewTestCaService(trust.RoleVerifier, verifierCa, clientmodels.TrustLevel_High, "https://ca.example/verifier.crl"),
		)))
	checker := anchorChecker(t, signer, server, clientmodels.TrustLevel_High)
	require.Empty(t, checker.Anchors(), "nothing before the first fetch")

	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)

	anchors := checker.Anchors()
	require.Len(t, anchors, 2)
	require.Equal(t, trust.RoleIssuer, anchors[0].Role)
	require.Equal(t, issuerCa.Raw, anchors[0].Certificate.Raw)
	require.Equal(t, clientmodels.TrustLevel_Medium, anchors[0].Confers)
	require.Equal(t, []string{"https://ca.example/issuer.crl"}, anchors[0].CRLDistributionPoints)
	require.Equal(t, trust.RoleVerifier, anchors[1].Role)
	require.Equal(t, clientmodels.TrustLevel_High, anchors[1].Confers)

	// A CA is not a party: an anchor entry grants nothing to a session that turns
	// up with the CA's own certificate.
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleIssuer, trust.Evidence{Certificate: issuerCa}))
}

func TestAnchors_TheSourceCeilingCapsTheEntry(t *testing.T) {
	signer := NewTestLoteSigner(t)
	ca := testCa(t, "Ambitious CA")

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1,
		NewTestEntity("Operator", "", NewTestCaService(trust.RoleIssuer, ca, clientmodels.TrustLevel_High))))
	checker := anchorChecker(t, signer, server, clientmodels.TrustLevel_Medium)
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)

	anchors := checker.Anchors()
	require.Len(t, anchors, 1)
	require.Equal(t, clientmodels.TrustLevel_Medium, anchors[0].Confers,
		"an entry cannot promote itself past what its list may confer")
}

func TestAnchors_AnEntrySayingNothingConfersMedium(t *testing.T) {
	signer := NewTestLoteSigner(t)
	ca := testCa(t, "Quiet CA")

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1,
		NewTestEntity("Operator", "", NewTestCaService(trust.RoleIssuer, ca, clientmodels.TrustLevel_Unevaluated))))
	checker := anchorChecker(t, signer, server, clientmodels.TrustLevel_High)
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)

	require.Equal(t, clientmodels.TrustLevel_Medium, checker.Anchors()[0].Confers,
		"medium is the certificate channel's rung for anyone who is not Yivi")
}

func TestAnchors_APartyListsCaServicesInstallNothing(t *testing.T) {
	signer := NewTestLoteSigner(t)
	ca := testCa(t, "Smuggled CA")

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestList(testListId, 1,
		NewTestEntity("Operator", "", NewTestCaService(trust.RoleIssuer, ca, clientmodels.TrustLevel_High))))
	checker := NewChecker(Config{
		Sources:     []Source{server.Source(testListId, clientmodels.TrustLevel_High)},
		X509Context: signer.X509VerificationContext(),
	})
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)

	require.Empty(t, checker.Anchors(), "a party source delivers parties; a CA on it is not an anchor")
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleIssuer, trust.Evidence{Certificate: ca}),
		"and it is not a party either")
}

func TestAnchors_AnAnchorListsPartyServicesGrantNobody(t *testing.T) {
	const did = "did:web:party.example.com"
	signer := NewTestLoteSigner(t)

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1,
		NewTestEntity("Party", "", NewTestDidService(trust.RoleVerifier, did))))
	checker := anchorChecker(t, signer, server, clientmodels.TrustLevel_High)
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)

	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Identifiers: []string{did}}),
		"an anchor source delivers anchors; a party on it grants nothing")
	require.Empty(t, checker.Anchors())
}

func TestAnchors_TheSignerPinRefusesAnotherCertificate(t *testing.T) {
	signer := NewTestLoteSigner(t)
	ca := testCa(t, "Pinned CA")

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1,
		NewTestEntity("Operator", "", NewTestCaService(trust.RoleIssuer, ca, clientmodels.TrustLevel_Medium))))

	source := server.AnchorSource(testAnchorListId, signer, clientmodels.TrustLevel_High)
	source.SignerSKI = []byte("some other key")
	checker := NewChecker(Config{Sources: []Source{source}, X509Context: signer.X509VerificationContext()})

	_, err := checker.Refresh(context.Background())
	require.ErrorContains(t, err, "subject key identifier",
		"a certificate under the right CA is not enough: the anchor list names its signer")
	require.Empty(t, checker.Anchors())
}

func TestAnchors_AWithdrawnCaIsNotDelivered(t *testing.T) {
	signer := NewTestLoteSigner(t)
	ca := testCa(t, "Withdrawn CA")

	withdrawn := NewTestCaService(trust.RoleIssuer, ca, clientmodels.TrustLevel_Medium)
	withdrawn.Information.Status = ServiceStatusWithdrawn

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1, NewTestEntity("Operator", "", withdrawn)))
	checker := anchorChecker(t, signer, server, clientmodels.TrustLevel_High)
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)

	require.Empty(t, checker.Anchors(), "withdrawal is the anchor list's kill switch")
}

func TestAnchors_AnExpiredListDeliversNothing(t *testing.T) {
	signer := NewTestLoteSigner(t)
	ca := testCa(t, "Expiring CA")

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1,
		NewTestEntity("Operator", "", NewTestCaService(trust.RoleIssuer, ca, clientmodels.TrustLevel_Medium))))

	now := time.Now()
	checker := NewChecker(Config{
		Sources:     []Source{server.AnchorSource(testAnchorListId, signer, clientmodels.TrustLevel_High)},
		X509Context: signer.X509VerificationContext(),
		Now:         func() time.Time { return now },
	})
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)
	require.Len(t, checker.Anchors(), 1)

	now = now.Add(48 * time.Hour) // past NewTestList's day-long window
	require.Empty(t, checker.Anchors(), "past next_update the list is no evidence, anchors included")
}

// The M1 case: a list the wallet held past its next_update dropped out of every
// snapshot, so a re-issue with the very same entries lifts every party on it.
func TestRefresh_AnExpiredListRenewedWithTheSameEntriesIsAChange(t *testing.T) {
	const did = "did:web:steady.example.com"
	signer := NewTestLoteSigner(t)
	server := NewTestLoteServer(t)

	now := time.Now()
	list := NewTestList(testListId, 1, NewTestEntity("Steady", "", NewTestDidService(trust.RoleVerifier, did)))
	list.SchemeInformation.NextUpdate = now.Add(time.Hour)
	server.Serve(t, signer, list)

	checker := NewChecker(Config{
		Sources:     []Source{server.Source(testListId, clientmodels.TrustLevel_Medium)},
		X509Context: signer.X509VerificationContext(),
		Now:         func() time.Time { return now },
	})
	changed, err := checker.Refresh(context.Background())
	require.NoError(t, err)
	require.False(t, changed, "a first fetch is not a change")

	now = now.Add(2 * time.Hour)
	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Identifiers: []string{did}}), "expired")

	// Issued at the real clock — the signer signs at the real clock and clause 6.6.5
	// refuses a document dated after its signature — with a window that reaches
	// past the test's advanced clock.
	renewed := NewTestList(testListId, 2, NewTestEntity("Steady", "", NewTestDidService(trust.RoleVerifier, did)))
	renewed.SchemeInformation.NextUpdate = now.Add(24 * time.Hour)
	server.Serve(t, signer, renewed)

	changed, err = checker.Refresh(context.Background())
	require.NoError(t, err)
	require.True(t, changed, "every party on the list just went from low back to its rung; the app must redraw")
}

func TestValidateSources(t *testing.T) {
	signer := NewTestLoteSigner(t)
	good := Source{Key: "a", LoTEType: LoTETypeRecognizedParties, URL: "https://l.example/a"}
	anchor := Source{Key: "b", LoTEType: LoTETypeTrustAnchors, URL: "https://l.example/b", Delivers: DeliversAnchors, SignerSKI: signer.Cert.SubjectKeyId}

	require.NoError(t, ValidateSources([]Source{good, anchor}))
	require.NoError(t, ValidateSources(nil))

	for name, sources := range map[string][]Source{
		"empty key":            {{LoTEType: LoTETypeRecognizedParties, URL: "https://l.example"}},
		"duplicate key":        {good, good},
		"empty URL":            {{Key: "a", LoTEType: LoTETypeRecognizedParties}},
		"empty type":           {{Key: "a", URL: "https://l.example"}},
		"anchor without a pin": {{Key: "b", LoTEType: LoTETypeTrustAnchors, URL: "https://l.example", Delivers: DeliversAnchors}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, ValidateSources(sources))
		})
	}
}

func TestNewChecker_DropsAMisconfiguredSource(t *testing.T) {
	signer := NewTestLoteSigner(t)
	ca := testCa(t, "Unpinned CA")

	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestAnchorList(testAnchorListId, 1,
		NewTestEntity("Operator", "", NewTestCaService(trust.RoleIssuer, ca, clientmodels.TrustLevel_Medium))))

	unpinned := server.AnchorSource(testAnchorListId, signer, clientmodels.TrustLevel_High)
	unpinned.SignerSKI = nil
	checker := NewChecker(Config{Sources: []Source{unpinned}, X509Context: signer.X509VerificationContext()})

	_, err := checker.Refresh(context.Background())
	require.NoError(t, err, "the source was dropped, not consulted half-configured")
	require.Empty(t, checker.Anchors())
	require.EqualValues(t, 0, server.Hits(), "and never fetched")
}
