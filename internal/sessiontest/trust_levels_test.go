package sessiontest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The trust ladder as real protocol sessions: both roles at their rungs, the
// rules that keep a rung honest, and the one rule that still blocks a session.
//
// Each test publishes its own LoTE from an in-process server and points the
// wallet at it through client.Config.RecognizedTrustLists, so nothing depends on
// a published list existing.
//
// How a counterparty authenticates decides the channel a test can reach a rung
// through:
//
//   - The veramo OpenID4VCI issuer (preAuthIssuerURL) signs with did:web, so it
//     climbs through the list channel only. List it under [testIssuerDid].
//   - The EUDI Python PID issuer signs with `x5c` under an anchored CA, so it
//     reaches high by certificate with no list (eudi_pid_python_issuer_test.go).
//   - The EUDI Kotlin verifier authenticates with a Yivi-issued certificate that
//     also carries the attribute authorization the over-ask test exceeds
//     (testdata/eudi/verifier/verifier_scheme_data.json).
//   - The veramo verifier authenticates with a did:jwk generated at runtime, so a
//     test that lists it reads the DID off a first session's Requestor.Id.
//
// A new rung is therefore a new entry on that test's list: NewTestDidService,
// NewTestCertificateService or NewTestSkiService. The rung an entry confers is
// its source's — TrustLevel_High stands in for Yivi's own list, TrustLevel_Medium
// for any other recognized one.
//
// The degradation matrix and the typed gate error live in
// eudi/openid4vp/client_lote_test.go and client_trust_test.go and in
// eudi/openid4vci/session_trust_test.go; persistence and transitions in
// client/trust_list_test.go; log columns in eudi/services/log_service_test.go;
// display mapping in irma/display_test.go.

const testTrustListId = "urn:yivi:trustlist:sessiontest"

// The DID the veramo OpenID4VCI test issuer signs with, and so what a list must
// name to vouch for it.
const testIssuerDid = "did:web:localhost%3A8443:test-issuer:.well-known"

func testSessionHandlerForTrustLevels(t *testing.T) {
	t.Run("issuer listed on a medium list ranks medium", testListedIssuerRanksMedium)
	t.Run("issuer listed on yivi's list ranks high", testIssuerOnYivisListRanksHigh)
	t.Run("a marked entry on a medium list stays medium", testMarkedEntryOnMediumListStaysMedium)
	t.Run("issuer listed as verifier only stays low", testIssuerListedInTheWrongRoleStaysLow)
	t.Run("unreachable list leaves the issuer low and issuing", testUnreachableListLeavesIssuerLow)
	t.Run("over-ask fails at the top rung", testOverAskFailsAtTopRung)
	t.Run("stored credential follows the list, logs do not", testStoredCredentialFollowsTheList)
	t.Run("verifier rungs follow the lists", testVerifierRungsFollowTheLists)
	t.Run("disclosure candidates rank the issuer too", testDisclosureCandidatesRankTheIssuer)
	t.Run("an unknown-CA verifier ranks low and proceeds", testUnknownCaVerifierRanksLowAndProceeds)
	t.Run("an unknown-CA verifier listed on yivi's list ranks high", testUnknownCaVerifierListedOnYivisListRanksHigh)
	t.Run("a third-party CA verifier ranks medium", testThirdPartyCaVerifierRanksMedium)
	t.Run("a broken request reports the typed error", testBrokenRequestReportsTypedError)
	t.Run("certificate keying needs both halves", testCertificateKeyingNeedsBothHalves)
	t.Run("an issuer keyed on its certificate ranks and renders", testIssuerKeyedOnItsCertificate)
}

// One verifier up all three rungs. The first, unvouched-for run still discloses,
// which is the verifier side of fail-soft; the wallet consults two lists, so the
// climb from medium to high is a change of source, not of entry.
func testVerifierRungsFollowTheLists(t *testing.T) {
	const mediumListId = testTrustListId + ":medium"
	const yiviListId = testTrustListId + ":yivi"

	signer := lote.NewTestLoteSigner(t)
	mediumServer := lote.NewTestLoteServer(t)
	yiviServer := lote.NewTestLoteServer(t)

	mediumServer.Serve(t, signer, lote.NewTestList(mediumListId, 1))
	yiviServer.Serve(t, signer, lote.NewTestList(yiviListId, 1))

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{
			mediumServer.Source(mediumListId, clientmodels.TrustLevel_Medium),
			yiviServer.Source(yiviListId, clientmodels.TrustLevel_High),
		})
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, testCredentialSdJwt, testCredentialClaims)

	unlisted := discloseToVeramoVerifier(t, c, 2, sessionHandler)
	require.Equal(t, clientmodels.TrustLevel_Low, unlisted.Requestor.TrustLevel,
		"a verifier no list vouches for ranks low, and still gets its disclosure")
	require.Equal(t, "test-verifier", unlisted.Requestor.Name,
		"with nothing curated to go on, the verifier is shown under the name it gives itself")

	verifierDid := unlisted.Requestor.Id
	require.NotEmpty(t, verifierDid, "a verifier without a certificate is identified by its DID")

	mediumServer.Serve(t, signer, lote.NewTestList(mediumListId, 2,
		lote.NewTestEntity("Curated Verifier BV", "",
			lote.NewTestDidService(trust.RoleVerifier, verifierDid))))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	listed := discloseToVeramoVerifier(t, c, 3, sessionHandler)
	require.Equal(t, clientmodels.TrustLevel_Medium, listed.Requestor.TrustLevel,
		"the same verifier, granted on a recognized list that is not Yivi's, ranks medium")
	require.Equal(t, "Curated Verifier BV", listed.Requestor.Name,
		"the curated name on the entry outranks the name the verifier gives itself")

	yiviServer.Serve(t, signer, lote.NewTestList(yiviListId, 2,
		lote.NewTestEntity("Curated Verifier BV", "",
			lote.NewTestDidService(trust.RoleVerifier, verifierDid))))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	onYivisList := discloseToVeramoVerifier(t, c, 4, sessionHandler)
	require.Equal(t, clientmodels.TrustLevel_High, onYivisList.Requestor.TrustLevel,
		"an entry on Yivi's own list reaches the top rung: being listed is being onboarded")
	require.True(t, onYivisList.Requestor.TrustLevel.IsVouchedFor())
}

// The second place a stored credential's issuer is ranked at read: the disclosure
// planner. A credential showing one rung in the wallet and another in a session
// would be the visible bug.
func testDisclosureCandidatesRankTheIssuer(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_Medium)})
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, testCredentialSdJwt, testCredentialClaims)
	require.Equal(t, clientmodels.TrustLevel_Low, candidateIssuerLevel(t, c, 2, sessionHandler),
		"nobody vouches for the issuer, in the disclosure plan as in the credential list")

	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed Issuer BV", "",
			lote.NewTestDidService(trust.RoleIssuer, testIssuerDid))))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Medium, candidateIssuerLevel(t, c, 3, sessionHandler),
		"the disclosure plan promotes the issuer on the next read, like the credential list")
	require.Equal(t, clientmodels.TrustLevel_Medium, storedIssuerLevel(t, c),
		"and the two read paths agree")
}

// The "X.509 → unknown CA" row: a chain the wallet cannot trace proves nothing,
// so its holder is low with self-asserted contents. Same verifier as everywhere
// else; only this wallet anchors no CA.
func testUnknownCaVerifierRanksLowAndProceeds(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, clientHandler, sessionHandler := newTestClient(t, testClient{Locale: "en", NoVerifierCA: true})
	defer c.Close()
	c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	session := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler, createEmailAuthRequestRequest()).ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel,
		"a certificate no anchor stands behind is evidentially a self-asserted key")
	require.Nil(t, session.Requestor.Image,
		"nothing an unanchored certificate carries may render a logo")
}

// max(certificate, list) with the certificate channel silent: a party the wallet
// cannot trace still reaches the top rung through an entry keyed on that very
// certificate.
func testUnknownCaVerifierListedOnYivisListRanksHigh(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	const curatedName = "Listed Stranger BV"
	verifierLeaf := eudiVerifierLeaf(t)

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity(curatedName, subjectOrganizationIdentifier(t, verifierLeaf),
			lote.NewTestSkiService(trust.RoleVerifier, verifierLeaf))))

	c, clientHandler, sessionHandler := newTestClient(t, testClient{
		Locale:       "en",
		LoteRoot:     signer.RootCert,
		TrustLists:   []lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_High)},
		NoVerifierCA: true,
	})
	defer c.Close()
	c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, clientHandler.AwaitEnrollmentResult())
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	session := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler, createEmailAuthRequestRequest()).ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel,
		"a list entry lifts a party whose certificate channel is silent all the way to high")
	require.Equal(t, curatedName, session.Requestor.Name,
		"and the curated name is what the user sees")
}

// Medium by certificate: the CA every other test installs as a stand-in for
// Yivi's is pinned here as a third-party anchor, so the same verifier lands one
// rung lower — still under the name its CA attested.
func testThirdPartyCaVerifierRanksMedium(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, clientHandler, sessionHandler := newTestClient(t, testClient{
		Locale: "en",
		// ...not installed at high, but pinned as a third-party anchor at medium.
		NoVerifierCA:         true,
		ExtraVerifierAnchors: []eudi.ExtraTrustAnchor{{PEM: testdata.VerifierCACertBytes, Confers: clientmodels.TrustLevel_Medium}},
	})
	defer c.Close()
	c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	session := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler, createEmailAuthRequestRequest()).ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	require.Equal(t, clientmodels.TrustLevel_Medium, session.Requestor.TrustLevel,
		"an anchored third-party CA confers medium: somebody vouches, but not Yivi")
	require.Equal(t, "Yivi B.V.", session.Requestor.Name,
		"shown under the organisation name its CA attested")
}

// The state that is not a rung: a verifier the wallet cannot authenticate at all
// is a session failure the app must be able to name.
func testBrokenRequestReportsTypedError(t *testing.T) {
	c, _, sessionHandler := instantiateClient(t, nil, "en")
	defer c.Close()

	requestJwt := unresolvableDidAuthRequest(t)
	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, requestJwt)
	}))
	defer requestServer.Close()

	startOpenID4VPDisclosureSession(t, c, 1, "openid4vp://?request_uri="+url.QueryEscape(requestServer.URL))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Status_Error, session.Status)
	require.NotNil(t, session.Error)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, session.Error.ErrorType,
		"a rejected party must be distinguishable from a network or protocol failure")
	require.Nil(t, session.DisclosurePlan, "nothing may be offered for disclosure")
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, session.Requestor.TrustLevel,
		"a party that failed the gate has no rung: it was never evaluated")
}

func unresolvableDidAuthRequest(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return testdata.CreateTestAuthorizationRequestJWTWithClientId(
		"decentralized_identifier:did:web:localhost%3A1", key, &x509.Certificate{},
		func(token *jwt.Token) { delete(token.Header, "x5c") },
	)
}

// The transition end to end: a credential issued while nobody vouches for its
// issuer reads at the rung the list says now, and delisting demotes it back — no
// level column, no migration. The activity log keeps the rung its session showed.
//
// Mutation check: freezing the rung at issuance makes both moves read low.
func testStoredCredentialFollowsTheList(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_Medium)})
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, testCredentialSdJwt, testCredentialClaims)
	require.Equal(t, clientmodels.TrustLevel_Low, storedIssuerLevel(t, c),
		"nobody vouched for the issuer at issuance time")
	loggedLevel := issuanceLogIssuerLevel(t, c)
	require.Equal(t, clientmodels.TrustLevel_Low, loggedLevel)

	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed Issuer BV", "", lote.NewTestDidService(trust.RoleIssuer, testIssuerDid))))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Medium, storedIssuerLevel(t, c),
		"the stored credential promotes on the next read")
	require.Equal(t, loggedLevel, issuanceLogIssuerLevel(t, c),
		"the activity log keeps the rung the session showed")

	// Delisted: the entry is gone from a newer issue of the same list.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 2))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Low, storedIssuerLevel(t, c),
		"a delisted issuer demotes on the next read")
	require.Equal(t, loggedLevel, issuanceLogIssuerLevel(t, c),
		"and the log still does not follow")
}

// ----------------------------------------------------------------------------
// Issuer rungs
// ----------------------------------------------------------------------------

// An entry on a list that is not Yivi's own is somebody vouching, but not Yivi.
func testListedIssuerRanksMedium(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_Medium,
		lote.NewTestDidService(trust.RoleIssuer, testIssuerDid))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Medium)
}

// Being on Yivi's own list is being onboarded, the same word a scheme certificate
// gives.
func testIssuerOnYivisListRanksHigh(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_High,
		lote.NewTestDidService(trust.RoleIssuer, testIssuerDid))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_High)
}

// The rung is the source's word, never the entry's, so an entry decorating itself
// with a marking changes nothing.
//
// Mutation check: entry-level lifting in lote.listingOf makes this read high.
func testMarkedEntryOnMediumListStaysMedium(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_Medium,
		lote.NewTestDidService(trust.RoleIssuer, testIssuerDid, "onboarded-by-yivi"))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Medium)
}

// Trust as a verifier is not trust as an issuer: same party, same list, wrong
// grant.
func testIssuerListedInTheWrongRoleStaysLow(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_High,
		lote.NewTestDidService(trust.RoleVerifier, testIssuerDid))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Low)
}

// The fail-soft floor from both sides: an unreachable list is absent evidence,
// and an issuer nobody vouches for still issues.
//
// Mutation check: refusing a low-ranking issuer, or surfacing the list failure
// into the session, fails here.
func testUnreachableListLeavesIssuerLow(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	source := server.Source(testTrustListId, clientmodels.TrustLevel_High)
	server.Close()

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert, []lote.Source{source})
	defer c.Close()

	require.Error(t, c.RefreshTrustLists(context.Background()))

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Low)
}

// ----------------------------------------------------------------------------
// Grant violations still block
// ----------------------------------------------------------------------------

// The one hard rule: a trust level never blocks a session, but a request
// exceeding what the party's certificate authorizes always does — asserted here at
// the highest rung.
func testOverAskFailsAtTopRung(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	// The highest rung there is — its certificate still bounds what it may ask for.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Yivi B.V.", "",
			lote.NewTestCertificateService(trust.RoleVerifier,
				signer.NewTestPartyCertificate(t, "unused-party", "")))))

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_High)})
	defer c.Close()
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	// Not among the attribute sets the certificate authorizes
	// (testdata/eudi/verifier/verifier_scheme_data.json).
	overAsk := createAuthRequestRequestWithDcql(`
		  {
			"credentials": [
			  {
				"id": "32f54163-7166-48f1-93d8-ff217bdb0653",
				"format": "dc+sd-jwt",
				"meta": {
					"vct_values": ["irma-demo.MijnOverheid.address"]
				},
				"claims": [
				  {
					"path": ["street"]
				  }
				]
			  }
			]
		  }
		`)

	session := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler, overAsk).ClientSession
	require.Equal(t, clientmodels.Status_Error, session.Status,
		"a request beyond the certificate's authorization fails however well vouched-for the verifier is")
	require.Nil(t, session.DisclosurePlan, "nothing may be offered for disclosure")
}

// The negative half of certificate keying: an entry naming the right key but the
// wrong legal entity grants nobody, or an entry would keep granting the entity a
// key was reassigned to.
//
// A validated certificate is high whatever the list says, so the assertion is the
// absence of the curated name. The positive case is in
// published_trust_list_test.go.
func testCertificateKeyingNeedsBothHalves(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	const curatedName = "Should Not Show BV"
	verifierLeaf := eudiVerifierLeaf(t)

	for _, tc := range []struct {
		name  string
		entry func(t *testing.T, signer *lote.TestLoteSigner) lote.Entity
	}{
		{
			name: "the right key with the wrong legal entity",
			entry: func(t *testing.T, _ *lote.TestLoteSigner) lote.Entity {
				return lote.NewTestEntity(curatedName, "VATNL-999999999",
					lote.NewTestSkiService(trust.RoleVerifier, verifierLeaf))
			},
		},
		{
			name: "a key that is not the verifier's",
			entry: func(t *testing.T, signer *lote.TestLoteSigner) lote.Entity {
				stranger := signer.NewTestPartyCertificate(t, "stranger.example.com", "")
				return lote.NewTestEntity(curatedName, "",
					lote.NewTestSkiService(trust.RoleVerifier, stranger))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := lote.NewTestLoteSigner(t)
			server := lote.NewTestLoteServer(t)
			server.Serve(t, signer, lote.NewTestList(testTrustListId, 1, tc.entry(t, signer)))

			c, clientHandler, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
				[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_High)})
			defer c.Close()
			c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
			require.NoError(t, clientHandler.AwaitEnrollmentResult())
			require.NoError(t, c.RefreshTrustLists(context.Background()))

			session := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler, createEmailAuthRequestRequest()).ClientSession
			requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

			require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel,
				"the certificate channel is untouched by a list entry that does not match")
			require.NotEqual(t, curatedName, session.Requestor.Name,
				"an entry that does not match must not lend the party its curated name")
		})
	}
}

// The issuer keying path: same matchesIdentity as the verifier's, but the
// certificate comes off the SD-JWT VC rather than a request. Keyed on the SKI of
// the EUDI Python PID issuer's committed leaf, with no organization identifier.
func testIssuerKeyedOnItsCertificate(t *testing.T) {
	const curatedName = "Curated PID Issuer BV"

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity(curatedName, "",
			lote.NewTestSkiService(trust.RoleIssuer, eudiPidIssuerLeaf(t)))))

	c, _, sessionHandler := instantiateClientWithTrustLists(t, readEudiPidIssuerPyCA(t), "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_Medium)})
	defer c.Close()
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	offer := createPidOfferViaPythonIssuer(t, samplePidUserData())
	startOpenID4VCISession(t, c, 1, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true, TransactionCode: &offer.TxCode},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel,
		"an x5c issuer under the wallet's anchors is high through the certificate channel")
	require.Equal(t, curatedName, session.Requestor.Name,
		"and a list entry keyed on that certificate lends it the curated name")
}

// The committed certificate the EUDI Python PID issuer signs with, mounted into
// the container as issuer.der.
func eudiPidIssuerLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	return certFromPemFile(t, "eudi-pid-issuer-py", "certs", "issuer.pem")
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// A wallet whose one recognized list carries the veramo test issuer under the
// given service, already fetched.
func clientWithIssuerList(t *testing.T, confers clientmodels.TrustLevel, service lote.Service) (*client.Client, *MockSessionHandler) {
	t.Helper()

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed Issuer BV", "", service)))

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, confers)})
	t.Cleanup(func() { _ = c.Close() })

	require.NoError(t, c.RefreshTrustLists(context.Background()))
	return c, sessionHandler
}

const testCredentialSdJwt = "TestCredentialSdJwt"

const testCredentialClaims = `{
	"given_name": "Trust",
	"family_name": "Ladder",
	"email": "trust@example.com"
}`

func storedIssuerLevel(t *testing.T, c *client.Client) clientmodels.TrustLevel {
	t.Helper()
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	return creds[0].Issuer.TrustLevel
}

func issuanceLogIssuerLevel(t *testing.T, c *client.Client) clientmodels.TrustLevel {
	t.Helper()
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Issuance {
			require.NotNil(t, logs[i].IssuanceLog)
			return logs[i].IssuanceLog.Issuer.TrustLevel
		}
	}
	t.Fatal("no issuance log found")
	return clientmodels.TrustLevel_Unevaluated
}

// Runs one full disclosure and returns the session state the permission screen
// was built from. It completes, so every rung this is called at is also asserted
// not to block.
func discloseToVeramoVerifier(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
) clientmodels.SessionState {
	t.Helper()

	verifierSession := createVeramoVerifierDcqlSession(t)
	startOpenID4VPDisclosureSession(t, c, sessionId, verifierSession.RequestUri)

	permission := awaitSessionState(t, sessionHandler)
	requireSessionState(t, permission, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	chosen := permission.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, permission.Id, makeDisclosureChoice(chosen))

	done := awaitSessionState(t, sessionHandler)
	requireSessionState(t, done, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	return permission
}

// Reads the issuer rung off the owned credential a disclosure plan offers, then
// completes the session so the next one can run.
func candidateIssuerLevel(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
) clientmodels.TrustLevel {
	t.Helper()

	permission := discloseToVeramoVerifier(t, c, sessionId, sessionHandler)
	option := permission.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.NotEmpty(t, option.Credentials, "the plan must offer a credential the wallet holds")
	return option.Credentials[0].Issuer.TrustLevel
}

// Asserts the rung a pre-authorized issuance's permission screen showed, on the
// session header and on the offered credential — ranked separately — then lets it
// complete.
func requireIssuedAtLevel(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	expected clientmodels.TrustLevel,
) {
	t.Helper()

	offer := createPreAuthOffer(t)
	startOpenID4VCISession(t, c, 1, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	require.Equal(t, expected, session.Requestor.TrustLevel, "the session's issuer rung")
	require.NotEmpty(t, session.OfferedCredentials)
	for _, offered := range session.OfferedCredentials {
		require.Equal(t, expected, offered.Issuer.TrustLevel,
			"credential %q carries its own issuer rung", offered.CredentialId)
	}

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}
