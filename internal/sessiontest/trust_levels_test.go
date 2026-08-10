package sessiontest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
// wallet at it through the construction seam
// (client.Config.RecognizedTrustLists, passed by instantiateClientWithTrustLists),
// so nothing depends on a published list existing.
//
// # The parties, and how to give one a rung
//
// The compose counterparties each authenticate differently, which is what
// decides the channel a test can reach a rung through:
//
//   - The veramo OpenID4VCI issuer (preAuthIssuerURL) signs with did:web, so it
//     has no certificate and climbs through the list channel only. List it under
//     [testIssuerDid], which is the `iss` of every credential it issues.
//   - The EUDI Python PID issuer signs with `x5c` under a CA the wallet is given
//     as an anchor, so it reaches high through the certificate channel with no
//     list at all (eudi_pid_python_issuer_test.go).
//   - The EUDI Kotlin verifier authenticates with a Yivi-issued certificate, so
//     it is high by certificate — and its certificate carries the attribute
//     authorization the over-ask test exceeds
//     (testdata/eudi/verifier/verifier_scheme_data.json).
//   - The veramo verifier authenticates with a did:jwk generated at runtime, so
//     a test that wants to list it reads the DID off a first session's
//     Requestor.Id rather than hardcoding one (see testVerifierRungsFollowTheLists).
//
// A new rung for a party is therefore a new entry on that test's list, not a new
// counterparty: NewTestDidService for the DID-identified ones,
// NewTestCertificateService or NewTestSkiService for a certificate. The rung an
// entry confers is its source's: a source conferring TrustLevel_High stands in
// for Yivi's own list, one conferring TrustLevel_Medium for any other
// recognized list.
//
// # Where the rest of the matrix lives
//
// The four ways a list stops being evidence (unreachable, tampered, expired,
// replayed) and the typed gate error are covered against the OpenID4VP client in
// eudi/openid4vp/client_lote_test.go and client_trust_test.go, and against the
// OpenID4VCI session in eudi/openid4vci/session_trust_test.go; the list's own
// wiring, persistence and transitions in client/trust_list_test.go; the log
// snapshot columns in eudi/services/log_service_test.go and
// eudi_logs_test.go; the IRMA display mapping in irma/display_test.go and
// client/session_handler_test.go.
//
// # Mutation checks
//
// Five decisions are guarded by tests that go red when the guard is removed.
// Each row was verified by making the change and watching the named test fail:
//
//  1. Fail-soft floor — an unusable list is absent evidence, so parties cap at
//     low. Skip verifyChain in lote.verify ⇒ eudi/openid4vp
//     TestNewSession_ListDegradations_CapTheVerifierAtLow/tampered_signature.
//     Drop lote.Checker.Snapshot's next_update check ⇒ eudi/trust/lote
//     TestChecker_AListPastItsNextUpdateStopsGranting. Expiry is guarded twice —
//     once when a list is fetched, once when a held one is read — so the expired
//     degradation case only goes red when both are removed; the held-list check
//     is the one a wallet that cannot refresh depends on, and it has its own test.
//  2. The rung is the source's word — have lote.listingOf lift entries that
//     carry a marking (resurrecting entry-level tiers) ⇒
//     testMarkedEntryOnMediumListStaysMedium, plus eudi/trust/lote
//     TestChecker_ListingConfersTheSourcesLevel and client
//     TestClient_RefreshTrustLists_ListingConfersTheSourcesLevel.
//  3. Fire once, re-sign silently — have lote.entriesDiffer compare whole lists
//     instead of entities (so a new sequence number counts) ⇒ client
//     TestTrustListRefreshNotifiesOnContentChange.
//  4. A rejected party is not a generic error — report the gate failure through
//     handleFailure in openid4vp ⇒ testBrokenRequestReportsTypedError, plus
//     eudi/openid4vp
//     TestNewSession_ExpiredVerifierCertificate_ReportsPartyValidationFailed.
//  5. Rank at read, not at issuance — freeze the rung in
//     credentialService.GetCredentialMetadataList ⇒
//     testStoredCredentialFollowsTheList, plus client
//     TestStoredCredentialIssuerRanksAtRead.

const testTrustListId = "urn:yivi:trustlist:sessiontest"

// testIssuerDid is the DID the veramo OpenID4VCI test issuer signs with. It is
// the `iss` of every SD-JWT VC it issues, and therefore the identifier a
// recognized list has to name to vouch for it as an issuer.
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

// testVerifierRungsFollowTheLists walks one verifier up all three rungs, so the
// rung and the name the wallet reports are shown to follow the recognized lists
// rather than the request. The first, unvouched-for run discloses successfully,
// which is the verifier side of fail-soft: a low rung is rendered, never enforced.
//
// The wallet consults two lists — one that is not Yivi's own (conferring
// medium) and Yivi's own (conferring high) — because the rung is the source's
// word: the same verifier climbs from medium to high not by its entry changing
// but by which list carries it.
//
// The veramo verifier's did:jwk is generated at runtime, so the test learns the
// identifier from the first session instead of hardcoding it.
func testVerifierRungsFollowTheLists(t *testing.T) {
	const mediumListId = testTrustListId + ":medium"
	const yiviListId = testTrustListId + ":yivi"

	signer := lote.NewTestLoteSigner(t)
	mediumServer := lote.NewTestLoteServer(t)
	yiviServer := lote.NewTestLoteServer(t)

	// Both lists start current and empty: a wallet that consults a list on
	// which nobody is granted vouches for nobody.
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

	// Listed on Yivi's own list: Yivi vouching for the party, the top rung.
	yiviServer.Serve(t, signer, lote.NewTestList(yiviListId, 2,
		lote.NewTestEntity("Curated Verifier BV", "",
			lote.NewTestDidService(trust.RoleVerifier, verifierDid))))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	onYivisList := discloseToVeramoVerifier(t, c, 4, sessionHandler)
	require.Equal(t, clientmodels.TrustLevel_High, onYivisList.Requestor.TrustLevel,
		"an entry on Yivi's own list reaches the top rung: being listed is being onboarded")
	require.True(t, onYivisList.Requestor.TrustLevel.IsTrusted())
}

// testDisclosureCandidatesRankTheIssuer covers the second place a stored
// credential's issuer is ranked at read: the disclosure planner, next to the
// credential list. Both read the same persisted evidence through the same
// evaluator, and a credential that showed one rung in the wallet and another in a
// session would be the visible bug.
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

// testUnknownCaVerifierRanksLowAndProceeds is the "X.509 → unknown CA" row of
// the matrix: a chain the wallet cannot trace to any anchor proves nothing, so
// its holder is a legitimate-looking stranger — low, with the certificate's
// contents counted as self-asserted — and the session reaches the permission
// screen behind the warning rather than failing.
//
// The verifier here is the same EUDI service every other test talks to, signing
// its request exactly as always; only this wallet anchors no verifier CA, so
// nobody vouches for it.
func testUnknownCaVerifierRanksLowAndProceeds(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, clientHandler, sessionHandler := instantiateClientWithoutVerifierTrust(t)
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

// testUnknownCaVerifierListedOnYivisListRanksHigh is the escape hatch the list
// channel is built to carry: a party whose certificate the wallet cannot trace
// to any anchor still reaches the top rung through an entry on Yivi's own list
// keyed on that very certificate — max(certificate, list) with the certificate
// channel silent.
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

	// The full form with verifierCA nil: the wallet anchors no verifier CA at
	// all, so the list entry is the only thing that can speak for the verifier.
	c, clientHandler, sessionHandler := instantiateClientWithVerifierTrust(t, "", nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_High)}, nil)
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

// testThirdPartyCaVerifierRanksMedium is the blog's medium: somebody vouches,
// but not Yivi. The same verifier CA every other test installs as a stand-in
// for the Yivi CA is pinned here as a third-party anchor conferring medium, so
// the same verifier, the same request and the same certificate land one rung
// lower — with the name its CA attested, not a warning-screen name.
func testThirdPartyCaVerifierRanksMedium(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, clientHandler, sessionHandler := instantiateClientWithExtraAnchors(t, "", nil, "en", nil, nil,
		nil, // no verifier CA installed at high...
		[]eudi.ExtraTrustAnchor{{PEM: testdata.VerifierCACertBytes, Confers: clientmodels.TrustLevel_Medium}})
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

// testBrokenRequestReportsTypedError is the state that is not a rung: a
// verifier the wallet cannot authenticate at all — here an unresolvable DID —
// is a session failure the app must be able to name, so it can say the request
// was not trustworthy rather than showing a generic error.
func testBrokenRequestReportsTypedError(t *testing.T) {
	c, _, sessionHandler := instantiateClient(t, nil, "en")
	defer c.Close()

	// An authorization request whose client_id names a did:web nothing serves:
	// the wallet cannot resolve who it is talking to, and nothing else about
	// the request can make up for that.
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

// unresolvableDidAuthRequest signs an authorization request as a did:web
// verifier whose document nobody serves.
func unresolvableDidAuthRequest(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return testdata.CreateTestAuthorizationRequestJWTWithClientId(
		"decentralized_identifier:did:web:localhost%3A1", key, &x509.Certificate{},
		func(token *jwt.Token) { delete(token.Header, "x5c") },
	)
}

// testStoredCredentialFollowsTheList is the transition behaviour end to end: a
// credential is issued while nobody vouches for its issuer, the issuer is then
// listed, and reading the credential again gives the rung the list says now —
// no level column, no migration. Delisting demotes it back.
//
// The activity log is the counterpart: it recorded the rung the session showed
// and keeps it through both moves, because a log is what happened, not what is
// true now.
//
// Mutation check for demote-on-read: freezing the rung at issuance makes the
// promotion and the demotion both read low.
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

	// The issuer is granted on a recognized list, and the wallet fetches it.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed Issuer BV", "", lote.NewTestDidService(trust.RoleIssuer, testIssuerDid))))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	require.Equal(t, clientmodels.TrustLevel_Medium, storedIssuerLevel(t, c),
		"the stored credential promotes on the next read")
	require.Equal(t, loggedLevel, issuanceLogIssuerLevel(t, c),
		"the activity log keeps the rung the session showed")

	// Delisted again: the entry is gone from a newer issue of the same list.
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

// testListedIssuerRanksMedium is the recognized-list channel on the issuer
// side: an entry on a recognized list that is not Yivi's own is somebody
// vouching for the party, but not Yivi.
func testListedIssuerRanksMedium(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_Medium,
		lote.NewTestDidService(trust.RoleIssuer, testIssuerDid))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Medium)
}

// testIssuerOnYivisListRanksHigh is the top rung through the list: every entry
// on Yivi's own list is Yivi vouching for the party — being listed is being
// onboarded — the same word its scheme certificate would give.
func testIssuerOnYivisListRanksHigh(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_High,
		lote.NewTestDidService(trust.RoleIssuer, testIssuerDid))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_High)
}

// testMarkedEntryOnMediumListStaysMedium guards the rule that the rung is the
// source's word, never the entry's: an entry decorating itself with a marking
// (here the retired onboarded-by-yivi bytes) on a list that confers medium
// stays medium.
//
// Mutation check for that rule — resurrecting entry-level lifting in
// lote.listingOf makes this read high.
func testMarkedEntryOnMediumListStaysMedium(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_Medium,
		lote.NewTestDidService(trust.RoleIssuer, testIssuerDid, "onboarded-by-yivi"))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Medium)
}

// testIssuerListedInTheWrongRoleStaysLow pins that trust as a verifier is not
// trust as an issuer: the same party, the same list, the wrong grant.
func testIssuerListedInTheWrongRoleStaysLow(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, clientmodels.TrustLevel_High,
		lote.NewTestDidService(trust.RoleVerifier, testIssuerDid))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Low)
}

// testUnreachableListLeavesIssuerLow is the fail-soft floor, from both sides at
// once: a list the wallet cannot reach is absent evidence rather than a failure,
// and an issuer nobody vouches for still issues its credential.
//
// Mutation check for fail-soft — refusing a low-ranking issuer, or surfacing the
// list failure into the session, fails here.
func testUnreachableListLeavesIssuerLow(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	source := server.Source(testTrustListId, clientmodels.TrustLevel_High)
	server.Close()

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert, []lote.Source{source})
	defer c.Close()

	// The refresh reports the problem to whoever asked for it, and that is as
	// far as it travels.
	require.Error(t, c.RefreshTrustLists(context.Background()))

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Low)
}

// ----------------------------------------------------------------------------
// Grant violations still block
// ----------------------------------------------------------------------------

// testOverAskFailsAtTopRung is the one hard rule: a trust level never blocks a
// session, but a request exceeding what the party's vouching artifact allows
// always does — at every rung, so it is asserted at the highest one.
func testOverAskFailsAtTopRung(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	// The verifier the EUDI test verifier authenticates as, listed on Yivi's
	// own list: the highest rung there is. Its certificate still says which
	// attributes it may ask for.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Yivi B.V.", "",
			lote.NewTestCertificateService(trust.RoleVerifier,
				signer.NewTestPartyCertificate(t, "unused-party", "")))))

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, clientmodels.TrustLevel_High)})
	defer c.Close()
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	// irma-demo.MijnOverheid.address is not among the attribute sets the
	// verifier's certificate authorizes (testdata/eudi/verifier/verifier_scheme_data.json).
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

// testCertificateKeyingNeedsBothHalves is the negative half of certificate
// keying: an entry that names the right key but the wrong legal entity, or the
// wrong key entirely, grants nobody. The certificate says which key signed, the
// organizationIdentifier says whose key it is, and a match needs both — otherwise
// an entry would keep granting the entity a key was reassigned to.
//
// The rung cannot show any of this: a validated certificate is high whatever the
// list says. So the assertion is the *absence* of the curated name, which is the
// only signal that a match was a match rather than a coincidence. The positive
// case lives in the published group, where a real download can also prove the
// curated logo wins (see published_trust_list_test.go).
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

// testIssuerKeyedOnItsCertificate covers the issuer role's keying path, which
// shares matchesIdentity with the verifier's but assembles its evidence through a
// different protocol: the certificate comes off the SD-JWT VC the issuer signed,
// not off a request. The EUDI Python PID issuer signs with `x5c`, so it is the
// party for it — keyed on the SKI of its committed leaf, with no organization
// identifier, which is the documented "keyed on the certificate alone" form.
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

// eudiPidIssuerLeaf parses the committed certificate the EUDI Python PID issuer
// signs its credentials with (mounted into the container as issuer.der).
func eudiPidIssuerLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	leafPem, err := os.ReadFile(filepath.Join(testdataFolder, "eudi-pid-issuer-py", "certs", "issuer.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(leafPem)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return leaf
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// clientWithIssuerList builds a wallet whose one recognized list carries the
// veramo test issuer under the given service, published by an in-process server
// and already fetched.
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

// storedIssuerLevel is the rung the credential list puts the wallet's one stored
// credential's issuer on right now.
func storedIssuerLevel(t *testing.T, c *client.Client) clientmodels.TrustLevel {
	t.Helper()
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	return creds[0].Issuer.TrustLevel
}

// issuanceLogIssuerLevel is the rung the newest issuance log entry recorded,
// which is the rung its session showed and must stay that way.
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

// discloseToVeramoVerifier runs one full disclosure against the veramo verifier
// and returns the session state the permission screen was built from — the party
// the user was shown. The disclosure is completed, so every rung this is called
// at is also asserted not to block.
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

// candidateIssuerLevel starts a disclosure, reads the issuer rung off the owned
// credential the plan offers, and completes the session so the next one can run.
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

// requireIssuedAtLevel runs a full pre-authorized issuance and asserts the rung
// the permission screen showed — on the session header and on the offered
// credential, which are ranked separately — then lets the issuance complete, so
// every rung is also asserted not to block.
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
