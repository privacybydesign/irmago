package sessiontest

import (
	"context"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/stretchr/testify/require"
)

// The trust ladder as real protocol sessions: both roles at their rungs, the
// rules that keep a rung honest, and the one rule that still blocks a session.
//
// Each test publishes its own LoTE from an in-process server and points the
// wallet at it through the construction seam
// (client.NewWithRecognizedTrustLists, reached here through
// instantiateClientWithTrustLists), so nothing depends on a published list
// existing.
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
//     Requestor.Id rather than hardcoding one (see testListedVerifierRanksMedium).
//
// A new rung for a party is therefore a new entry on that test's list, not a new
// counterparty: NewTestDidService for the DID-identified ones,
// NewTestCertificateService or NewTestSkiService for a certificate, plus
// lote.MarkingOnboardedByYivi on a source published with operatedByYivi.
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
//  2. The marking is Yivi's word — drop the source.OperatedByYivi condition in
//     lote.listingOf ⇒ testForeignMarkingStaysMedium, plus eudi/trust/lote
//     TestChecker_MarkingOnlyCountsOnYivisOwnList and client
//     TestClient_RefreshTrustLists_MarkedOnYivisListRanksHigh.
//  3. Fire once, re-sign silently — have lote.entriesDiffer compare whole lists
//     instead of entities (so a new sequence number counts) ⇒ client
//     TestTrustListRefreshNotifiesOnContentChange.
//  4. A rejected party is not a generic error — report the gate failure through
//     handleFailure in openid4vp ⇒ eudi/openid4vp
//     TestNewSession_RevokedVerifierCertificate_ReportsPartyValidationFailed.
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
	t.Run("listed issuer ranks medium", testListedIssuerRanksMedium)
	t.Run("issuer marked on yivi's list ranks high", testMarkedIssuerRanksHigh)
	t.Run("marking on another operator's list stays medium", testForeignMarkingStaysMedium)
	t.Run("issuer listed as verifier only stays low", testIssuerListedInTheWrongRoleStaysLow)
	t.Run("unreachable list leaves the issuer low and issuing", testUnreachableListLeavesIssuerLow)
	t.Run("over-ask fails at the top rung", testOverAskFailsAtTopRung)
	t.Run("stored credential follows the list, logs do not", testStoredCredentialFollowsTheList)
	t.Run("listed verifier ranks medium under its curated name", testListedVerifierRanksMedium)
}

// testListedVerifierRanksMedium runs the same verifier twice — once before its
// entry exists and once after — so the rung and the name the wallet reports are
// shown to follow the recognized list rather than the request. The first,
// unvouched-for run discloses successfully, which is the verifier side of
// fail-soft: a low rung is rendered, never enforced.
//
// The veramo verifier's did:jwk is generated at runtime, so the test learns the
// identifier from the first session instead of hardcoding it.
func testListedVerifierRanksMedium(t *testing.T) {
	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, false)})
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, testCredentialSdJwt, testCredentialClaims)

	unlisted := discloseToVeramoVerifier(t, c, 2, sessionHandler)
	require.Equal(t, clientmodels.TrustLevel_Low, unlisted.Requestor.TrustLevel,
		"a verifier no list vouches for ranks low, and still gets its disclosure")
	require.Equal(t, "test-verifier", unlisted.Requestor.Name,
		"with nothing curated to go on, the verifier is shown under the name it gives itself")

	verifierDid := unlisted.Requestor.Id
	require.NotEmpty(t, verifierDid, "a verifier without a certificate is identified by its DID")

	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Curated Verifier BV", "",
			lote.NewTestDidService(lote.ServiceTypeVerifier, verifierDid))))
	require.NoError(t, c.RefreshTrustLists(context.Background()))

	listed := discloseToVeramoVerifier(t, c, 3, sessionHandler)
	require.Equal(t, clientmodels.TrustLevel_Medium, listed.Requestor.TrustLevel,
		"the same verifier, now granted on a recognized list, ranks medium")
	require.Equal(t, "Curated Verifier BV", listed.Requestor.Name,
		"the curated name on the entry outranks the name the verifier gives itself")
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
		[]lote.Source{server.Source(testTrustListId, false)})
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, testCredentialSdJwt, testCredentialClaims)
	require.Equal(t, clientmodels.TrustLevel_Low, storedIssuerLevel(t, c),
		"nobody vouched for the issuer at issuance time")
	loggedLevel := issuanceLogIssuerLevel(t, c)
	require.Equal(t, clientmodels.TrustLevel_Low, loggedLevel)

	// The issuer is granted on a recognized list, and the wallet fetches it.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed Issuer BV", "", lote.NewTestDidService(lote.ServiceTypeIssuer, testIssuerDid))))
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
// side: an entry granting the issuer, carrying no marking, is somebody
// vouching for the party.
func testListedIssuerRanksMedium(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, false, lote.NewTestDidService(lote.ServiceTypeIssuer, testIssuerDid))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Medium)
}

// testMarkedIssuerRanksHigh is the top rung through the list: Yivi's own list
// marking an entry as onboarded is Yivi vouching for the party, the same word
// its scheme certificate would give.
func testMarkedIssuerRanksHigh(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, true,
		lote.NewTestDidService(lote.ServiceTypeIssuer, testIssuerDid, lote.MarkingOnboardedByYivi))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_High)
}

// testForeignMarkingStaysMedium guards the rule that the marking is Yivi's word
// to give: the same bytes on a list Yivi does not operate is that operator
// claiming Yivi onboarded someone, and it must not lift the party.
//
// Mutation check for that rule — dropping the "only on Yivi's own list"
// condition makes this read high.
func testForeignMarkingStaysMedium(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, false,
		lote.NewTestDidService(lote.ServiceTypeIssuer, testIssuerDid, lote.MarkingOnboardedByYivi))
	defer c.Close()

	requireIssuedAtLevel(t, c, sessionHandler, clientmodels.TrustLevel_Medium)
}

// testIssuerListedInTheWrongRoleStaysLow pins that trust as a verifier is not
// trust as an issuer: the same party, the same list, the wrong grant.
func testIssuerListedInTheWrongRoleStaysLow(t *testing.T) {
	c, sessionHandler := clientWithIssuerList(t, true,
		lote.NewTestDidService(lote.ServiceTypeVerifier, testIssuerDid, lote.MarkingOnboardedByYivi))
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
	source := server.Source(testTrustListId, true)
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
	// The verifier the EUDI test verifier authenticates as, marked on Yivi's
	// own list: the highest rung there is. Its certificate still says which
	// attributes it may ask for.
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Yivi B.V.", "",
			lote.NewTestCertificateService(lote.ServiceTypeVerifier,
				signer.NewTestPartyCertificate(t, "unused-party", ""),
				lote.MarkingOnboardedByYivi))))

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, true)})
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

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// clientWithIssuerList builds a wallet whose one recognized list carries the
// veramo test issuer under the given service, published by an in-process server
// and already fetched.
func clientWithIssuerList(t *testing.T, yivisOwnList bool, service lote.Service) (*client.Client, *MockSessionHandler) {
	t.Helper()

	signer := lote.NewTestLoteSigner(t)
	server := lote.NewTestLoteServer(t)
	server.Serve(t, signer, lote.NewTestList(testTrustListId, 1,
		lote.NewTestEntity("Listed Issuer BV", "", service)))

	c, _, sessionHandler := instantiateClientWithTrustLists(t, nil, "en", signer.RootCert,
		[]lote.Source{server.Source(testTrustListId, yivisOwnList)})
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
