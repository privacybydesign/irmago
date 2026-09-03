package sessiontest

import (
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/testdata"
)

// ============================================================================
// DCQL shapes against a real mdoc
//
// The AV disclosure suite in openid4vp_mdoc_av_disclosure_test.go presents one
// element of one credential and then mutates the request some fifty ways. What it
// never does is ask for more than that: two queries at once, a choice, an optional
// set, claim sets, two matching candidates, or several presentations for one
// query. Those shapes exist for mdoc only as handler unit tests, and the SD-JWT
// end-to-end suite covers each of them about sixty times over.
//
// Every subtest here issues a real age credential from the reference issuer,
// presents to the reference verifier over direct_post.jwt, verifies the
// DeviceResponse the verifier received against a transcript rebuilt from the
// captured request, and reads the activity log. The credential is shaped per
// subtest: the container mints any age_over_NN named in the offer, so a subtest
// that needs two elements, or two distinct credentials, asks for them.
//
// age_over_21 is the second element throughout. It is one the issuer advertises,
// so its label is published and can be pinned; a threshold the issuer does not
// advertise would be minted just the same but shown under its identifier.
// ============================================================================

const (
	avSecondElement        = "age_over_21"
	avAgeOver21DisplayName = "Age Over 21"

	avQueryIdDefault   = "age"
	avQueryIdAgeOver18 = "age18"
	avQueryIdAgeOver21 = "age21"
)

func testSessionHandlerForOpenID4VPWithMdocAvDcqlShapes(t *testing.T) {
	t.Run(
		"two mdoc queries in one request are answered with two presentations",
		testOpenID4VP_MdocAv_TwoQueriesInOneRequest,
	)
	t.Run(
		"a credential_sets choice between two queries presents only the chosen one",
		testOpenID4VP_MdocAv_CredentialSetChoice,
	)
	t.Run(
		"an optional credential set is marked optional and can be granted",
		testOpenID4VP_MdocAv_OptionalCredentialSet,
	)
	t.Run(
		"claim_sets discloses the first satisfiable set only",
		testOpenID4VP_MdocAv_ClaimSets,
	)
	t.Run(
		"two matching credentials are offered as two candidates",
		testOpenID4VP_MdocAv_TwoCandidates,
	)
	t.Run(
		"multiple lets the user present both candidates for one query",
		testOpenID4VP_MdocAv_MultiplePresentations,
	)
	t.Run(
		"intent_to_retain reaches the permission screen and the log",
		testOpenID4VP_MdocAv_IntentToRetain,
	)
}

// testOpenID4VP_MdocAv_TwoQueriesInOneRequest asks for two elements of the age
// credential as two separate credential queries.
//
// Two queries are two presentations, even when one credential answers both: each
// gets its own DeviceResponse with only its element, keyed under its own query id,
// signed over the same transcript, and each spends a batch instance. The log lists
// the credential twice, once per presentation, because that is what left the
// wallet.
//
// The reference verifier refuses this session with RequiredCredentialSetNotSatisfied
// after validating both documents. The DC API twin of this test in
// openid4vp_dc_api_mdoc_test.go shows why: the wallet keys both presentations
// under the second query id, because the plan maps a credential hash to one query
// id (dcql.DcqlResult.HashToQueryId), so a credential that answers two queries can
// only ever be attributed to the last one.
func testOpenID4VP_MdocAv_TwoQueriesInOneRequest(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocWithElementsViaPythonIssuer(t, c, 1, sessionHandler, avElementsBoth())
	remainingBefore := avMdocInstancesRemaining(t, c)

	dcql := newDcql(
		avQuery(avQueryIdAgeOver18, avClaim(avMandatoryElement)),
		avQuery(avQueryIdAgeOver21, avClaim(avSecondElement)),
	)
	testSession, requestJwt := startMdocDcqlSession(t, c, 2, sessionHandler, dcql)

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver18())}},
				{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver21())}},
			},
		},
	)

	approvedRequestor := session.Requestor
	grantFirstOwnedOptions(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	transcript := avSessionTranscript(t, requestJwt)
	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)

	presented18 := requireSingleDeviceResponse(t, walletResponse, avQueryIdAgeOver18)
	requireDeviceAuthVerifiesElements(t, presented18, transcript, map[string]any{avMandatoryElement: true})

	presented21 := requireSingleDeviceResponse(t, walletResponse, avQueryIdAgeOver21)
	requireDeviceAuthVerifiesElements(t, presented21, transcript, map[string]any{avSecondElement: true})

	require.Equal(
		t,
		remainingBefore-2,
		avMdocInstancesRemaining(t, c),
		"two presentations must spend two instances",
	)

	disclosureLog := requireSingleDisclosureLog(t, c)
	requireLogVerifier(t, disclosureLog, approvedRequestor)
	require.Len(t, disclosureLog.Credentials, 2, "one log credential per presentation")

	logged18 := findLogCredentialWithAttr(t, disclosureLog.Credentials, avMandatoryElement)
	requireLogCredential(t, logged18, avLogCredential(avAttrAgeOver18()), "age_over_18 entry")

	logged21 := findLogCredentialWithAttr(t, disclosureLog.Credentials, avSecondElement)
	requireLogCredential(t, logged21, avLogCredential(avAttrAgeOver21()), "age_over_21 entry")
}

// testOpenID4VP_MdocAv_CredentialSetChoice puts the same two queries behind a
// credential_sets entry with two options, so the user has to pick one.
//
// Both options are satisfiable by the one credential the wallet holds, so the
// permission screen shows one choice with two owned options that differ only in
// the element they would disclose. Only the picked one is presented; the other
// query id must be absent from the vp_token rather than present and empty.
func testOpenID4VP_MdocAv_CredentialSetChoice(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocWithElementsViaPythonIssuer(t, c, 1, sessionHandler, avElementsBoth())

	dcql := newDcqlWithCredentialSets(
		credentialSetChoice(avQueryIdAgeOver18, avQueryIdAgeOver21),
		avQuery(avQueryIdAgeOver18, avClaim(avMandatoryElement)),
		avQuery(avQueryIdAgeOver21, avClaim(avSecondElement)),
	)
	testSession, requestJwt := startMdocDcqlSession(t, c, 2, sessionHandler, dcql)

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{
					avPlanCredential(avAttrAgeOver18()),
					avPlanCredential(avAttrAgeOver21()),
				}},
			},
		},
	)

	approvedRequestor := session.Requestor
	chosen := ownedOptionWithAttr(t, session.DisclosurePlan.DisclosureChoicesOverview[0], avSecondElement)
	grantPermission(t, c, 2, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	requireQueryAbsent(t, walletResponse, avQueryIdAgeOver18)

	presented := requireSingleDeviceResponse(t, walletResponse, avQueryIdAgeOver21)
	requireDeviceAuthVerifiesElements(
		t,
		presented,
		avSessionTranscript(t, requestJwt),
		map[string]any{avSecondElement: true},
	)

	disclosureLog := requireSingleDisclosureLog(t, c)
	requireLogVerifier(t, disclosureLog, approvedRequestor)
	require.Len(t, disclosureLog.Credentials, 1)
	requireLogCredential(t, disclosureLog.Credentials[0], avLogCredential(avAttrAgeOver21()), "chosen entry")
}

// testOpenID4VP_MdocAv_OptionalCredentialSet marks the only query optional.
//
// The permission screen has to say so, and granting it is an ordinary disclosure.
// The other answer, sharing nothing, is pinned over the DC API in
// openid4vp_dc_api_mdoc_test.go: the reference verifier answers an empty vp_token
// on the redirect flow with a 500 (a failed requirement in its response handling),
// so the wallet's side of that case can only be read where nothing sits between
// the wallet and the test.
func testOpenID4VP_MdocAv_OptionalCredentialSet(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	dcql := newDcqlWithCredentialSets(
		optionalCredentialSet(avQueryIdDefault),
		avQuery(avQueryIdDefault, avClaim(avMandatoryElement)),
	)
	testSession, requestJwt := startMdocDcqlSession(t, c, 2, sessionHandler, dcql)

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Optional: true, Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver18())}},
			},
		},
	)

	grantFirstOwnedOptions(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	presented := requireSingleDeviceResponse(t, walletResponse, avQueryIdDefault)
	requireDeviceAuthVerifies(t, presented, avSessionTranscript(t, requestJwt))

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 1)
}

// testOpenID4VP_MdocAv_ClaimSets names both elements in one query and prefers the
// second through claim_sets.
//
// The handler picks the first satisfiable set, so age_over_21 alone is what the
// user is asked about and what the verifier receives. The other element is on the
// credential and in the query; it must reach neither the screen nor the wire.
func testOpenID4VP_MdocAv_ClaimSets(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocWithElementsViaPythonIssuer(t, c, 1, sessionHandler, avElementsBoth())

	query := avQuery(
		avQueryIdDefault,
		withClaimId(avClaim(avMandatoryElement), "a"),
		withClaimId(avClaim(avSecondElement), "b"),
	)
	query["claim_sets"] = [][]string{{"b"}, {"a"}}

	testSession, requestJwt := startMdocDcqlSession(t, c, 2, sessionHandler, newDcql(query))

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver21())}},
			},
		},
	)

	grantFirstOwnedOptions(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	presented := requireSingleDeviceResponse(t, walletResponse, avQueryIdDefault)
	requireDeviceAuthVerifiesElements(
		t,
		presented,
		avSessionTranscript(t, requestJwt),
		map[string]any{avSecondElement: true},
	)

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 1)
	requireLogCredential(t, disclosureLog.Credentials[0], avLogCredential(avAttrAgeOver21()), "claim set entry")
}

// testOpenID4VP_MdocAv_TwoCandidates holds two distinct age credentials and asks
// for the element both carry.
//
// The two are distinct to the wallet because their element sets differ, which is
// what keeps them from collapsing into one by hash. The permission screen offers
// both; the one the user picks is the one whose batch is spent, and the other is
// left whole. That is checked by asking again afterwards and comparing the
// remaining counts per option, since a presentation of age_over_18 alone does not
// say which batch it came from.
func testOpenID4VP_MdocAv_TwoCandidates(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)
	issueAvMdocWithElementsViaPythonIssuer(t, c, 2, sessionHandler, avElementsBoth())

	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, avSingleElementDcql())

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{
					avPlanCredential(avAttrAgeOver18()),
					avPlanCredential(avAttrAgeOver18()),
				}},
			},
		},
	)

	options := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	first, second := options[0].Credentials[0], options[1].Credentials[0]
	require.NotEqual(t, first.Hash, second.Hash, "two credentials must be two options, not one shown twice")

	remainingBefore := map[string]uint{
		first.Hash:  *first.BatchInstanceCountRemaining,
		second.Hash: *second.BatchInstanceCountRemaining,
	}

	grantPermission(t, c, 3, makeDisclosureChoice(options[1]))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	presented := requireSingleDeviceResponse(t, walletResponse, avQueryIdDefault)
	requireDeviceAuthVerifies(t, presented, avSessionTranscript(t, requestJwt))

	// Ask again: the picked option is one instance shorter, the other untouched.
	again, _ := startMdocDcqlSession(t, c, 4, sessionHandler, avSingleElementDcql())
	requireSessionState(
		t,
		again.ClientSession,
		4,
		clientmodels.Type_Disclosure,
		clientmodels.Status_RequestPermission,
	)

	remainingAfter := map[string]uint{}
	for _, bundle := range again.ClientSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions {
		cred := bundle.Credentials[0]
		remainingAfter[cred.Hash] = *cred.BatchInstanceCountRemaining
	}

	require.Equal(
		t,
		remainingBefore[first.Hash],
		remainingAfter[first.Hash],
		"the option the user did not pick must not be spent",
	)
	require.Equal(
		t,
		remainingBefore[second.Hash]-1,
		remainingAfter[second.Hash],
		"the picked option must be one instance shorter",
	)

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 1)
}

// testOpenID4VP_MdocAv_MultiplePresentations sets the DCQL multiple flag on a
// query two credentials can answer, and the user hands over both.
//
// The vp_token entry for the query becomes two DeviceResponses. Each is verified
// on its own against the one transcript, and the two must carry different
// issuerAuths, since two presentations of one instance would be the linkability
// the batch exists to prevent.
func testOpenID4VP_MdocAv_MultiplePresentations(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)
	issueAvMdocWithElementsViaPythonIssuer(t, c, 2, sessionHandler, avElementsBoth())

	query := avQuery(avQueryIdDefault, avClaim(avMandatoryElement))
	query["multiple"] = true

	testSession, requestJwt := startMdocDcqlSession(t, c, 3, sessionHandler, newDcql(query))

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Multiple: true, Owned: []expectedPlanCredential{
					avPlanCredential(avAttrAgeOver18()),
					avPlanCredential(avAttrAgeOver18()),
				}},
			},
		},
	)

	// Both bundles in one selection: that is what the multiple flag permits.
	grantAllOwnedOptions(t, c, 3, session.DisclosurePlan.DisclosureChoicesOverview[0])

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	presentations := deviceResponsesForQuery(t, walletResponse, avQueryIdDefault)
	require.Len(t, presentations, 2, "the verifier must receive one presentation per selected credential")

	transcript := avSessionTranscript(t, requestJwt)
	for _, presentation := range presentations {
		requireDeviceAuthVerifies(t, presentation, transcript)
	}

	require.NotEqual(
		t,
		issuerAuthOf(t, presentations[0].Documents[0]),
		issuerAuthOf(t, presentations[1].Documents[0]),
		"two presentations must come from two attestations",
	)

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 2, "both presented credentials are logged")
}

// testOpenID4VP_MdocAv_IntentToRetain declares retention for one of two requested
// elements.
//
// intent_to_retain is the one thing a verifier tells the user about what happens
// to a value afterwards, and it is only defined for mso_mdoc. The flag has to be
// set on every mdoc attribute, true where declared and false where not, on the
// permission screen and in the log alike. A screen that shows the flag and a log
// that forgets it leaves the user unable to see later what they agreed to.
func testOpenID4VP_MdocAv_IntentToRetain(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocWithElementsViaPythonIssuer(t, c, 1, sessionHandler, avElementsBoth())

	retainedClaim := avClaim(avMandatoryElement)
	retainedClaim["intent_to_retain"] = true

	query := avQuery(avQueryIdDefault, retainedClaim, avClaim(avSecondElement))
	testSession, _ := startMdocDcqlSession(t, c, 2, sessionHandler, newDcql(query))

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	retainedAttr := avAttrAgeOver18()
	retainedAttr.IntentToRetain = new(true)
	notRetainedAttr := avAttrAgeOver21()
	notRetainedAttr.IntentToRetain = new(false)

	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{avPlanCredential(retainedAttr, notRetainedAttr)}},
			},
		},
	)

	grantFirstOwnedOptions(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	requireVerifierAccepted(t, testSession.VerifierSession)

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 1)
	requireLogCredential(
		t,
		disclosureLog.Credentials[0],
		avLogCredential(retainedAttr, notRetainedAttr),
		"log entry",
	)
}

// ----------------------------------------------------------------------------
// Query builders
// ----------------------------------------------------------------------------

func avElementsBoth() map[string]bool {
	return map[string]bool{
		avMandatoryElement: true,
		avSecondElement:    true,
	}
}

// avClaim is one DCQL claim for an element of the age credential.
func avClaim(element string) map[string]any {
	return map[string]any{
		"path": []string{avDocType, element},
	}
}

func withClaimId(claim map[string]any, id string) map[string]any {
	claim["id"] = id
	return claim
}

// avQuery is one mso_mdoc credential query for the age credential.
func avQuery(id string, claims ...map[string]any) map[string]any {
	return map[string]any{
		"id":     id,
		"format": string(clientmodels.Format_MsoMdoc),
		"meta":   map[string]any{"doctype_value": avDocType},
		"claims": claims,
	}
}

func newDcql(credentials ...map[string]any) map[string]any {
	return map[string]any{
		"credentials": credentials,
	}
}

func newDcqlWithCredentialSets(
	credentialSets []map[string]any,
	credentials ...map[string]any,
) map[string]any {
	dcql := newDcql(credentials...)
	dcql["credential_sets"] = credentialSets
	return dcql
}

func credentialSetChoice(queryIds ...string) []map[string]any {
	options := make([][]string, 0, len(queryIds))
	for _, queryId := range queryIds {
		options = append(options, []string{queryId})
	}
	return []map[string]any{
		{"options": options},
	}
}

func optionalCredentialSet(queryId string) []map[string]any {
	return []map[string]any{
		{"options": [][]string{{queryId}}, "required": false},
	}
}

// avSingleElementDcql is the request the AV suite's happy path uses, as a
// dcql_query: one query for age_over_18 under the default id.
func avSingleElementDcql() map[string]any {
	return newDcql(avQuery(avQueryIdDefault, avClaim(avMandatoryElement)))
}

// ----------------------------------------------------------------------------
// Expectations
// ----------------------------------------------------------------------------

func avAttrAgeOver18() expectedAttr {
	return expectedAttr{
		Path:        []any{avDocType, avMandatoryElement},
		DisplayName: new(avAgeOver18DisplayName),
		Value:       boolVal(true),
	}
}

func avAttrAgeOver21() expectedAttr {
	return expectedAttr{
		Path:        []any{avDocType, avSecondElement},
		DisplayName: new(avAgeOver21DisplayName),
		Value:       boolVal(true),
	}
}

// avPlanCredential is the age credential as the permission screen shows it,
// with the given attributes.
//
// Beyond name and attributes: the issuer is verified because the document signer
// chain checked out at issuance; the card image is the one the issuer publishes
// in its credential metadata; the validity dates come from the MSO. Revocation is
// neither supported nor flagged, since the mdoc path has no status mechanism.
// That last pair pins the honest current state, not a claim that it is right.
func avPlanCredential(attrs ...expectedAttr) expectedPlanCredential {
	return expectedPlanCredential{
		CredentialId:        avDocType,
		Name:                avCredentialDisplayName,
		IssuerName:          avIssuerDisplayName,
		Attributes:          attrs,
		IssuerVerified:      new(true),
		Format:              new(clientmodels.Format_MsoMdoc),
		HasImage:            new(true),
		HasIssuanceDate:     new(true),
		HasExpiryDate:       new(true),
		Revoked:             new(false),
		RevocationSupported: new(false),
	}
}

// avLogCredential is the age credential as the activity log records it: the same
// facts the permission screen showed, minus the dates, which a caller pins
// against the credential list where it has one.
func avLogCredential(attrs ...expectedAttr) expectedLogCredential {
	return expectedLogCredential{
		CredentialId:        avDocType,
		Formats:             []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc},
		Name:                new(avCredentialDisplayName),
		IssuerName:          new(avIssuerDisplayName),
		IssuerVerified:      new(true),
		HasImage:            new(true),
		Attributes:          attrs,
		Revoked:             new(false),
		RevocationSupported: new(false),
	}
}

// ----------------------------------------------------------------------------
// Session helpers
// ----------------------------------------------------------------------------

// startMdocDcqlSession starts the given dcql_query at the direct_post.jwt verifier
// and hands the request to the wallet, capturing the request object so the
// transcript can be rebuilt.
func startMdocDcqlSession(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
	dcql map[string]any,
) (openID4VPTestSession, string) {
	t.Helper()

	return startMdocAvSessionCapturingRequest(
		t,
		c,
		sessionId,
		sessionHandler,
		testdata.OpenID4VP_DirectPostJwt_Host,
		createAvMdocSessionRequestWithDcql(t, dcql, nil),
	)
}

// grantFirstOwnedOptions grants every choice in the plan with its first owned
// option, for the shapes where there is nothing to choose.
func grantFirstOwnedOptions(
	t *testing.T,
	c *client.Client,
	sessionId int,
	session clientmodels.SessionState,
) {
	t.Helper()

	var choices []clientmodels.DisclosureDisconSelection
	for _, pickOne := range session.DisclosurePlan.DisclosureChoicesOverview {
		require.NotEmpty(t, pickOne.OwnedOptions, "every choice should have an owned option")
		choices = append(choices, makeDisclosureChoice(pickOne.OwnedOptions[0]))
	}

	grantPermission(t, c, sessionId, choices...)
}

func grantAllOwnedOptions(
	t *testing.T,
	c *client.Client,
	sessionId int,
	pickOne clientmodels.DisclosurePickOne,
) {
	t.Helper()

	var selected []clientmodels.SelectedCredential
	for _, bundle := range pickOne.OwnedOptions {
		selected = append(selected, makeDisclosureChoice(bundle).Credentials...)
	}

	grantPermission(t, c, sessionId, clientmodels.DisclosureDisconSelection{Credentials: selected})
}

// ownedOptionWithAttr returns the owned option that would disclose the given
// element, for the shapes where the user picks by content.
func ownedOptionWithAttr(
	t *testing.T,
	pickOne clientmodels.DisclosurePickOne,
	element string,
) *clientmodels.DisclosureBundle {
	t.Helper()

	for _, bundle := range pickOne.OwnedOptions {
		for _, cred := range bundle.Credentials {
			if findAttr(cred.Attributes, avDocType, element) != nil {
				return bundle
			}
		}
	}

	t.Fatalf("no owned option discloses %q", element)
	return nil
}

// findLogCredentialWithAttr returns the log credential carrying the given element,
// for entries that list one credential several times.
func findLogCredentialWithAttr(
	t *testing.T,
	creds []clientmodels.LogCredential,
	element string,
) clientmodels.LogCredential {
	t.Helper()

	for _, cred := range creds {
		if findAttr(cred.Attributes, avDocType, element) != nil {
			return cred
		}
	}

	t.Fatalf("no log credential carries %q", element)
	return clientmodels.LogCredential{}
}

// requireLogVerifier checks the log names the verifier the permission screen
// showed, verified flag included.
func requireLogVerifier(
	t *testing.T,
	disclosureLog *clientmodels.DisclosureLog,
	approved clientmodels.TrustedParty,
) {
	t.Helper()

	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureLog.Protocol)
	require.NotNil(t, disclosureLog.Verifier)
	require.Equal(t, approved.Id, disclosureLog.Verifier.Id)
	require.Equal(t, approved.Name, disclosureLog.Verifier.Name)
	require.Equal(
		t,
		approved.Verified,
		disclosureLog.Verifier.Verified,
		"the log must record the verifier the way the permission screen showed it",
	)
}

// ----------------------------------------------------------------------------
// Reading what the verifier received
// ----------------------------------------------------------------------------

// requireVerifierAccepted fetches the verifier's record of the session and
// asserts it reported no error.
func requireVerifierAccepted(t *testing.T, verifierSession EudiVerifierSession) map[string]any {
	t.Helper()

	result, err := GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	require.Nil(t, result["error"], "verifier returned error: %v", result["error_description"])

	return result
}

func presentationsForQuery(t *testing.T, walletResponse map[string]any, queryId string) []string {
	t.Helper()

	vpToken, ok := walletResponse["vp_token"].(map[string]any)
	require.True(t, ok, "vp_token should be a JSON object, got %T", walletResponse["vp_token"])

	entry, ok := vpToken[queryId]
	require.True(t, ok, "vp_token should carry query id %q, got keys %v", queryId, vpTokenKeys(vpToken))

	switch value := entry.(type) {
	case string:
		return []string{value}
	case []any:
		presentations := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			require.True(t, ok, "vp_token[%q] items should be strings, got %T", queryId, item)
			presentations = append(presentations, text)
		}
		return presentations
	default:
		t.Fatalf("vp_token[%q] should be a string or array, got %T", queryId, entry)
		return nil
	}
}

// deviceResponsesForQuery decodes every presentation the verifier recorded for a
// query id.
func deviceResponsesForQuery(
	t *testing.T,
	walletResponse map[string]any,
	queryId string,
) []stdmdoc.DeviceResponse {
	t.Helper()

	encoded := presentationsForQuery(t, walletResponse, queryId)

	responses := make([]stdmdoc.DeviceResponse, 0, len(encoded))
	for _, text := range encoded {
		raw, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(text)
		}
		require.NoError(t, err, "vp_token entry should be base64-encoded CBOR")

		var response stdmdoc.DeviceResponse
		require.NoError(t, cbor.Unmarshal(raw, &response), "vp_token entry should decode as a DeviceResponse")
		require.Equal(t, uint64(0), response.Status, "DeviceResponse status should be OK")
		require.Len(t, response.Documents, 1)

		responses = append(responses, response)
	}

	return responses
}

func requireSingleDeviceResponse(
	t *testing.T,
	walletResponse map[string]any,
	queryId string,
) stdmdoc.DeviceResponse {
	t.Helper()

	responses := deviceResponsesForQuery(t, walletResponse, queryId)
	require.Len(t, responses, 1, "expected exactly one presentation for query %q", queryId)

	return responses[0]
}

// requireQueryAbsent asserts the verifier recorded nothing for a query id: not an
// empty entry, no entry at all.
func requireQueryAbsent(t *testing.T, walletResponse map[string]any, queryId string) {
	t.Helper()

	vpToken, _ := walletResponse["vp_token"].(map[string]any)
	_, present := vpToken[queryId]
	require.False(t, present, "query %q must not be answered, got keys %v", queryId, vpTokenKeys(vpToken))
}

func vpTokenKeys[V any](vpToken map[string]V) []string {
	keys := make([]string, 0, len(vpToken))
	for key := range vpToken {
		keys = append(keys, key)
	}
	return keys
}
