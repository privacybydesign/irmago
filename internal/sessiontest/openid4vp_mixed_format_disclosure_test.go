package sessiontest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/testdata"
)

// ============================================================================
// One request, two formats
//
// A relying party asking for an SD-JWT VC and an mdoc in the same DCQL query is
// the ARF's ordinary case: a PID as SD-JWT next to an attestation as mdoc. Until
// these subtests nothing in the repository carried such a query. The two format
// handlers were each exercised alone, and the only cross-format test asked for
// the age credential as SD-JWT and expected a refusal.
//
// The reference issuer issues both: its PID as dc+sd-jwt and its age credential
// as mso_mdoc, signed by the same CA, so one wallet trusting one anchor holds
// both. The reference verifier classifies both types, so one session at it can
// ask for both. The presentation the verifier records is then read back per
// format: the SD-JWT's disclosures decoded, the DeviceResponse's DeviceAuth
// re-verified against a transcript rebuilt from the captured request.
// ============================================================================

const (
	mixedPidQueryId = "pid"
	mixedAgeQueryId = "age"
)

func testSessionHandlerForOpenID4VPWithMixedFormats(t *testing.T) {
	t.Run(
		"a pid sd-jwt and an age mdoc are disclosed in one session over direct_post.jwt",
		func(t *testing.T) { runMixedFormatDisclosure(t, testdata.OpenID4VP_DirectPostJwt_Host) },
	)
	t.Run(
		"a pid sd-jwt and an age mdoc are disclosed in one session over direct_post",
		func(t *testing.T) { runMixedFormatDisclosure(t, testdata.OpenID4VP_DirectPost_Host) },
	)
	t.Run(
		"a credential_sets choice across formats presents only the chosen format",
		testOpenID4VP_MixedFormat_CredentialSetChoice,
	)
	t.Run(
		"a pid sd-jwt and an age mdoc are disclosed in one dc api session",
		testOpenID4VP_MixedFormat_OverDcApi,
	)
}

// runMixedFormatDisclosure is the happy path: both queries required, both owned,
// both presented, both logged.
func runMixedFormatDisclosure(t *testing.T, verifierHost string) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndAvMdoc(t, c, sessionHandler)

	testSession, requestJwt := startMdocAvSessionCapturingRequest(
		t,
		c,
		3,
		sessionHandler,
		verifierHost,
		createAvMdocSessionRequestWithDcql(t, mixedDcql(), nil),
	)

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{pidPlanCredential()}},
				{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver18())}},
			},
		},
	)

	approvedRequestor := session.Requestor
	grantFirstOwnedOptions(t, c, 3, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	requirePidPresented(t, walletResponse)

	presented := requireSingleDeviceResponse(t, walletResponse, mixedAgeQueryId)
	requireDeviceAuthVerifies(t, presented, avSessionTranscript(t, requestJwt))

	requireMixedDisclosureLog(t, c, approvedRequestor)
}

// testOpenID4VP_MixedFormat_CredentialSetChoice offers the two formats as
// alternatives. The permission screen shows one choice with an SD-JWT option and
// an mdoc option; the user picks the mdoc, and the SD-JWT query id is absent from
// what the verifier receives.
func testOpenID4VP_MixedFormat_CredentialSetChoice(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndAvMdoc(t, c, sessionHandler)

	dcql := mixedDcqlWithCredentialSets(credentialSetChoice(mixedPidQueryId, mixedAgeQueryId))
	testSession, requestJwt := startMdocAvSessionCapturingRequest(
		t,
		c,
		3,
		sessionHandler,
		testdata.OpenID4VP_DirectPostJwt_Host,
		createAvMdocSessionRequestWithDcql(t, dcql, nil),
	)

	session := testSession.ClientSession
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{
					pidPlanCredential(),
					avPlanCredential(avAttrAgeOver18()),
				}},
			},
		},
	)

	approvedRequestor := session.Requestor
	chosen := ownedOptionWithCredentialId(t, session.DisclosurePlan.DisclosureChoicesOverview[0], avDocType)
	grantPermission(t, c, 3, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	requireQueryAbsent(t, walletResponse, mixedPidQueryId)

	presented := requireSingleDeviceResponse(t, walletResponse, mixedAgeQueryId)
	requireDeviceAuthVerifies(t, presented, avSessionTranscript(t, requestJwt))

	disclosureLog := requireSingleDisclosureLog(t, c)
	requireLogVerifier(t, disclosureLog, approvedRequestor)
	require.Len(t, disclosureLog.Credentials, 1, "only the chosen format is logged")
	requireLogCredential(t, disclosureLog.Credentials[0], avLogCredential(avAttrAgeOver18()), "chosen entry")
}

// testOpenID4VP_MixedFormat_OverDcApi runs the same two-format request over the
// Digital Credentials API: the reference verifier signs it, forces dc_api.jwt,
// and decrypts and validates what comes back. The mdoc's DeviceAuth is
// re-verified against the DC API handover with the verifier's encryption key.
func testOpenID4VP_MixedFormat_OverDcApi(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidAndAvMdoc(t, c, sessionHandler)

	verifierSession, err := StartDcApiTestSessionAtEudiVerifier(
		testdata.OpenID4VP_DcApi_Host,
		createDcApiSessionRequestWithDcql(t, dcApiVerifierOrigin, mixedDcql(), readEudiPidIssuerPyCA(t)),
	)
	require.NoError(t, err)
	requireSignedForOrigin(t, verifierSession.Request, dcApiVerifierOrigin)

	session := startDcApiSession(
		t,
		c,
		3,
		sessionHandler,
		&openid4vp.DcApiRequest{
			Protocol: openid4vp.DcApiProtocolSigned,
			Origin:   dcApiVerifierOrigin,
			Data:     signedDcApiData(t, verifierSession.Request),
		},
	)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.True(t, session.Requestor.Verified)
	requireDisclosurePlan(
		t,
		session.DisclosurePlan,
		expectedDisclosurePlan{
			Choices: []expectedPickOneChoice{
				{Owned: []expectedPlanCredential{pidPlanCredential()}},
				{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver18())}},
			},
		},
	)

	approvedRequestor := session.Requestor
	grantFirstOwnedOptions(t, c, 3, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, session.DcApiResponse, "the wallet must return a DC API response")

	require.NoError(t, PostDcApiWalletResponseToEudiVerifier(verifierSession, session.DcApiResponse))

	walletResponse := requireVerifierAccepted(t, verifierSession.EudiVerifierSession)
	requirePidPresented(t, walletResponse)

	presented := requireSingleDeviceResponse(t, walletResponse, mixedAgeQueryId)
	requireDeviceAuthVerifies(
		t,
		presented,
		dcApiTranscriptFromSignedRequest(t, verifierSession.Request, dcApiVerifierOrigin),
	)

	requireMixedDisclosureLog(t, c, approvedRequestor)
}

// ----------------------------------------------------------------------------
// Fixtures and expectations
// ----------------------------------------------------------------------------

// issuePidAndAvMdoc fills the wallet with the reference issuer's PID as SD-JWT
// and its age credential as mdoc, as sessions 1 and 2.
func issuePidAndAvMdoc(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler) {
	t.Helper()
	issuePidViaPythonIssuer(t, c, 1, sessionHandler, samplePidUserData())
	issueAvMdocViaPythonIssuer(t, c, 2, sessionHandler)
}

// mixedDcql asks for the PID's names as SD-JWT and the age credential's
// age_over_18 as mdoc.
func mixedDcql() map[string]any {
	return newDcql(mixedPidQuery(), mixedAgeQuery())
}

func mixedDcqlWithCredentialSets(credentialSets []map[string]any) map[string]any {
	return newDcqlWithCredentialSets(credentialSets, mixedPidQuery(), mixedAgeQuery())
}

func mixedPidQuery() map[string]any {
	return map[string]any{
		"id":     mixedPidQueryId,
		"format": string(clientmodels.Format_SdJwtVc),
		"meta":   map[string]any{"vct_values": []string{eudiPidIssuerPyVct}},
		"claims": []map[string]any{
			{"path": []string{"given_name"}},
			{"path": []string{"family_name"}},
		},
	}
}

func mixedAgeQuery() map[string]any {
	return avQuery(mixedAgeQueryId, avClaim(avMandatoryElement))
}

// pidPlanCredential is the PID as the permission screen shows it for the names
// query. Attributes follow the issuer's metadata order, not the query's.
func pidPlanCredential() expectedPlanCredential {
	return expectedPlanCredential{
		CredentialId:    eudiPidIssuerPyVct,
		Name:            eudiPidIssuerPyDisplayNameEN,
		IssuerName:      avIssuerDisplayName,
		Attributes:      pidNameAttrs(),
		IssuerVerified:  new(true),
		Format:          new(clientmodels.Format_SdJwtVc),
		HasIssuanceDate: new(true),
		HasExpiryDate:   new(true),
	}
}

func pidNameAttrs() []expectedAttr {
	data := samplePidUserData()
	return []expectedAttr{
		{Path: []any{"family_name"}, DisplayName: new("Family Name(s)"), Value: strVal(data.FamilyName)},
		{Path: []any{"given_name"}, DisplayName: new("Given Name(s)"), Value: strVal(data.GivenName)},
	}
}

// requirePidPresented checks the verifier recorded one SD-JWT presentation for
// the PID query disclosing exactly the two requested names.
func requirePidPresented(t *testing.T, walletResponse map[string]any) {
	t.Helper()

	presentations := presentationsForQuery(t, walletResponse, mixedPidQueryId)
	require.Len(t, presentations, 1, "expected exactly one PID presentation")

	data := samplePidUserData()
	disclosed := extractDisclosedClaims(t, presentations[0])
	require.Equal(
		t,
		map[string]string{
			"given_name":  data.GivenName,
			"family_name": data.FamilyName,
		},
		disclosed,
		"the PID presentation must disclose the two requested names and nothing else",
	)
}

// requireMixedDisclosureLog checks one log entry records both credentials, each
// under its own format, both from the same verified issuer.
func requireMixedDisclosureLog(t *testing.T, c *client.Client, approvedRequestor clientmodels.TrustedParty) {
	t.Helper()

	disclosureLog := requireSingleDisclosureLog(t, c)
	requireLogVerifier(t, disclosureLog, approvedRequestor)
	require.Len(t, disclosureLog.Credentials, 2, "one log credential per presented credential")

	loggedPid := findLogCredential(t, disclosureLog.Credentials, eudiPidIssuerPyVct)
	requireLogCredential(
		t,
		loggedPid,
		expectedLogCredential{
			CredentialId:   eudiPidIssuerPyVct,
			Formats:        []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Name:           new(eudiPidIssuerPyDisplayNameEN),
			IssuerName:     new(avIssuerDisplayName),
			IssuerVerified: new(true),
			Attributes:     pidNameAttrs(),
		},
		"pid entry",
	)

	loggedAge := findLogCredential(t, disclosureLog.Credentials, avDocType)
	requireLogCredential(t, loggedAge, avLogCredential(avAttrAgeOver18()), "age entry")
}

// ownedOptionWithCredentialId returns the owned option for the given credential
// id, for the shapes where the user picks between credentials.
func ownedOptionWithCredentialId(
	t *testing.T,
	pickOne clientmodels.DisclosurePickOne,
	credentialId string,
) *clientmodels.DisclosureBundle {
	t.Helper()

	for _, bundle := range pickOne.OwnedOptions {
		for _, cred := range bundle.Credentials {
			if cred.CredentialId == credentialId {
				return bundle
			}
		}
	}

	t.Fatalf("no owned option carries credential %q", credentialId)
	return nil
}
