package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// An optional credential set whose option names several credential queries:
// `{"options": [["test-credential", "vcdm"]], "required": false}`. The pair is
// shared together or not at all, and because the set is optional, missing one
// half of it never blocks the session with an issuance step.
//
// The pair mixes formats on purpose (an SD-JWT VC and a VCDM credential), as
// eduwallet's exam check-in does.

func testSessionHandlerForOpenID4VPOptionalCombinedSet(t *testing.T) {
	t.Run("optional pair shared next to a required set", testOptionalCombinedSetShared)
	t.Run("optional pair skipped next to a required set", testOptionalCombinedSetSkipped)
	t.Run("optional pair with one half missing asks for no issuance", testOptionalCombinedSetPartlyOwned)
	t.Run("only an optional pair, skipped, sends an empty response", testOnlyOptionalCombinedSetSkipped)
}

const optionalPairTestClaims = `{
	"given_name": "Test",
	"family_name": "User",
	"email": "test@example.com"
}`

const optionalPairEmailClaims = `{
	"email": "required@example.com",
	"domain": "example.com"
}`

// optionalCombinedSetQuery asks for the test SD-JWT VC and the VCDM credential
// as one optional option, and, when withRequiredEmail is set, for an email
// credential in a required set placed before it.
func optionalCombinedSetQuery(withRequiredEmail bool) string {
	emailQuery, emailSet := "", ""
	if withRequiredEmail {
		emailQuery = `,
				{
					"id": "email-cred",
					"format": "dc+sd-jwt",
					"meta": {"vct_values": ["https://localhost:8443/vct/email"]},
					"claims": [ { "path": ["email"] } ]
				}`
		emailSet = `{ "options": [["email-cred"]] },
				`
	}
	return `{
		"dcql": {
			"credentials": [
				{
					"id": "test-credential",
					"format": "dc+sd-jwt",
					"meta": {"vct_values": ["https://localhost:8443/vct/test"]},
					"claims": [ { "path": ["email"] } ]
				},
				{
					"id": "` + vcdmQueryId + `",
					"format": "vc+sd-jwt",
					"meta": {"type_values": [["` + vcdmVerifiableCredentialIri + `", "` + vcdmCredentialType + `"]]},
					"claims": [ { "path": ["credentialSubject", "given_name"] } ]
				}` + emailQuery + `
			],
			"credential_sets": [
				` + emailSet + `{ "options": [["test-credential", "` + vcdmQueryId + `"]], "required": false }
			]
		}
	}`
}

func testOptionalCombinedSetShared(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "TestCredentialSdJwt", optionalPairTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 3, sessionHandler, "EmailCredentialSdJwt", optionalPairEmailClaims)
	holderDid := vcdmHolderDid(t, requireSingleVcdmCredential(t, c).Attributes)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, optionalCombinedSetQuery(true))
	startOpenID4VPDisclosureSession(t, c, 4, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	require.Nil(t, session.DisclosurePlan.IssueDuringDisclosure)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 2)

	required := session.DisclosurePlan.DisclosureChoicesOverview[0]
	require.False(t, required.Optional)
	require.Len(t, required.OwnedOptions, 1)

	pair := session.DisclosurePlan.DisclosureChoicesOverview[1]
	require.True(t, pair.Optional)
	require.Len(t, pair.OwnedOptions, 1)
	require.Len(t, pair.OwnedOptions[0].Credentials, 2, "the pair is offered as one bundle")

	grantPermission(t, c, session.Id,
		makeDisclosureChoice(required.OwnedOptions[0]),
		makeDisclosureChoice(pair.OwnedOptions[0]),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	requireNoVeramoVcdmErrors(t, result)
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "required@example.com"),
	)
	requireVerifierReceivedClaims(t, result, "test-credential",
		claim([]any{"email"}, "test@example.com"),
	)
	requireVerifierReceivedClaims(t, result, vcdmQueryId,
		claim([]any{"given_name"}, "Vera"),
		claim([]any{"family_name"}, "Modell"),
		claim([]any{"email"}, "vera@example.com"),
		claim([]any{"id"}, holderDid),
	)
}

func testOptionalCombinedSetSkipped(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "TestCredentialSdJwt", optionalPairTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 3, sessionHandler, "EmailCredentialSdJwt", optionalPairEmailClaims)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, optionalCombinedSetQuery(true))
	startOpenID4VPDisclosureSession(t, c, 4, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 2)
	required := session.DisclosurePlan.DisclosureChoicesOverview[0]
	require.Len(t, required.OwnedOptions, 1)
	require.True(t, session.DisclosurePlan.DisclosureChoicesOverview[1].Optional)

	grantPermission(t, c, session.Id,
		makeDisclosureChoice(required.OwnedOptions[0]),
		clientmodels.DisclosureDisconSelection{},
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "required@example.com"),
	)
	requireVerifierReceivedNothingFor(t, result, "test-credential")
	requireVerifierReceivedNothingFor(t, result, vcdmQueryId)
}

// The wallet holds the VCDM credential but not the test SD-JWT VC, so the
// optional pair cannot be answered. The session still asks for permission
// straight away, offering the missing half as something the user could add,
// and the user shares only the required email.
func testOptionalCombinedSetPartlyOwned(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "EmailCredentialSdJwt", optionalPairEmailClaims)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, optionalCombinedSetQuery(true))
	startOpenID4VPDisclosureSession(t, c, 3, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	require.Nil(t, session.DisclosurePlan.IssueDuringDisclosure,
		"an optional set never forces issuance, even when half of its option is owned")
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 2)

	required := session.DisclosurePlan.DisclosureChoicesOverview[0]
	require.Len(t, required.OwnedOptions, 1)

	pair := session.DisclosurePlan.DisclosureChoicesOverview[1]
	require.True(t, pair.Optional)
	require.Empty(t, pair.OwnedOptions, "the VCDM credential alone does not answer the pair")
	require.Len(t, pair.ObtainableOptions, 1)
	require.Equal(t, "https://localhost:8443/vct/test", pair.ObtainableOptions[0].CredentialId,
		"only the missing half is offered, not the VCDM credential the wallet already holds")

	grantPermission(t, c, session.Id,
		makeDisclosureChoice(required.OwnedOptions[0]),
		clientmodels.DisclosureDisconSelection{},
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "required@example.com"),
	)
	requireVerifierReceivedNothingFor(t, result, vcdmQueryId)
}

// A request whose only set is the optional pair, skipped: like any skipped
// optional disclosure, the verifier gets a response holding no credentials.
func testOnlyOptionalCombinedSetSkipped(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "TestCredentialSdJwt", optionalPairTestClaims)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, optionalCombinedSetQuery(false))
	startOpenID4VPDisclosureSession(t, c, 3, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 1)
	pair := session.DisclosurePlan.DisclosureChoicesOverview[0]
	require.True(t, pair.Optional)
	require.Len(t, pair.OwnedOptions, 1)
	require.Len(t, pair.OwnedOptions[0].Credentials, 2)

	grantPermission(t, c, session.Id, clientmodels.DisclosureDisconSelection{})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	if result.Result != nil {
		require.Empty(t, result.Result.Credentials, "a skipped pair must not reach the verifier")
	}
}
