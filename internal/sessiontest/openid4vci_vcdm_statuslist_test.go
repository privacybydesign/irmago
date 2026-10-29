package sessiontest

// End-to-end status tests for SD-JWT-secured VCDM credentials: the VCDM
// counterpart of openid4vci_statuslist_test.go, against the same veramo issuer.
//
// The issuer gives a vc+sd-jwt credential a W3C Bitstring Status List entry in
// `credentialStatus`, and serves the status list credential itself as a
// vc+jwt. So these tests pin the W3C mechanism end to end; the IETF
// `status.status_list` claim on a VCDM credential is covered in-process in
// eudi/services/vcdm_status_test.go.
//
// Each test mirrors the SD-JWT VC test of the same behaviour; the wallet must
// treat the two alike.

import (
	"context"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

const (
	// vcdmStatusListConfigId is the only VCDM credential configuration of the
	// test issuer with a statuslist entry.
	vcdmStatusListConfigId = "StatusListCredentialVcdm"

	// vcdmStatusListRecordType is what veramo files the issued credentials
	// under: the configuration's scope, not its id. The email tells them apart
	// from the TestCredentialVcdm credentials, which share the scope.
	vcdmStatusListRecordType = "TestVcdmCredential"

	vcdmStatusListEmail = "statuslist-vcdm@example.com"
)

var vcdmStatusListClaims = `{
	"given_name": "Vera",
	"family_name": "StatusList",
	"email": "` + vcdmStatusListEmail + `"
}`

func testSessionHandlerForOpenID4VCIVcdmStatusList(t *testing.T) {
	t.Run("issued credential supports revocation and refresh runs", testOpenID4VCIVcdmStatusListRevocationSupported)
	t.Run("revocation found by the sweep notifies the app", testOpenID4VCIVcdmStatusListRevocationNotifiesApp)
	t.Run("revoked credential is surfaced in the disclosure plan", testOpenID4VPVcdmStatusListRevokedSurfacedInPlan)
	t.Run("a revoked credential is recorded as revoked in the disclosure log", testOpenID4VPVcdmStatusListRevokedRecordedInLog)
}

func issueVcdmStatusListCredential(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionId int) {
	t.Helper()
	issueCredentialViaOpenID4VCIFromIssuer(t, c, sessionId, sessionHandler, preAuthIssuerURL, preAuthAdminToken,
		vcdmStatusListConfigId, vcdmStatusListClaims)
}

// vcdmStatusListDcql asks for the status-list VCDM credential's email.
var vcdmStatusListDcql = vcdmDcqlQuery(
	`"meta": {"type_values": [["`+vcdmVerifiableCredentialIri+`", "`+vcdmCredentialType+`"]]}`,
	[]any{"credentialSubject", "email"},
)

func testOpenID4VCIVcdmStatusListRevocationSupported(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueVcdmStatusListCredential(t, c, sessionHandler, 1)

	cred := requireSingleVcdmCredential(t, c)
	require.True(t, cred.RevocationSupported, "a credential carrying a status reference supports revocation")
	require.False(t, cred.Revoked, "a freshly issued credential is not revoked")

	require.NoError(t, c.RefreshStatuses(context.Background()))
}

func testOpenID4VCIVcdmStatusListRevocationNotifiesApp(t *testing.T) {
	c, clientHandler, sessionHandler := instantiateClient(t, nil, "en")
	defer c.Close()

	issueVcdmStatusListCredential(t, c, sessionHandler, 1)
	changesAfterIssuance := clientHandler.CredentialsChangedCount()

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance, clientHandler.CredentialsChangedCount(),
		"re-confirming a status must not wake the app")

	revokeCredentialsViaVeramo(t, vcdmStatusListRecordType, vcdmStatusListEmail)

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance+1, clientHandler.CredentialsChangedCount(),
		"a status change must wake the app")
	require.True(t, requireSingleVcdmCredential(t, c).Revoked, "the revocation the app was told about")

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance+1, clientHandler.CredentialsChangedCount(),
		"a known revocation is not re-reported")
}

func testOpenID4VPVcdmStatusListRevokedSurfacedInPlan(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueVcdmStatusListCredential(t, c, sessionHandler, 1)
	revokeCredentialsViaVeramo(t, vcdmStatusListRecordType, vcdmStatusListEmail)
	require.NoError(t, c.RefreshStatuses(context.Background()))

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, vcdmStatusListDcql)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// As for SD-JWT VC, the wallet offers a revoked credential and leaves the
	// decision to the frontend.
	require.NotEmpty(t, session.DisclosurePlan.DisclosureChoicesOverview, "expected a disclosure choice")
	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.NotEmpty(t, owned, "revoked instance still expected in the plan")
	require.NotEmpty(t, owned[0].Credentials, "bundle must hold the credential instance")
	requirePlanCredentialDetails(t, owned[0].Credentials[0], expectedPlanCredential{
		Revoked:             new(true),
		RevocationSupported: new(true),
	}, "revoked VCDM candidate")
}

func testOpenID4VPVcdmStatusListRevokedRecordedInLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueVcdmStatusListCredential(t, c, sessionHandler, 1)
	revokeCredentialsViaVeramo(t, vcdmStatusListRecordType, vcdmStatusListEmail)
	require.NoError(t, c.RefreshStatuses(context.Background()))

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, vcdmStatusListDcql)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.NotEmpty(t, owned, "revoked instance still expected in the plan")

	grantPermission(t, c, 2, makeDisclosureChoice(owned[0]))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 1)
	requireLogCredential(t, disclosureLog.Credentials[0], expectedLogCredential{
		CredentialId:        vcdmCredentialId,
		Formats:             []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVcdm},
		Revoked:             new(true),
		RevocationSupported: new(true),
	}, "revoked VCDM entry")
}
