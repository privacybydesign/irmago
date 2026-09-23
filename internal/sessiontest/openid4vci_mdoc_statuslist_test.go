package sessiontest

// End-to-end Token Status List (draft-ietf-oauth-status-list-15) tests for
// mso_mdoc, the counterpart of openid4vci_statuslist_test.go for SD-JWT VC.
//
// The credentials come from the EUDI Python issuer, which embeds a status
// reference in the MSO (§6.3.2) when its take_url hands it one. The status list
// behind that reference is served by an in-test server (see
// helper_mdoc_status_list_test.go), so each test decides what the list says and
// when it changes. Only the PID is given a status: the issuer never asks for one
// for the age credential (country AV), and the mDL is left without one so
// nothing else in this suite changes.
//
// What they exercise:
//   - issuance-time holder check: the wallet fetches and verifies the Status List
//     Token (CWT, or JWT in one test) and stores the credential only
//     when its entry reads VALID; a revoked entry, an unreachable list or a list
//     signed by an untrusted key all refuse the credential;
//   - the credential list reports revocation support and the status;
//   - RefreshStatuses finds a revocation made after issuance and tells the app;
//   - disclosure: a revoked mdoc is still offered, with Revoked=true, and the
//     activity log records that it was revoked.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
)

// statusListEntryRevoked is the value of a revoked entry in a 1-bit list
// (draft-ietf-oauth-status-list-15 §7.1: 0x01 is INVALID).
const statusListEntryRevoked uint8 = 1

func testSessionHandlerForOpenID4VCIMdocStatusList(t *testing.T) {
	t.Run("issuance/a valid status is accepted and reported", testMdocStatusListIssuanceAcceptsValid)
	t.Run("issuance/without a status the credential reports no revocation support", testMdocStatusListWithoutStatus)
	t.Run("issuance/a credential revoked before it is stored is refused", testMdocStatusListIssuanceRefusesRevoked)
	t.Run("issuance/a status list that cannot be fetched refuses the credential", testMdocStatusListIssuanceRefusesUnreachableList)
	t.Run("issuance/a status list signed by an untrusted key refuses the credential", testMdocStatusListIssuanceRefusesUntrustedList)
	t.Run("refresh/a revocation found by the sweep notifies the app", testMdocStatusListRevocationNotifiesApp)
	t.Run("refresh/a JWT status list works for an mdoc too", testMdocStatusListJwtList)
	t.Run("disclosure/a revoked credential is offered as revoked and logged as revoked", testMdocStatusListRevokedDisclosure)
}

// testMdocStatusListIssuanceAcceptsValid issues a PID whose entry reads VALID.
//
// That the issuance succeeds is only half the point: a wallet that ignored the
// status would succeed too. The token fetch proves the wallet looked, and the
// credential list proves it kept the reference.
func testMdocStatusListIssuanceAcceptsValid(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListCWT)

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueMdocViaPythonIssuer(t, c, 1, sessionHandler, pidMdocConfigId, pidMdocIssuanceData())

	require.Positive(t, statusList.entriesHandedOut(), "the issuer should have asked for a status list entry")
	require.Positive(t, statusList.tokenFetchCount(), "the wallet should have checked the status at issuance")

	pid := credentialListEntry(t, c, pidMdocDocType)
	require.True(t, pid.RevocationSupported, "a PID with a status reference can be checked for revocation")
	require.False(t, pid.Revoked)

	require.NoError(t, c.RefreshStatuses(context.Background()))
	pid = credentialListEntry(t, c, pidMdocDocType)
	require.False(t, pid.Revoked, "the sweep re-reads the list, which still says valid")
}

// testMdocStatusListWithoutStatus issues an mDL next to a status-carrying PID.
// The server hands entries to the PID only, so the mDL is issued as by an issuer
// without revocation, so the two must come out different: only the PID can be checked.
func testMdocStatusListWithoutStatus(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListCWT)

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueMdocViaPythonIssuer(t, c, 1, sessionHandler, mdlConfigId, mdlIssuanceData())
	require.Zero(t, statusList.entriesHandedOut(), "the mDL was not supposed to get an entry")

	mdl := credentialListEntry(t, c, mdlDocType)
	require.False(t, mdl.RevocationSupported, "an mDL without a status reference cannot be checked")
	require.False(t, mdl.Revoked)

	issueMdocViaPythonIssuer(t, c, 2, sessionHandler, pidMdocConfigId, pidMdocIssuanceData())
	pid := credentialListEntry(t, c, pidMdocDocType)
	require.True(t, pid.RevocationSupported)

	// The sweep has one credential to check and must leave the other alone.
	require.NoError(t, c.RefreshStatuses(context.Background()))
	mdl = credentialListEntry(t, c, mdlDocType)
	require.False(t, mdl.RevocationSupported)
	require.False(t, mdl.Revoked)
}

// testMdocStatusListIssuanceRefusesRevoked hands out entries that already read
// revoked. The wallet checks at issuance and must refuse, the same fail-closed
// rule it applies to SD-JWT VCs.
func testMdocStatusListIssuanceRefusesRevoked(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListCWT)
	statusList.setNewStatus(statusListEntryRevoked)

	requirePidMdocIssuanceRefused(t, statusList, "credential status is invalid")
}

// testMdocStatusListIssuanceRefusesUnreachableList has the issuer embed a
// reference to a list the server then fails to serve. A status the wallet
// cannot read is not a valid one.
func testMdocStatusListIssuanceRefusesUnreachableList(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListCWT)
	statusList.setTokenUnavailable()

	requirePidMdocIssuanceRefused(t, statusList, "status list fetch failed")
}

// testMdocStatusListIssuanceRefusesUntrustedList serves a well-formed list that
// says valid, signed by a key the wallet does not trust. The signature is what
// makes the list the issuer's word, so this must be refused like a revocation.
func testMdocStatusListIssuanceRefusesUntrustedList(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListCWT).
		withSigner(statuslist.NewTestStatusListSigner(t))

	requirePidMdocIssuanceRefused(t, statusList, "certificate signed by unknown authority")
}

// testMdocStatusListRevocationNotifiesApp is the mdoc counterpart of
// testOpenID4VCIStatusListRevocationNotifiesApp: the issuer revokes after
// issuance, and the wallet's sweep finds it and tells the app, once.
func testMdocStatusListRevocationNotifiesApp(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListCWT)

	c, clientHandler, sessionHandler := instantiateClient(t, readEudiPidIssuerPyCA(t), "en")
	defer c.Close()

	issueMdocViaPythonIssuer(t, c, 1, sessionHandler, pidMdocConfigId, pidMdocIssuanceData())
	changesAfterIssuance := clientHandler.CredentialsChangedCount()

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance, clientHandler.CredentialsChangedCount(),
		"re-confirming a status must not wake the app")

	statusList.setAll(statusListEntryRevoked)

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance+1, clientHandler.CredentialsChangedCount(),
		"a status change must wake the app")

	pid := credentialListEntry(t, c, pidMdocDocType)
	require.True(t, pid.Revoked, "the revocation the app was told about")
	require.True(t, pid.RevocationSupported)

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance+1, clientHandler.CredentialsChangedCount(),
		"a known revocation is not re-reported")
}

// testMdocStatusListJwtList runs issuance and the sweep against a list served
// as a JWT. Nothing in the spec ties the list's encoding to the credential's,
// and the wallet tells them apart by the bytes it fetches.
func testMdocStatusListJwtList(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListJWT)

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueMdocViaPythonIssuer(t, c, 1, sessionHandler, pidMdocConfigId, pidMdocIssuanceData())
	require.Positive(t, statusList.tokenFetchCount(), "the wallet should have checked the status at issuance")
	pid := credentialListEntry(t, c, pidMdocDocType)
	require.True(t, pid.RevocationSupported)
	require.False(t, pid.Revoked)

	statusList.setAll(statusListEntryRevoked)

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.True(t, credentialListEntry(t, c, pidMdocDocType).Revoked)
}

// testMdocStatusListRevokedDisclosure revokes an issued PID and then asks for
// it. As for SD-JWT VCs, the wallet does not hide a revoked credential: it
// offers it marked revoked, leaves the choice to the user, and records in the
// log that what was shared had been revoked.
func testMdocStatusListRevokedDisclosure(t *testing.T) {
	statusList := startMdocStatusListServer(t, mdocStatusListCWT)

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueMdocViaPythonIssuer(t, c, 1, sessionHandler, pidMdocConfigId, pidMdocIssuanceData())
	statusList.setAll(statusListEntryRevoked)

	// The token cached at issuance still says valid; the sweep replaces it.
	require.NoError(t, c.RefreshStatuses(context.Background()))

	dcql := `{
		"credentials": [
			{
				"id": "pid",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
				"claims": [
					{ "path": ["eu.europa.ec.eudi.pid.1", "family_name"] }
				]
			}
		]
	}`
	testSession, _ := startMdocDcqlSession(t, c, 2, sessionHandler, dcql)

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 1)
	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.NotEmpty(t, owned, "a revoked credential is still offered")
	requirePlanCredentialDetails(t, owned[0].Credentials[0], expectedPlanCredential{
		Revoked:             new(true),
		RevocationSupported: new(true),
	}, "revoked PID")

	grantFirstOwnedOptions(t, c, 2, session)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 1)
	requireLogCredential(t, disclosureLog.Credentials[0], expectedLogCredential{
		CredentialId:        pidMdocDocType,
		Formats:             []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc},
		Revoked:             new(true),
		RevocationSupported: new(true),
	}, "revoked PID entry")
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// requirePidMdocIssuanceRefused issues a PID into a fresh wallet and requires
// the wallet to refuse it for wantReason, with nothing stored.
//
// The wallet verifies the credential before it asks the user to accept it, so
// the refusal lands before any permission step and nothing is offered.
func requirePidMdocIssuanceRefused(t *testing.T, statusList *mdocStatusListServer, wantReason string) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	session := redeemMdocOfferViaPythonIssuer(t, c, 1, sessionHandler, pidMdocConfigId, pidMdocIssuanceData())
	require.Equal(t, clientmodels.Status_Error, session.Status,
		"the wallet must refuse a credential whose status is not valid")
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, wantReason, "refused, but not for the reason under test")
	require.Empty(t, session.OfferedCredentials, "the wallet offered a credential it was about to refuse")

	require.Positive(t, statusList.entriesHandedOut(),
		"the issuer never asked for a status entry, so this refusal proves nothing about status")
	requireNoMdocStored(t, c, pidMdocDocType)
}
