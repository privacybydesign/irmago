package sessiontest

// End-to-end Token Status List (draft-ietf-oauth-status-list-15) tests over
// OpenID4VCI. These require the full docker-compose stack; the veramo issuer
// hosts the status list itself.
//
// What they exercise:
//   - issuance-time holder check: the wallet fetches + verifies the
//     statuslist+jwt the issuer serves (signed by its did:web, sub == uri) and
//     accepts the credential because the freshly-allocated bit reads VALID;
//   - RefreshStatuses: the background sweep re-fetches for the stored instance
//     and writes back its LastKnownStatus;
//   - disclosure-time revocation surfacing: after the issuer revokes the
//     credential, a subsequent OpenID4VP disclosure still offers it in the
//     plan, now carrying Revoked=true (IRMA parity — the frontend decides, the
//     wallet does not fail closed).
//
// At disclosure the plan's Revoked flag comes from a live (cache-aware) Token
// Status List check on the instance, performed by services.RevocationService
// (kept out of the disclosure planner itself). The checker serves the cached
// token while it is within its own ttl and re-fetches once expired; if no
// verifiable status is available it fails safe to revoked. The wallet does not
// error the session — it surfaces Revoked for the frontend, with the verifier
// as backstop.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// testSessionHandlerForOpenID4VCIStatusList groups the status-list e2e tests.
// Wire it into TestSessionHandler (session_handler_test.go) with:
//
//	t.Run("openid4vci/sdjwtvc/status-list", testSessionHandlerForOpenID4VCIStatusList)
func testSessionHandlerForOpenID4VCIStatusList(t *testing.T) {
	t.Run("issuance accepts a valid status and refresh runs", testOpenID4VCIStatusListIssuanceAcceptsValid)
	t.Run("revoked credential is surfaced in the disclosure plan", testOpenID4VPStatusListRevokedSurfacedInPlan)
	t.Run("a revoked credential cannot be shared, so nothing is logged", testOpenID4VPStatusListRevokedRecordedInLog)
	t.Run("revocation found by the sweep notifies the app", testOpenID4VCIStatusListRevocationNotifiesApp)
}

// testOpenID4VCIStatusListRevocationNotifiesApp is the SD-JWT VC counterpart of
// TestIdemixRevocationNotifiesApp: an issuer revokes a real status-list
// credential, and the wallet's status refresh sweep tells the app about it
// through ClientHandler.CredentialsChanged. It also pins the other half of the
// contract — a sweep that only re-confirms a status the wallet already had stays
// silent, so the scheduled sweep does not nag the app on every interval.
func testOpenID4VCIStatusListRevocationNotifiesApp(t *testing.T) {
	c, clientHandler, sessionHandler := instantiateClient(t, nil, "en")
	defer c.Close()

	issueStatusListCredential(t, c, sessionHandler, 1)

	// Issuance may itself be a credentials change, so measure from here.
	changesAfterIssuance := clientHandler.CredentialsChangedCount()

	// The credential is valid and the wallet already recorded it as such at
	// issuance, so this sweep finds nothing new.
	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance, clientHandler.CredentialsChangedCount(),
		"re-confirming a status must not wake the app")

	revokeStatusListCredentialViaVeramo(t, statusListCredentialEmail)

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance+1, clientHandler.CredentialsChangedCount(),
		"a status change must wake the app")

	// The credential is revoked in what the app would now re-request.
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	cred := findCredentialByName(t, creds, "Status List Credential (SD-JWT)")
	require.True(t, cred.Revoked, "the revocation the app was told about")

	// A later sweep re-confirms the revocation it already knows about.
	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, changesAfterIssuance+1, clientHandler.CredentialsChangedCount(),
		"a known revocation is not re-reported")
}

const statusListCredentialEmail = "statuslist@example.com"

// createStatusListPreAuthOffer creates a pre-authorized offer for the
// StatusListCredentialSdJwt — the only SD-JWT VC credential whose metadata has
// a `statuslist` entry, so issuance reserves an index on the issuer's own
// statuslist+jwt list and embeds status.status_list{idx,uri}.
func createStatusListPreAuthOffer(t *testing.T) openid4vciOfferResponse {
	t.Helper()
	return postOffer(t, preAuthIssuerURL, preAuthAdminToken, fmt.Sprintf(`{
		"credentials": ["StatusListCredentialSdJwt"],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": {
			"given_name": "Test",
			"family_name": "StatusList",
			"email": %q
		}
	}`, statusListCredentialEmail))
}

// issueStatusListCredential runs the full pre-auth issuance for the
// status-list credential and asserts it succeeds. Success here already proves
// the issuance-time holder status check passed (the wallet fetched + verified
// the issuer's statuslist+jwt and read VALID at the allocated index).
func issueStatusListCredential(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionId int) {
	t.Helper()
	offer := createStatusListPreAuthOffer(t)

	startOpenID4VCISession(t, c, sessionId, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error {
		t.Fatalf("status-list issuance errored before permission (check `docker compose logs veramo_openid4vci`): %+v", session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error {
		t.Fatalf("status-list issuance errored after permission grant (the holder-side status check fetches the statuslist+jwt from the issuer — check `docker compose logs veramo_openid4vci`): %+v", session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

func testOpenID4VCIStatusListIssuanceAcceptsValid(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueStatusListCredential(t, c, sessionHandler, 1)

	// The credential is present in the wallet.
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	cred := findCredentialByName(t, creds, "Status List Credential (SD-JWT)")
	require.NotNil(t, cred, "issued status-list credential should appear in GetCredentials")

	// The background refresh sweep runs against the real issuer for the stored
	// instance and completes without error (a per-URI fetch failure would be
	// logged-and-swallowed, but a transport/setup error surfaces here).
	require.NoError(t, c.RefreshStatuses(context.Background()))
}

func testOpenID4VPStatusListRevokedSurfacedInPlan(t *testing.T) {
	// Requires an IETF-compliant status source. Upstream eduwallet/veramo-agent
	// packs bits MSB-first (W3C @digitalcredentials/bitstring), which the IETF
	// wallet (LSB-first, draft §4.1) reads at the wrong position, so a revoked
	// credential reads as VALID. docker-compose therefore builds the issuer
	// from privacybydesign/veramo-agent, a fork that emits LSB-first bit arrays
	// for application/statuslist+jwt.
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue, then revoke at the issuer, which flips the credential's bit.
	issueStatusListCredential(t, c, sessionHandler, 1)
	revokeStatusListCredentialViaVeramo(t, statusListCredentialEmail)

	// The wallet cached the (valid) status list token at issuance. RefreshStatuses
	// bypasses that cache, re-fetches the now-revoked list, and updates the shared
	// cache. The disclosure plan's live (cache-aware) status check then reads the
	// refreshed (revoked) list; without this refresh it would hit the still-valid
	// cached token.
	require.NoError(t, c.RefreshStatuses(context.Background()))

	// Start an OpenID4VP disclosure that requests the status-list credential by
	// its vct.
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, statusListDisclosureDcql)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The wallet shows a revoked credential rather than hiding it: it is the
	// slot's candidate with Revoked=true, marked unusable with reason revoked,
	// so the frontend can offer to add it again.
	require.NotEmpty(t, session.DisclosurePlan.Choices, "expected a disclosure choice")
	slot := session.DisclosurePlan.Choices[0].Options[0].Slots[0]
	require.Len(t, slot.Candidates, 1, "revoked instance still expected in the plan")
	require.False(t, slot.Candidates[0].Usable, "a revoked card cannot be shared")
	require.Equal(t, clientmodels.UnusableReason_Revoked, slot.Candidates[0].UnusableReason)
	owned := []*bundle{{Credentials: slot.Candidates}}
	require.True(t, owned[0].Credentials[0].Revoked,
		"revoked instance must be surfaced to the frontend with Revoked=true")
}

// statusListCredentialVct is the vct the test issuer mints the status-list
// credential under.
const statusListCredentialVct = "https://localhost:8443/vct/statuslist"

// statusListDisclosureDcql asks for the status-list credential's email.
const statusListDisclosureDcql = `{
	"dcql": {
		"credentials": [
			{
				"id": "statuslist-cred",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["` + statusListCredentialVct + `"] },
				"claims": [ { "path": ["email"] } ]
			}
		]
	}
}`

// testOpenID4VPStatusListRevokedRecordedInLog follows the plan test above through
// to the answer: the revoked card is offered, but as unusable, and an answer
// naming it is refused, so nothing reaches the verifier or the activity log.
func testOpenID4VPStatusListRevokedRecordedInLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueStatusListCredential(t, c, sessionHandler, 1)
	revokeStatusListCredentialViaVeramo(t, statusListCredentialEmail)
	require.NoError(t, c.RefreshStatuses(context.Background()))

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, statusListDisclosureDcql)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	requireRevokedCandidateRefused(t, c, sessionHandler, session, statusListCredentialVct)
}

// revokeStatusListCredentialViaVeramo revokes every issued status-list
// credential bearing the given email, via the veramo issuer admin API, which
// flips that credential's bit.
//
// StatusListCredentialSdJwt is issued as a batch (multiple instances, each with
// its own status index), and the same email is reused across test runs, so we
// revoke *all* matching records — that guarantees whichever instance the wallet
// discloses has been revoked.
func revokeStatusListCredentialViaVeramo(t *testing.T, email string) {
	t.Helper()
	revokeCredentialsViaVeramo(t, "StatusListCredentialSdJwt", email)
}

// revokeCredentialsViaVeramo is revokeStatusListCredentialViaVeramo for any
// credential the test issuer reserved a status for. recordType is the name
// veramo files the issued credentials under, which for a configuration with a
// scope is the scope rather than the configuration id.
func revokeCredentialsViaVeramo(t *testing.T, recordType string, email string) {
	t.Helper()

	// 1) List the issued status-list credentials (POST, admin-authenticated).
	//    The claims are returned as a JSON string, so we match the email there.
	listBody := fmt.Sprintf(`{"credential":%q}`, recordType)
	req, err := http.NewRequest(http.MethodPost, preAuthIssuerURL+"/api/list-credentials", strings.NewReader(listBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+preAuthAdminToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "listing veramo credentials should succeed")

	var records []struct {
		UUID   string `json:"uuid"`
		Claims string `json:"claims"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&records))

	// 2) Revoke every record whose claims contain our email. veramo sets the
	//    bit on every status list the record was issued with.
	revoked := 0
	for _, rec := range records {
		if rec.UUID == "" || !strings.Contains(rec.Claims, email) {
			continue
		}
		body := fmt.Sprintf(`{"uuid": %q, "state": "revoke"}`, rec.UUID)
		rreq, err := http.NewRequest(http.MethodPost, preAuthIssuerURL+"/api/revoke-credential", strings.NewReader(body))
		require.NoError(t, err)
		rreq.Header.Set("Content-Type", "application/json")
		rreq.Header.Set("Authorization", "Bearer "+preAuthAdminToken)
		rresp, err := http.DefaultClient.Do(rreq)
		require.NoError(t, err)
		rresp.Body.Close()
		require.Equal(t, http.StatusOK, rresp.StatusCode, "revoke-credential should succeed")
		revoked++
	}
	require.Positive(t, revoked, "expected to revoke at least one status-list credential for %s", email)
}

// requireRevokedCandidateRefused checks that a revoked card is offered in the
// plan but cannot be shared: it is the slot's candidate with usable false and
// reason revoked, an answer naming it is refused, and nothing is logged.
func requireRevokedCandidateRefused(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, session clientmodels.SessionState, credentialId string) {
	t.Helper()
	require.NotEmpty(t, session.DisclosurePlan.Choices, "expected a disclosure choice")
	slot := session.DisclosurePlan.Choices[0].Options[0].Slots[0]
	require.Len(t, slot.Candidates, 1, "revoked instance still expected in the plan")
	revoked := slot.Candidates[0]
	require.Equal(t, credentialId, revoked.CredentialId)
	require.False(t, revoked.Usable)
	require.Equal(t, clientmodels.UnusableReason_Revoked, revoked.UnusableReason)

	err := c.HandleUserInteraction(clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{Granted: true, Choices: []clientmodels.ChoiceSelection{{
			Option: 0,
			Slots:  []clientmodels.SlotSelection{{SlotId: slot.Id, Credentials: []clientmodels.SelectedCredential{selectWhole(revoked)}}},
		}}},
	})
	require.Error(t, err, "a revoked card cannot be shared")
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Error, session.Status)
	requireNoDisclosureLog(t, c)
}
