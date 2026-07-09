package sessiontest

// !!! UNVERIFIED SCAFFOLDING — never executed against a running stack. !!!
//
// End-to-end Token Status List (draft-ietf-oauth-status-list-15) tests over
// OpenID4VCI. These require the full docker-compose stack including the
// statuslist_agent service and veramo bumped to v1.5.5. See
// testdata/statuslist-agent/README.md for the runtime unknowns that must be
// validated before these can be expected to pass.
//
// What they exercise:
//   - issuance-time holder check: the wallet fetches + verifies the
//     statuslist+jwt the agent serves (signed by its did:web, sub == uri) and
//     accepts the credential because the freshly-allocated bit reads VALID;
//   - RefreshStatuses: the background sweep re-fetches for the stored instance;
//   - disclosure-time fail-closed: after the issuer revokes the credential,
//     a subsequent OpenID4VP disclosure is refused.
//
// NOTE: the wallet does not currently surface LastKnownStatus via
// GetCredentials().Revoked (credential_service.go hardcodes Revoked:false,
// "revocation not yet implemented"), so the revocation effect is asserted via
// disclosure refusal rather than via the credential model.

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
	t.Run("revoked credential is refused at disclosure", testOpenID4VPStatusListRevokedRefusesDisclosure)
}

const statusListCredentialEmail = "statuslist@example.com"

// createStatusListPreAuthOffer creates a pre-authorized offer for the
// StatusListCredentialSdJwt — the only credential whose issuer config wires a
// `statusLists` entry, so issuance reserves an index on the statuslist_agent
// and embeds status.status_list{idx,uri}.
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
// the agent's statuslist+jwt and read VALID at the allocated index).
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
		t.Fatalf("status-list issuance errored before permission (check `docker compose logs veramo_openid4vci statuslist_agent`): %+v", session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error {
		t.Fatalf("status-list issuance errored after permission grant (the holder-side status check fetches the statuslist+jwt from the agent — check `docker compose logs statuslist_agent`): %+v", session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

func testOpenID4VCIStatusListIssuanceAcceptsValid(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueStatusListCredential(t, c, sessionHandler, 1)

	// The credential is present in the wallet.
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	cred := findCredentialByName(t, creds, "en", "Status List Credential (SD-JWT)")
	require.NotNil(t, cred, "issued status-list credential should appear in GetCredentials")

	// The background refresh sweep runs against the real agent for the stored
	// instance and completes without error (a per-URI fetch failure would be
	// logged-and-swallowed, but a transport/setup error surfaces here).
	require.NoError(t, c.RefreshStatuses(context.Background()))
}

func testOpenID4VPStatusListRevokedRefusesDisclosure(t *testing.T) {
	// Requires an IETF-compliant status source. The upstream eduwallet
	// statuslist-agent packs bits MSB-first (W3C @digitalcredentials/bitstring),
	// which the IETF wallet (LSB-first, draft §4.1) reads at the wrong position,
	// so a revoked credential reads as VALID. docker-compose therefore builds
	// the status agent from privacybydesign/statuslist-agent, a fork that emits
	// LSB-first bit arrays for application/statuslist+jwt.
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue, then revoke at the issuer (which proxies the revoke to the
	// statuslist_agent, flipping the credential's bit).
	issueStatusListCredential(t, c, sessionHandler, 1)
	revokeStatusListCredentialViaVeramo(t, statusListCredentialEmail)

	// The wallet cached the (valid) status list token at issuance, so it must
	// re-fetch before it can observe the revocation. This simulates the
	// background refresh sweep learning of the revocation; without it the
	// disclosure-time check would read the stale-but-fresh cached token.
	require.NoError(t, c.RefreshStatuses(context.Background()))

	// Start an OpenID4VP disclosure that requests the status-list credential by
	// its vct. FindCandidates does not consult status (checkInstanceStatus runs
	// in PrepareDisclosure, after permission is granted), so the revoked
	// credential still appears as an owned option in the plan.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "statuslist-cred",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["https://localhost:8443/vct/statuslist"] },
					"claims": [ { "path": ["email"] } ]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The revoked instance still appears in the plan (status is checked on
	// grant, not during planning). Granting must then fail closed: the session
	// must NOT reach Success.
	require.NotEmpty(t, session.DisclosurePlan.DisclosureChoicesOverview, "expected a disclosure choice")
	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.NotEmpty(t, owned, "revoked instance still expected in the plan (status checked on grant, not plan)")
	grantPermission(t, c, session.Id, makeDisclosureChoice(owned[0]))

	session = awaitSessionState(t, sessionHandler)
	require.NotEqual(t, clientmodels.Status_Success, session.Status,
		"disclosure of a revoked credential must be refused (fail-closed status check)")
}

// revokeStatusListCredentialViaVeramo revokes every issued status-list
// credential bearing the given email, via the veramo issuer admin API. veramo
// proxies each revoke to the statuslist_agent, flipping that credential's bit.
//
// StatusListCredentialSdJwt is issued as a batch (multiple instances, each with
// its own status index), and the same email is reused across test runs, so we
// revoke *all* matching records — that guarantees whichever instance the wallet
// discloses has been revoked.
func revokeStatusListCredentialViaVeramo(t *testing.T, email string) {
	t.Helper()

	// 1) List the issued status-list credentials (POST, admin-authenticated).
	//    The claims are returned as a JSON string, so we match the email there.
	listBody := `{"credential":"StatusListCredentialSdJwt"}`
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

	// 2) Revoke every record whose claims contain our email. veramo proxies
	//    each revoke to the statuslist_agent, which sets the bit.
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
