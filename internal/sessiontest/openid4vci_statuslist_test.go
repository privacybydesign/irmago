package sessiontest

// End-to-end Token Status List (draft-ietf-oauth-status-list-15) tests over
// OpenID4VCI. These require the full docker-compose stack including the
// statuslist_agent service and veramo bumped to v1.5.5.
//
// What they exercise:
//   - issuance-time holder check: the wallet fetches + verifies the
//     statuslist+jwt the agent serves (signed by its did:web, sub == uri) and
//     accepts the credential because the freshly-allocated bit reads VALID;
//   - RefreshStatuses: the background sweep re-fetches for the stored instance;
//   - disclosure-time revocation surfacing: after the issuer revokes the
//     credential, a subsequent OpenID4VP disclosure still offers it in the
//     plan, now carrying Revoked=true (IRMA parity — the frontend decides, the
//     wallet does not fail closed).
//
// At disclosure the plan's Revoked flag comes from a live (cache-aware) Token
// Status List check on the instance to be disclosed: the checker serves the
// cached status list token while it is within its own ttl and re-fetches once
// expired. If neither an in-ttl cached value nor a fresh fetch is available the
// instance is treated as revoked (fail-safe). The wallet does not error the
// session: it surfaces Revoked for the frontend, with the verifier as backstop.

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

func testOpenID4VPStatusListRevokedSurfacedInPlan(t *testing.T) {
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

	// The wallet cached the (valid) status list token at issuance. RefreshStatuses
	// bypasses that cache, re-fetches the now-revoked list, and updates the shared
	// cache. The disclosure plan's live (cache-aware) status check then reads the
	// refreshed (revoked) list; without this refresh it would hit the still-valid
	// cached token.
	require.NoError(t, c.RefreshStatuses(context.Background()))

	// Start an OpenID4VP disclosure that requests the status-list credential by
	// its vct.
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

	// IRMA parity: the wallet does not refuse a revoked credential outright. It
	// offers it in the plan with Revoked=true so the frontend can decide what to
	// do; the verifier's own status check is the backstop.
	require.NotEmpty(t, session.DisclosurePlan.DisclosureChoicesOverview, "expected a disclosure choice")
	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.NotEmpty(t, owned, "revoked instance still expected in the plan")
	require.NotEmpty(t, owned[0].Credentials, "bundle must hold the credential instance")
	require.True(t, owned[0].Credentials[0].Revoked,
		"revoked instance must be surfaced to the frontend with Revoked=true")
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
