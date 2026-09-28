package sessiontest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/privacybydesign/irmago/walletprovider/fake"
	"github.com/stretchr/testify/require"
)

// walletProviderPin is the PIN the test wallet units are activated with.
const walletProviderPin = "12345"

// testSessionHandlerForWalletProvider runs the OpenID4VC flows of a wallet
// whose credentials are bound to wallet provider keys, with the fake provider.
func testSessionHandlerForWalletProvider(t *testing.T) {
	t.Run("sd-jwt vc issued and disclosed with provider keys", testWalletProviderSdJwtIssueAndDisclose)
	t.Run("mdoc issued and disclosed with provider keys", testWalletProviderMdocIssueAndDisclose)
	t.Run("wrong PIN can be retried", testWalletProviderWrongPinRetry)
	t.Run("declining the PIN cancels issuance before any key exists", testWalletProviderPinDeclinedAtIssuance)
	t.Run("blocked PIN ends the disclosure", testWalletProviderPinBlocked)
	t.Run("issuance activates a wallet unit that is not activated yet", testWalletProviderInlineActivation)
}

// createWalletProviderClient creates a wallet whose OpenID4VC credentials are
// bound to keys of the fake wallet provider. With activate, the wallet unit is
// activated up front with walletProviderPin; otherwise it is left for
// issuance to activate.
func createWalletProviderClient(t *testing.T, issuerChain []byte, activate bool) (*client.Client, *fake.Provider, *MockSessionHandler) {
	t.Helper()
	var provider *fake.Provider
	factory := func(host walletprovider.Host) (walletprovider.WalletProvider, error) {
		p, err := fake.New(fake.Options{})(host)
		if err != nil {
			return nil, err
		}
		provider = p.(*fake.Provider)
		return p, nil
	}
	c, _, sessionHandler := instantiateClientWithConfig(t, issuerChain, client.Config{
		Locale:         "en",
		WalletProvider: factory,
	})
	require.NotNil(t, provider)

	if activate {
		require.NoError(t, provider.Activate(context.Background(), walletProviderPin))
	}
	return c, provider, sessionHandler
}

// enterPin answers the PIN prompt the session is showing.
func enterPin(t *testing.T, c *client.Client, sessionId int, pin string) {
	t.Helper()
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: sessionId,
		Type:      clientmodels.UI_EnteredPin,
		Payload:   clientmodels.PinInteractionPayload{Pin: pin, Proceed: true},
	})
}

// issueTestCredentialWithProvider runs the pre-authorized issuance of the test
// SD-JWT VC through the PIN prompt the wallet provider adds.
func issueTestCredentialWithProvider(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionId int) {
	t.Helper()
	offer := createPreAuthOffer(t)
	startOpenID4VCISession(t, c, sessionId, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: sessionId,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	// The PIN comes after the user agreed to the issuance and before any key
	// is minted.
	session = awaitSessionState(t, sessionHandler)
	require.Nil(t, session.Error, "session error: %s", describeSessionError(session.Error))
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPin)
	require.Nil(t, session.RemainingPinAttempts)
	enterPin(t, c, sessionId, walletProviderPin)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	grantPermission(t, c, sessionId)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Success)
	require.Equal(t, "CREDENTIAL_ISSUED", checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID))
}

// startVeramoDisclosure starts a disclosure of the test SD-JWT VC and answers
// the permission request, leaving the session at the PIN prompt.
func startVeramoDisclosure(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionId int) veramoVerifierSession {
	t.Helper()
	veramoSession := createVeramoVerifierDcqlSession(t)
	sessionReq, err := json.Marshal(client.SessionRequestData{
		URL:      veramoSession.RequestUri,
		Protocol: clientmodels.Protocol_OpenID4VP,
	})
	require.NoError(t, err)
	c.NewSession(sessionId, string(sessionReq))

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, sessionId, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPin)
	return veramoSession
}

func testWalletProviderSdJwtIssueAndDisclose(t *testing.T) {
	c, provider, sessionHandler := createWalletProviderClient(t, nil, true)
	defer c.Close()

	issueTestCredentialWithProvider(t, c, sessionHandler, 1)

	// Every key of the batch was minted by the provider, under one unlock
	// scoped to the issuer.
	unlocks := provider.Unlocks()
	require.Len(t, unlocks, 1)
	require.Equal(t, walletprovider.PurposeIssuancePoP, unlocks[0].Purpose)
	require.Equal(t, preAuthIssuerURL, unlocks[0].Counterparty)
	keys, err := provider.KeyCount()
	require.NoError(t, err)
	require.Positive(t, keys)
	require.Equal(t, keys, provider.SignCount(), "one proof of possession per key")

	veramoSession := startVeramoDisclosure(t, c, sessionHandler, 2)
	enterPin(t, c, 2, walletProviderPin)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "test-credential",
		claim([]any{"given_name"}, "Test"),
		claim([]any{"email"}, "test@example.com"),
	)

	// The key binding JWT was signed by the provider, under an unlock that
	// does not name the verifier.
	unlocks = provider.Unlocks()
	require.Len(t, unlocks, 2)
	require.Equal(t, walletprovider.PurposeDisclosureKB, unlocks[1].Purpose)
	require.Empty(t, unlocks[1].Counterparty)
	require.Equal(t, keys+1, provider.SignCount())
}

func testWalletProviderMdocIssueAndDisclose(t *testing.T) {
	c, provider, sessionHandler := createWalletProviderClient(t, readEudiPidIssuerPyCA(t), true)
	defer c.Close()

	// The Python issuer's offer carries a tx_code; the PIN follows the grant.
	status, body := postAvMdocOfferRequest(t, map[string]any{
		"credentials": []map[string]any{
			{"credential_configuration_id": pidMdocConfigId, "data": pidMdocIssuanceData()},
		},
	})
	require.Equal(t, 200, status, body)
	var offerJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &offerJSON))
	txCode := extractTxCodeValue(t, offerJSON)

	startOpenID4VCISession(t, c, 1, offerUriFromJson(t, offerJSON))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: 1,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true, TransactionCode: &txCode},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPin)
	enterPin(t, c, 1, walletProviderPin)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	grantPermission(t, c, 1)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	keys, err := provider.KeyCount()
	require.NoError(t, err)
	require.Greater(t, keys, 1, "a batch of device keys in the provider")

	dcql := `{
		"credentials": [
			{
				"id": "pid",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
				"claims": [
					{ "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
					{ "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
				]
			}
		]
	}`
	testSession, requestJwt := startMdocDcqlSession(t, c, 2, sessionHandler, dcql)
	session = testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	grantFirstOwnedOptions(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPin)
	enterPin(t, c, 2, walletProviderPin)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The DeviceAuth the provider signed verifies against the device key the
	// issuer put in the MSO.
	walletResponse := requireVerifierAccepted(t, testSession.VerifierSession)
	presented := requireSingleDeviceResponse(t, walletResponse, pidMdocQueryId)
	elements := requireMdocPresentationVerifies(t, presented, pidMdocNamespace, pidMdocDocType, avSessionTranscript(t, requestJwt))
	require.Equal(t, samplePidUserData().FamilyName, elements["family_name"])

	unlocks := provider.Unlocks()
	require.Len(t, unlocks, 2)
	require.Equal(t, walletprovider.PurposeDisclosureKB, unlocks[1].Purpose)
}

func testWalletProviderWrongPinRetry(t *testing.T) {
	c, provider, sessionHandler := createWalletProviderClient(t, nil, true)
	defer c.Close()

	issueTestCredentialWithProvider(t, c, sessionHandler, 1)
	veramoSession := startVeramoDisclosure(t, c, sessionHandler, 2)

	enterPin(t, c, 2, "00000")
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPin)
	require.NotNil(t, session.RemainingPinAttempts)
	require.Equal(t, 2, *session.RemainingPinAttempts)

	enterPin(t, c, 2, walletProviderPin)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	require.Len(t, provider.Unlocks(), 2)
}

func testWalletProviderPinDeclinedAtIssuance(t *testing.T) {
	c, provider, sessionHandler := createWalletProviderClient(t, nil, true)
	defer c.Close()

	offer := createPreAuthOffer(t)
	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: 1,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPin)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: 1,
		Type:      clientmodels.UI_EnteredPin,
		Payload:   clientmodels.PinInteractionPayload{Proceed: false},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)

	keys, err := provider.KeyCount()
	require.NoError(t, err)
	require.Zero(t, keys)
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	require.Nil(t, findCredentialByName(t, creds, "Test Credential (SD-JWT)"))
}

func testWalletProviderPinBlocked(t *testing.T) {
	c, _, sessionHandler := createWalletProviderClient(t, nil, true)
	defer c.Close()

	issueTestCredentialWithProvider(t, c, sessionHandler, 1)
	startVeramoDisclosure(t, c, sessionHandler, 2)

	enterPin(t, c, 2, "00000")
	awaitSessionState(t, sessionHandler)
	enterPin(t, c, 2, "00000")
	awaitSessionState(t, sessionHandler)
	enterPin(t, c, 2, "00000")

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPin)
	require.NotNil(t, session.PinBlockedTimeSeconds)
	require.Positive(t, *session.PinBlockedTimeSeconds)
}

func testWalletProviderInlineActivation(t *testing.T) {
	c, provider, sessionHandler := createWalletProviderClient(t, nil, false)
	defer c.Close()

	state, err := provider.State(context.Background())
	require.NoError(t, err)
	require.Equal(t, walletprovider.StateNotActivated, state)

	offer := createPreAuthOffer(t)
	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: 1,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPin)
	enterPin(t, c, 1, walletProviderPin)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	grantPermission(t, c, 1)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	state, err = provider.State(context.Background())
	require.NoError(t, err)
	require.Equal(t, walletprovider.StateActive, state)

	// The wallet unit was activated with the PIN that was entered.
	u, err := provider.Unlock(context.Background(), walletProviderPin, walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB})
	require.NoError(t, err)
	u.Close()
}
