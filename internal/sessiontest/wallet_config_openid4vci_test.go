package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/stretchr/testify/require"
)

// The trust system on the issuance side, against the veramo OpenID4VCI test
// issuer from docker-compose.yml. That issuer signs with a did:web, so it climbs
// the ladder through a did handle in the wallet config and nothing else: an
// unlisted run is what a stranger issuing to the wallet looks like.
//
// These need the Docker services; the in-process half of the trust system's
// integration tests is in wallet_config_trust_test.go.

// veramoIssuerDID is the DID the veramo OpenID4VCI test issuer signs with, and
// so what a config must list to vouch for it.
const veramoIssuerDID = "did:web:localhost%3A8443:test-issuer:.well-known"

func TestWalletConfigTrustOverOpenID4VCI(t *testing.T) {
	t.Run("an unlisted issuer ranks low and still issues", testOpenID4VCIUnlistedIssuerRanksLow)
	t.Run("an issuer listed by DID ranks high on the offer and in the wallet", testOpenID4VCIListedIssuerRanksHigh)
	t.Run("the policy refuses an issuer below the minimum", testOpenID4VCIPolicyRefusesIssuerBelowMinimum)
	t.Run("a listed issuance constraint refuses other credential types", testOpenID4VCIIssuanceConstraintRefusesOtherTypes)
}

// runPreAuthIssuanceToPermission starts the pre-authorized code flow at the veramo
// issuer and drives it to the permission prompt, returning that state.
func runPreAuthIssuanceToPermission(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionID int) clientmodels.SessionState {
	t.Helper()
	offer := createPreAuthOffer(t)
	startOpenID4VCISession(t, c, sessionID, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionID, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})
	return awaitSessionState(t, sessionHandler)
}

func testOpenID4VCIUnlistedIssuerRanksLow(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	staging.publish(nil)
	refreshConfig(t, c)

	session := runPreAuthIssuanceToPermission(t, c, sessionHandler, 1)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel, "a DID nobody vouches for")
	require.Equal(t, clientmodels.TrustLevel_Low, session.OfferedCredentials[0].Issuer.TrustLevel)

	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	credentials, _, err := c.GetCredentials()
	require.NoError(t, err)
	stored := findCredentialByName(t, credentials, "Test Credential (SD-JWT)")
	require.NotNil(t, stored)
	require.Equal(t, veramoIssuerDID, stored.Issuer.Id)
	require.Equal(t, clientmodels.TrustLevel_Low, stored.Issuer.TrustLevel)
	require.False(t, stored.IssuerNotTrusted, "the default policy admits low")
}

func testOpenID4VCIListedIssuerRanksHigh(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{
			didEntity("veramo", "Curated Issuer BV", walletconfig.RoleIssuer, clientmodels.TrustLevel_High, veramoIssuerDID),
		}
	})
	refreshConfig(t, c)

	session := runPreAuthIssuanceToPermission(t, c, sessionHandler, 1)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel, "ranked once the credentials reveal what signed them")
	require.Equal(t, "Curated Issuer BV", session.Requestor.Name, "the curated name outranks the issuer's metadata")
	require.Equal(t, clientmodels.TrustLevel_High, session.OfferedCredentials[0].Issuer.TrustLevel)

	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	credentials, _, err := c.GetCredentials()
	require.NoError(t, err)
	stored := findCredentialByName(t, credentials, "Test Credential (SD-JWT)")
	require.NotNil(t, stored)
	require.Equal(t, clientmodels.TrustLevel_High, stored.Issuer.TrustLevel, "the stored credential is ranked from its DID")

	// Delisting the issuer demotes the stored credential without touching it.
	staging.publish(nil)
	refreshConfig(t, c)
	credentials, _, err = c.GetCredentials()
	require.NoError(t, err)
	require.Equal(t, clientmodels.TrustLevel_Low, findCredentialByName(t, credentials, "Test Credential (SD-JWT)").Issuer.TrustLevel)
}

func testOpenID4VCIPolicyRefusesIssuerBelowMinimum(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	staging.publish(func(config *walletconfig.Config) {
		config.Policy.MinimumTrustLevel.Issuance = clientmodels.TrustLevel_Medium
	})
	refreshConfig(t, c)

	session := runPreAuthIssuanceToPermission(t, c, sessionHandler, 1)
	require.Equal(t, clientmodels.Status_Error, session.Status, "session error: %s", describeSessionError(session.Error))
	require.NotNil(t, session.Error)
	require.Equal(t, clientmodels.ErrorType_TrustLevelBelowMinimum, session.Error.ErrorType)

	credentials, _, err := c.GetCredentials()
	require.NoError(t, err)
	require.Nil(t, findCredentialByName(t, credentials, "Test Credential (SD-JWT)"), "nothing was stored")
}

func testOpenID4VCIIssuanceConstraintRefusesOtherTypes(t *testing.T) {
	staging := newConfigPublisher(t, walletconfig.EnvironmentStaging)
	c, _, sessionHandler := trustTestClient(t, staging, nil, testClientOptions{})
	defer c.Close()
	listing := didEntity("veramo", "Curated Issuer BV", walletconfig.RoleIssuer, clientmodels.TrustLevel_High, veramoIssuerDID)
	listing.Constraints = &walletconfig.Constraints{Issuance: &walletconfig.IssuanceConstraint{
		AllowedCredentials: []string{"urn:yivi:test:something-else"},
	}}
	staging.publish(func(config *walletconfig.Config) {
		config.TrustedEntities = []walletconfig.TrustedEntity{listing}
	})
	refreshConfig(t, c)

	session := runPreAuthIssuanceToPermission(t, c, sessionHandler, 1)
	require.Equal(t, clientmodels.Status_Error, session.Status, "session error: %s", describeSessionError(session.Error))
	require.NotNil(t, session.Error)
	require.Equal(t, clientmodels.ErrorType_PartyValidationFailed, session.Error.ErrorType)
	require.Contains(t, session.Error.WrappedError, "not listed as allowed to issue")
}
