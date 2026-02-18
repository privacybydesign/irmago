package sessiontest

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"

	// "github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestClientHandler(t *testing.T) {
	t.Run("disclosure using new session handler interface", testDisclosureWithNewHandlerInterface)

}

func testDisclosureWithNewHandlerInterface(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client, sessionHandler := createClient(t)
	defer client.Close()

	schemalessPerformIrmaIssuanceSession(t, client, sessionHandler, irmaServer, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	// discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPost_Host)
	// discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPostJwt_Host)
}

func schemalessPerformIrmaIssuanceSession(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	irmaServer *IrmaServer,
	request *irma.IssuanceRequest,
) {
	// delete keyshare session token so the pin is required
	c.DeleteKeyshareTokens()
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingIssuancePermission)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)
	require.Len(t, session.OfferedCredentials, 1)

	// give issuance permission
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(client.SessionUserInteraction{
				SessionID: session.Id,
				Type:      client.UI_Permission,
				Payload: client.IssuancePermissionInteractionPayload{
					Granted: true,
				},
			}),
		)
	}()

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPin)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)

	// give pin
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(client.SessionUserInteraction{
				SessionID: session.Id,
				Type:      client.UI_EnteredPin,
				Payload: client.PinInteractionPayload{
					Pin:     "12345",
					Proceed: true,
				},
			}),
		)
	}()

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_Success)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)
}

func awaitWithTimeout[T any](t *testing.T, channel chan T, timeout time.Duration) T {
	select {
	case msg := <-channel:
		return msg
	case <-time.After(timeout):
		require.Fail(t, "failed to await after %s", timeout)
	}
	// unreachable in theory
	var ret T
	return ret
}
