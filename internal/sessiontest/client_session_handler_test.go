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
	t.Run("single credential issuance", testSingleCredentialIssuance)
	t.Run("single credential disclosure with available credential", testSingleCredentialDisclosureWithAvailableCredential)
}

func testSingleCredentialDisclosureWithAvailableCredential(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	schemalessPerformIrmaIssuanceSession(
		t,
		c,
		sessionHandler,
		irmaServer,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)

	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}

	schemalessPerformIrmaDisclosureSession(t, c, sessionHandler, irmaServer, disclosureRequest)
}

func testSingleCredentialIssuance(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client, sessionHandler := createClient(t)
	defer client.Close()

	schemalessPerformIrmaIssuanceSession(
		t,
		client,
		sessionHandler,
		irmaServer,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)
}

func schemalessPerformIrmaDisclosureSession(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	irmaServer *IrmaServer,
	request *irma.DisclosureRequest,
) {
	c.DeleteKeyshareTokens()
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingDisclosurePermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
	require.Len(t, session.OfferedCredentials, 0)
	require.NotNil(t, session.DisclosurePlan)

	emailCred := session.DisclosurePlan.DisclosureMakeChoices.Required[0].OwnedOptions[0]

	choice := client.DisclosureDisconSelection{
		Credentials: []client.SelectedCredential{
			{
				CredentialId:   emailCred.CredentialId,
				CredentialHash: emailCred.Hash,
				AttributePaths: [][]any{
					{"email"},
				},
			},
		},
	}

	// give disclosure permission
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(client.SessionUserInteraction{
				SessionID: session.Id,
				Type:      client.UI_Permission,
				Payload: client.SessionPermissionInteractionPayload{
					Granted:           true,
					DisclosureChoices: []client.DisclosureDisconSelection{choice},
				},
			}),
		)
	}()

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPin)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)

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
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
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
				Payload: client.SessionPermissionInteractionPayload{
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
