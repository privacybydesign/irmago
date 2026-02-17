package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
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

	performIrmaIssuanceSession(t, client, irmaServer, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPost_Host)
	discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPostJwt_Host)
}

func schemalessPerformIrmaIssuanceSession(t *testing.T, client *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer, request *irma.IssuanceRequest) {
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	client.NewSession(sessionRequestJson, sessionHandler)
	details := sessionHandler.AwaitPermissionRequest()
	details.PermissionHandler(true, nil)

	require.True(t, sessionHandler.AwaitSessionEnd())
}
