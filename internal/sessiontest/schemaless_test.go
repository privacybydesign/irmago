package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

func TestSchemaless(t *testing.T) {
	t.Run("get credentials idemix only", testSchemaless)
}

func testSchemaless(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client, sessionHandler := createClient(t)
	defer client.Close()

	issue(t, irmaServer, client, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)

	creds, err := client.GetCredentials()
	require.NoError(t, err)

	require.Len(t, creds, 2)
}
