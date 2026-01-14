package sessiontest

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
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

	client := createClient(t)
	defer client.Close()

	performIrmaIssuanceSession(t, client, irmaServer, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	creds, err := client.GetCredentials()
	require.NoError(t, err)

	require.Len(t, creds, 2)
}
