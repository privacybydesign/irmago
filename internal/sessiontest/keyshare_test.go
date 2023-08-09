package sessiontest

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/stretchr/testify/require"
)

func TestManualKeyshareSession(t *testing.T) {
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServer.Stop()
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"))
	ms := createManualSessionHandler(t, nil)

	_, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	_, status = manualSessionHelper(t, nil, ms, request, nil, false)
	require.Equal(t, irma.ProofStatusValid, status)
}

func TestIssuanceKeyshareSession(t *testing.T) {
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServer.Stop()
	doIssuanceSession(t, true, nil, nil)
}

func TestKeyshareRegister(t *testing.T) {
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServer.Stop()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	require.NoError(t, client.KeyshareRemoveAll())
	require.NoError(t, client.RemoveStorage())

	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, <-handler.c)

	require.Len(t, client.CredentialInfoList(), 1)

	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()

	doSession(t, getIssuanceRequest(true), client, irmaServer, nil, nil, nil)
	keyshareSessions(t, client, irmaServer)
}

// Use the existing keyshare enrollment and credentials
// in a keyshare session of each session type.
func TestKeyshareSessions(t *testing.T) {
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServer.Stop()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	keyshareSessions(t, client, irmaServer)
}

func keyshareSessions(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	expiry := irma.Timestamp(irma.NewMetadataAttribute(0).Expiry())
	issuanceRequest := getCombinedIssuanceRequest(id)
	issuanceRequest.Credentials = append(issuanceRequest.Credentials,
		&irma.CredentialRequest{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes:       map[string]string{"email": "testusername"},
		},
	)
	doSession(t, issuanceRequest, client, irmaServer, nil, nil, nil)

	disclosureRequest := getDisclosureRequest(id)
	disclosureRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	doSession(t, disclosureRequest, client, irmaServer, nil, nil, nil)

	sigRequest := getSigningRequest(id)
	sigRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	doSession(t, sigRequest, client, irmaServer, nil, nil, nil)
}

func TestIssuanceCombinedMultiSchemeSession(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServer.Stop()

	id := irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")
	request := getCombinedIssuanceRequest(id)
	doSession(t, request, nil, irmaServer, nil, nil, nil)

	id = irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request = irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes: map[string]string{
				"email": "example@example.com",
			},
		},
	}, id)
	doSession(t, request, nil, irmaServer, nil, nil, nil)
}

func TestMultipleKeyshareServers(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	keyshareServerTest := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServerTest.Stop()
	keyshareServerTest2 := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test2"))
	defer keyshareServerTest2.Stop()

	client, handler := parseStorage(t, optionNoSchemeAssets)
	defer test.ClearTestStorage(t, client, handler.storage)

	logs, err := client.LoadNewestLogs(20)
	require.NoError(t, err)
	logsAmount := len(logs)

	test2SchemeID := irma.NewSchemeManagerIdentifier("test2")
	client.KeyshareEnroll(test2SchemeID, nil, "12345", "en")
	require.NoError(t, <-handler.c)

	// A session request that contains attributes from both test and test2 (both distributed schemes) should fail.
	request := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
		irma.NewAttributeTypeIdentifier("test2.test.mijnirma.email"),
	)
	_, _, _, err = irmaServer.irma.StartSession(request, nil)
	require.ErrorIs(t, err, irma.ErrMultipleDistributedSchemes)

	// Do a session with a request that contains attributes from test2 only.
	request = irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("test2.test.mijnirma.email"),
	)
	doSession(t, request, client, irmaServer, nil, nil, nil)
	logs, err = client.LoadNewestLogs(20)
	require.NoError(t, err)
	require.Len(t, logs, logsAmount+2)

	err = client.RemoveScheme(test2SchemeID)
	require.NoError(t, err)
	require.NotContains(t, client.Configuration.SchemeManagers, test2SchemeID)

	// Check whether all credentials and log entries being related to test2 are removed.
	logs, err = client.LoadNewestLogs(20)
	require.NoError(t, err)
	require.Len(t, logs, logsAmount)
	creds := client.CredentialInfoList()
	for _, cred := range creds {
		require.NotEqual(t, cred.SchemeManagerID, "test2")
	}
}

func TestKeyshareEnrollIncorrectPin(t *testing.T) {
	irmaServer := StartIrmaServer(t, nil)
	defer irmaServer.Stop()
	keyshareServerTest := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServerTest.Stop()
	keyshareServerTest2 := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test2"))
	defer keyshareServerTest2.Stop()

	client, handler := parseStorage(t, optionNoSchemeAssets)
	defer test.ClearTestStorage(t, client, handler.storage)

	test2SchemeID := irma.NewSchemeManagerIdentifier("test2")
	client.KeyshareEnroll(test2SchemeID, nil, "54321", "en")
	require.ErrorContains(t, <-handler.c, "incorrect pin")
	require.NotContains(t, client.EnrolledSchemeManagers(), test2SchemeID)
}

func TestKeyshareChainedSessions(t *testing.T) {
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"))
	defer keyshareServer.Stop()

	t.Run("BothKeyshare", func(t *testing.T) {
		doChainedSessions(t, IrmaServerConfiguration,
			irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
			irma.NewCredentialTypeIdentifier("test.test2.email"),
		)
	})
	t.Run("WithWithoutKeyshare", func(t *testing.T) {
		doChainedSessions(t, IrmaServerConfiguration,
			irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"),
			irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		)
	})
	t.Run("WithoutWith", func(t *testing.T) {
		doChainedSessions(t, IrmaServerConfiguration,
			irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"),
			irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
		)
	})
}
