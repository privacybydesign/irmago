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
	testkeyshare.StartKeyshareServer(t, logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"))
	ms := createManualSessionHandler(t, nil)

	_, status := manualSessionHelper(t, client, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	_, status = manualSessionHelper(t, client, ms, request, nil, false)
	require.Equal(t, irma.ProofStatusValid, status)
}

func TestIssuanceKeyshareSession(t *testing.T) {
	testkeyshare.StartKeyshareServer(t, logger)
	defer testkeyshare.StopKeyshareServer(t)
	doIssuanceSession(t, true, nil, nil)
}

func TestKeyshareRegister(t *testing.T) {
	testkeyshare.StartKeyshareServer(t, logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

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
	testkeyshare.StartKeyshareServer(t, logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
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
	testkeyshare.StartKeyshareServer(t, logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	id := irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")
	request := getCombinedIssuanceRequest(id)
	doSession(t, request, client, irmaServer, nil, nil, nil)

	id = irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request = irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes: map[string]string{
				"email": "example@example.com",
			},
		},
	}, id)
	doSession(t, request, client, irmaServer, nil, nil, nil)
}
