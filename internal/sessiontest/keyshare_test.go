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
	testkeyshare.StartKeyshareServer(t)
	defer testkeyshare.StopKeyshareServer(t)
	request := irma.NewSignatureRequest("I owe you everything", irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"))
	ms := createManualSessionHandler(t, nil)

	_, status := manualSessionHelper(t, nil, ms, request, request, false)
	require.Equal(t, irma.ProofStatusValid, status)
	_, status = manualSessionHelper(t, nil, ms, request, nil, false)
	require.Equal(t, irma.ProofStatusValid, status)
}

func TestRequestorIssuanceKeyshareSession(t *testing.T) {
	testkeyshare.StartKeyshareServer(t)
	defer testkeyshare.StopKeyshareServer(t)
	testRequestorIssuance(t, true, nil)
}

func TestKeyshareRegister(t *testing.T) {
	testkeyshare.StartKeyshareServer(t)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	require.NoError(t, client.KeyshareRemoveAll())
	require.NoError(t, client.RemoveStorage())

	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, <-handler.c)

	require.Len(t, client.CredentialInfoList(), 1)

	StartIrmaServer(t, false, "")
	defer StopIrmaServer()

	requestorSessionHelper(t, getIssuanceRequest(true), client, sessionOptionReuseServer)
	keyshareSessions(t, client)
}

// Use the existing keyshare enrollment and credentials
// in a keyshare session of each session type.
// Use keyshareuser.sql to enroll the user at the keyshare server.
func TestKeyshareSessions(t *testing.T) {
	testkeyshare.StartKeyshareServer(t)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	keyshareSessions(t, client)
}

func keyshareSessions(t *testing.T, client *irmaclient.Client) {
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
	requestorSessionHelper(t, issuanceRequest, client, sessionOptionReuseServer)

	disclosureRequest := getDisclosureRequest(id)
	disclosureRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	requestorSessionHelper(t, disclosureRequest, client, sessionOptionReuseServer)

	sigRequest := getSigningRequest(id)
	sigRequest.AddSingle(irma.NewAttributeTypeIdentifier("test.test.mijnirma.email"), nil, nil)
	requestorSessionHelper(t, sigRequest, client, sessionOptionReuseServer)
}

func TestIssuanceCombinedMultiSchemeSession(t *testing.T) {
	StartIrmaServer(t, false, "")
	defer StopIrmaServer()
	testkeyshare.StartKeyshareServer(t)
	defer testkeyshare.StopKeyshareServer(t)

	id := irma.NewAttributeTypeIdentifier("test.test.mijnirma.email")
	request := getCombinedIssuanceRequest(id)
	requestorSessionHelper(t, request, nil, sessionOptionReuseServer)

	id = irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request = irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes: map[string]string{
				"email": "example@example.com",
			},
		},
	}, id)
	requestorSessionHelper(t, request, nil, sessionOptionReuseServer)
}
