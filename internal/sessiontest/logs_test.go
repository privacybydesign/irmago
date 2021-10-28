package sessiontest

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestLogging(t *testing.T) {
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	logs, err := client.LoadNewestLogs(100)
	oldLogLength := len(logs)
	require.NoError(t, err)
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	var request irma.SessionRequest

	// Do issuance session
	request = getCombinedIssuanceRequest(attrid)
	sessionHelper(t, request, client)

	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+1)

	// Check whether newly issued credential is actually stored
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+1)

	entry := logs[0]
	require.NotNil(t, entry)
	require.NoError(t, err)
	issued, err := entry.GetIssuedCredentials(client.Configuration)
	require.NoError(t, err)
	require.NotNil(t, issued)
	disclosed, err := entry.GetDisclosedCredentials(client.Configuration)
	require.NoError(t, err)
	require.NotEmpty(t, disclosed)

	// Do disclosure session
	request = getDisclosureRequest(attrid)
	sessionHelper(t, request, client)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+2)

	// Check whether log entry for disclosing session is actually stored
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+2)

	entry = logs[0]
	require.NotNil(t, entry)
	require.NoError(t, err)
	disclosed, err = entry.GetDisclosedCredentials(client.Configuration)
	require.NoError(t, err)
	require.NotEmpty(t, disclosed)

	// Test before parameter
	logs, err = client.LoadLogsBefore(entry.ID, 100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+1)
	require.True(t, logs[0].ID < entry.ID)

	// Test max parameter
	logs, err = client.LoadNewestLogs(1)
	require.NoError(t, err)
	require.True(t, len(logs) == 1)

	// Do signature session
	request = getSigningRequest(attrid)
	sessionHelper(t, request, client)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+3)

	// Check whether log entry for signature session is actually stored
	require.NoError(t, client.Close())
	client, handler = parseExistingStorage(t, handler.storage)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+3)

	entry = logs[0]
	require.NotNil(t, entry)
	require.NoError(t, err)
	sig, err := entry.GetSignedMessage()
	require.NoError(t, err)
	require.NotNil(t, sig)
	attrs, status, err := sig.Verify(client.Configuration, nil)
	require.NoError(t, err)
	require.Equal(t, irma.ProofStatusValid, status)
	require.NotEmpty(t, attrs)
	require.Equal(t, attrid, attrs[0][0].Identifier)
}
