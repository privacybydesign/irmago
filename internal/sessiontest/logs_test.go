package sessiontest

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestLogging(t *testing.T) {
	client, _ := parseStorage(t)

	logs, err := client.LoadLogs(time.Now(), 100)
	oldLogLength := len(logs)
	require.NoError(t, err)
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	var request irma.SessionRequest

	// Do issuance session
	request = getCombinedIssuanceRequest(attrid)
	sessionHelper(t, request, "issue", client)

	logs, err = client.LoadLogs(time.Now(), 100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+1)

	entry := logs[len(logs)-1]
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
	sessionHelper(t, request, "verification", client)
	logs, err = client.LoadLogs(time.Now(), 100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+2)

	entry = logs[len(logs)-1]
	require.NotNil(t, entry)
	require.NoError(t, err)
	disclosed, err = entry.GetDisclosedCredentials(client.Configuration)
	require.NoError(t, err)
	require.NotEmpty(t, disclosed)

	// Do signature session
	request = getSigningRequest(attrid)
	sessionHelper(t, request, "signature", client)
	logs, err = client.LoadLogs(time.Now(), 100)
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+3)
	entry = logs[len(logs)-1]
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

	test.ClearTestStorage(t)
}
