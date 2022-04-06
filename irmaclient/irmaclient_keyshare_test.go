package irmaclient

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/stretchr/testify/require"
)

// Test pinchange interaction
func TestKeyshareChangePin(t *testing.T) {
	testkeyshare.StartKeyshareServer(t, irma.Logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	require.NoError(t, client.keyshareChangePinWorker(irma.NewSchemeManagerIdentifier("test"), "12345", "54321"))
	require.NoError(t, client.keyshareChangePinWorker(irma.NewSchemeManagerIdentifier("test"), "54321", "12345"))
}

func TestKeyshareChallengeResponseUpgrade(t *testing.T) {
	testkeyshare.StartKeyshareServer(t, irma.Logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	kss := client.keyshareServers[irma.NewSchemeManagerIdentifier("test")]

	// legacyuser is a copy of our user account at the keyshare server,
	// but witout a public key registered to it
	kss.Username = "legacyuser"
	// Convince ourselves that we still need to register our public key at the keyshare server
	kss.ChallengeResponse = false

	// Checking the PIN triggers the public key registration mechanism
	succeeded, _, _, err := client.KeyshareVerifyPin("12345", irma.NewSchemeManagerIdentifier("test"))
	require.True(t, succeeded)
	require.NoError(t, err)

	// Manually send a PIN auth message without challenge-response to check that the server
	// now enforces challenge-response for this account
	msg := irma.KeyshareAuthResponse{Username: kss.Username, Pin: kss.HashedPin("12345")}
	err = irma.NewHTTPTransport("http://localhost:8080", false).Post("users/verify/pin", nil, msg)
	require.IsType(t, &irma.SessionError{}, err)
	sessErr := err.(*irma.SessionError)
	require.NotNil(t, sessErr.RemoteError)
	require.Equal(t, keysharecore.ErrChallengeResponseRequired.Error(), sessErr.RemoteError.Message)
}
