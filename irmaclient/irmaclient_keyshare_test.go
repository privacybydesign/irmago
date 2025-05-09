package irmaclient

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
)

// Test pinchange interaction
func TestKeyshareChangePin(t *testing.T) {
	testSchemeID := irma.NewSchemeManagerIdentifier("test")
	test2SchemeID := irma.NewSchemeManagerIdentifier("test2")

	ks1 := testkeyshare.StartKeyshareServer(t, irma.Logger, testSchemeID, 0)
	defer ks1.Stop()
	ks2 := testkeyshare.StartKeyshareServer(t, irma.Logger, test2SchemeID, 0)
	defer ks2.Stop()

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	client.KeyshareEnroll(test2SchemeID, nil, "12345", "en")
	require.NoError(t, <-handler.c)

	client.KeyshareChangePin("12345", "54321")
	require.NoError(t, <-handler.c)

	// Test whether the authorization token is still valid after changing the PIN.
	transport := irma.NewHTTPTransport(fmt.Sprintf("http://%s", ks1.Addr), false)
	transport.SetHeader("X-IRMA-Keyshare-Username", client.keyshareServers[testSchemeID].Username)
	transport.SetHeader("Authorization", client.keyshareServers[testSchemeID].token)
	reqBody := []string{"test.test-0"}
	comms := &irma.ProofPCommitmentMap{}
	err := transport.Post("prove/getCommitments", comms, reqBody)
	require.NoError(t, err)

	client.KeyshareChangePin("54321", "12345")
	require.NoError(t, <-handler.c)
}

func TestKeyshareChangePinFailed(t *testing.T) {
	ks1 := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test"), 0)
	ks1Stopped := false
	defer func() {
		if !ks1Stopped {
			ks1.Stop()
		}
	}()
	ks2 := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test2"), 0)
	defer ks2.Stop()

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test2"), nil, "12345", "en")
	require.NoError(t, <-handler.c)

	ks1Stopped = true
	ks1.Stop()

	client.KeyshareChangePin("12345", "54321")
	require.Error(t, <-handler.c)
	for _, kss := range client.keyshareServers {
		require.False(t, kss.PinOutOfSync)
	}

	success, _, _, err := client.KeyshareVerifyPin("12345", irma.NewSchemeManagerIdentifier("test2"))
	require.NoError(t, err)
	require.True(t, success)
}

func TestKeyshareChallengeResponseUpgrade(t *testing.T) {
	ks := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer ks.Stop()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	kss := client.keyshareServers[irma.NewSchemeManagerIdentifier("test")]

	// legacyuser is a copy of our user account at the keyshare server,
	// but witout a public key registered to it
	kss.Username = "legacyuser"
	// Convince ourselves that we still need to register our public key at the keyshare server
	kss.ChallengeResponse = false

	// Checking a PIN triggers the public key registration mechanism.
	// Just as in normal authentication, we are allowed attempts with a wrong PIN.
	verifyWrongPin(t, client)

	// Actually trigger the public key registration mechanism using the correct PIN
	verifyPin(t, client)
	require.NotEmpty(t, kss.token)

	// challenge-response is now enforced for this account
	checkChallengeResponseEnforced(t, kss)

	// check PIN again using challenge-response
	kss.token = "" // clear auth token we got from upgrading to challenge-response
	verifyPin(t, client)
}

func TestKeyshareAuthentication(t *testing.T) {
	ks := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer ks.Stop()
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	kss := client.keyshareServers[irma.NewSchemeManagerIdentifier("test")]

	// This client has a public key registered at the keyshare server
	require.True(t, kss.ChallengeResponse)
	checkChallengeResponseEnforced(t, kss)

	verifyPin(t, client)
}

// checkChallengeResponseEnforced manually sends a PIN auth message without challenge-response
// to check that the server enforces challenge-response for this account.
func checkChallengeResponseEnforced(t *testing.T, kss *keyshareServer) {
	msg := irma.KeyshareAuthResponseData{Username: kss.Username, Pin: kss.HashedPin("12345")}
	err := irma.NewHTTPTransport("http://localhost:8080", false).Post("users/verify/pin", nil, msg)
	require.IsType(t, &irma.SessionError{}, err)
	sessErr := err.(*irma.SessionError)
	require.NotNil(t, sessErr)
	require.NotNil(t, sessErr.RemoteError)
	require.Equal(t, keysharecore.ErrChallengeResponseRequired.Error(), sessErr.RemoteError.Message)
}

func verifyPin(t *testing.T, client *IrmaClient) {
	succeeded, tries, blocked, err := client.KeyshareVerifyPin("12345", irma.NewSchemeManagerIdentifier("test"))
	require.NoError(t, err)
	require.True(t, succeeded)
	require.Zero(t, blocked)
	require.Equal(t, tries, 0)
}

func verifyWrongPin(t *testing.T, client *IrmaClient) {
	succeeded, tries, blocked, err := client.KeyshareVerifyPin("00000", irma.NewSchemeManagerIdentifier("test"))
	require.NoError(t, err)
	require.False(t, succeeded)
	require.Zero(t, blocked)
	require.Equal(t, 1, tries)
}
