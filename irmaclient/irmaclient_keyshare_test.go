package irmaclient

import (
	"github.com/stretchr/testify/require"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
)

// Test pinchange interaction
func TestKeyshareChangePin(t *testing.T) {
	ks1 := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test"))
	defer ks1.Stop()
	ks2 := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test2"))
	defer ks2.Stop()

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()
	schemeURL := "http://localhost:48681/irma_configuration_keyshare/test2"
	err := client.Configuration.DangerousTOFUInstallScheme(schemeURL)
	require.NoError(t, err)

	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test2"), nil, "12345", "en")
	require.NoError(t, <-handler.c)

	client.KeyshareChangePin("12345", "54321")
	require.NoError(t, <-handler.c)
	client.KeyshareChangePin("54321", "12345")
	require.NoError(t, <-handler.c)
}

func TestKeyshareChangePinFailed(t *testing.T) {
	ks1 := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test"))
	ks1Stopped := false
	defer func() {
		if !ks1Stopped {
			ks1.Stop()
		}
	}()
	ks2 := testkeyshare.StartKeyshareServer(t, irma.Logger, irma.NewSchemeManagerIdentifier("test2"))
	defer ks2.Stop()

	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()
	schemeURL := "http://localhost:48681/irma_configuration_keyshare/test2"
	err := client.Configuration.DangerousTOFUInstallScheme(schemeURL)
	require.NoError(t, err)

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
