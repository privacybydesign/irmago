package irmaclient

import (
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/stretchr/testify/require"
)

// Test pinchange interaction
func TestKeyshareChangePin(t *testing.T) {
	testkeyshare.StartKeyshareServer(t, irma.Logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, client, handler.storage)

	require.NoError(t, client.keyshareChangePinWorker(irma.NewSchemeManagerIdentifier("test"), "12345", "54321"))
	require.NoError(t, client.keyshareChangePinWorker(irma.NewSchemeManagerIdentifier("test"), "54321", "12345"))
}
