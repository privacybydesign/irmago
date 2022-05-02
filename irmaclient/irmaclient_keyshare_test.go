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
	testkeyshare.StartKeyshareServer(t, irma.Logger)
	defer testkeyshare.StopKeyshareServer(t)
	client, handler := parseStorage(t)
	defer test.ClearTestStorage(t, handler.storage)

	client.KeyshareChangePin("12345", "54321")
	require.NoError(t, <-handler.c)
	client.KeyshareChangePin("54321", "12345")
	require.NoError(t, <-handler.c)
}
