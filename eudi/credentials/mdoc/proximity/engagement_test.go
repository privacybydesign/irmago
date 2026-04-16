package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDeviceEngagementAgainstAnnexDVector is transpiled from multipaz:
//
//	multipaz/src/commonTest/kotlin/org/multipaz/mdoc/engagement/DeviceEngagementTest.kt
//	  -> testAgainstVector2021()
//
// It parses the exact DeviceEngagement CBOR the ISO 18013-5 Annex D example
// puts in a QR code and asserts every field.
func TestParseDeviceEngagementAgainstAnnexDVector(t *testing.T) {
	data, err := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_ENGAGEMENT)
	require.NoError(t, err)

	eng, err := ParseDeviceEngagement(data)
	require.NoError(t, err)

	assert.Equal(t, "1.0", eng.Version)

	// eDeviceKey: P-256 with specific X/Y from Annex D.
	require.NotNil(t, eng.EDeviceKey)
	expectedX, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_EPHEMERAL_DEVICE_KEY_X)
	expectedY, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_EPHEMERAL_DEVICE_KEY_Y)
	assert.Equal(t, expectedX, padLeft(eng.EDeviceKey.X.Bytes(), 32))
	assert.Equal(t, expectedY, padLeft(eng.EDeviceKey.Y.Bytes(), 32))

	// The raw #6.24-wrapped key bytes must round-trip unchanged into the
	// SessionTranscript.
	expectedBytes, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_E_DEVICE_KEY_BYTES)
	assert.Equal(t, expectedBytes, eng.EDeviceKeyBytes)

	// Exactly one BLE connection method: central-client-mode with a specific UUID.
	require.Len(t, eng.ConnectionMethods, 1)
	ble, ok := eng.ConnectionMethods[0].(BLEConnectionMethod)
	require.True(t, ok, "expected BLEConnectionMethod, got %T", eng.ConnectionMethods[0])
	assert.False(t, ble.SupportsPeripheralServerMode)
	assert.True(t, ble.SupportsCentralClientMode)
	assert.Nil(t, ble.PeripheralServerModeUUID)
	require.NotNil(t, ble.CentralClientModeUUID)
	assert.Equal(t, "45efef74-2b2c-4837-a9a3-b0e1d05a6917",
		ble.CentralClientModeUUID.String())
}

// TestEncodeDeviceEngagementRoundTrip builds a fresh DeviceEngagement with a
// random BLE UUID and verifies it round-trips through encode→parse unchanged.
// Mirrors multipaz's testDeviceEngagementQrBleCentralClientMode.
func TestEncodeDeviceEngagementRoundTrip(t *testing.T) {
	eKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	u := uuid.New()

	original := &DeviceEngagement{
		Version:    "1.0",
		EDeviceKey: &eKey.PublicKey,
		ConnectionMethods: []ConnectionMethod{
			BLEConnectionMethod{
				SupportsPeripheralServerMode: false,
				SupportsCentralClientMode:    true,
				CentralClientModeUUID:        &u,
			},
		},
	}

	encoded, err := EncodeDeviceEngagement(original)
	require.NoError(t, err)

	parsed, err := ParseDeviceEngagement(encoded)
	require.NoError(t, err)

	assert.Equal(t, "1.0", parsed.Version)
	assert.Equal(t, eKey.PublicKey.X.Cmp(parsed.EDeviceKey.X), 0)
	assert.Equal(t, eKey.PublicKey.Y.Cmp(parsed.EDeviceKey.Y), 0)
	require.Len(t, parsed.ConnectionMethods, 1)
	ble, ok := parsed.ConnectionMethods[0].(BLEConnectionMethod)
	require.True(t, ok)
	assert.Equal(t, u, *ble.CentralClientModeUUID)
}

// Silence unused warnings for helper big.Int import if the tests evolve.
var _ = big.NewInt
