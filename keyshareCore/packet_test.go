package keyshareCore

import (
	"crypto/rand"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketAccess(t *testing.T) {
	var testSecret = big.NewInt(51232)
	var testPassword [64]byte
	_, err := rand.Read(testPassword[:])
	require.NoError(t, err)

	var p unencryptedKeysharePacket
	p.setPin(testPassword)
	p.setKeyshareSecret(testSecret)
	assert.Equal(t, testPassword, p.getPin(), "password doesn't match")
	assert.Equal(t, 0, p.getKeyshareSecret().Cmp(testSecret), "keyshare secret doesn't match")
}

func TestPacketEncryptDecrypt(t *testing.T) {
	// Setup keys for test
	c := NewKeyshareCore()
	var key AesKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c.DangerousSetAESEncryptionKey(1, key)

	// Test parameters
	var testSecret = big.NewInt(5)
	var testPassword [64]byte
	_, err = rand.Read(testPassword[:])
	require.NoError(t, err)

	// Create and encrypt packet
	var p_before unencryptedKeysharePacket
	p_before.setPin(testPassword)
	err = p_before.setKeyshareSecret(testSecret)
	require.NoError(t, err)
	p_encypted, err := c.encryptPacket(p_before)
	require.NoError(t, err)

	// Decrypt and test values
	p_after, err := c.decryptPacket(p_encypted)
	require.NoError(t, err)
	assert.Equal(t, testPassword, p_after.getPin(), "passwords don't match")
	assert.Equal(t, 0, p_after.getKeyshareSecret().Cmp(testSecret), "keyshare secrets don't match")
}

func TestPacketAuthentication(t *testing.T) {
	// Setup keys for test
	c := NewKeyshareCore()
	var key AesKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c.DangerousSetAESEncryptionKey(1, key)

	// Test parameters
	var testSecret = big.NewInt(5)
	var testPassword [64]byte
	_, err = rand.Read(testPassword[:])
	require.NoError(t, err)

	// Create and encrypt packet
	var p_before unencryptedKeysharePacket
	p_before.setPin(testPassword)
	err = p_before.setKeyshareSecret(testSecret)
	require.NoError(t, err)
	p_encrypted, err := c.encryptPacket(p_before)
	require.NoError(t, err)

	// Modify encrypted packet and check that it no longer decrypts
	p_encrypted[33] = 0
	p_encrypted[34] = 15
	_, err = c.decryptPacket(p_encrypted)
	assert.Error(t, err, "Tampering not detected")
}

func TestMultiKey(t *testing.T) {
	// Setup keys for test
	c := NewKeyshareCore()
	var key AesKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c.DangerousSetAESEncryptionKey(1, key)
	_, err = rand.Read(key[:])
	require.NoError(t, err)
	c.DangerousAddAESKey(2, key)

	// Test parameters
	var testSecret = big.NewInt(5)
	var testPassword [64]byte
	_, err = rand.Read(testPassword[:])
	require.NoError(t, err)

	// Create packet
	var p_before unencryptedKeysharePacket
	p_before.setPin(testPassword)
	err = p_before.setKeyshareSecret(testSecret)
	require.NoError(t, err)

	// encrypt with key 1
	c.encryptionKeyID = 1
	c.encryptionKey = c.decryptionKeys[c.encryptionKeyID]
	e1, err := c.encryptPacket(p_before)
	require.NoError(t, err)

	// encrypt with key 2
	c.encryptionKeyID = 2
	c.encryptionKey = c.decryptionKeys[c.encryptionKeyID]
	e2, err := c.encryptPacket(p_before)
	require.NoError(t, err)

	// Check e1
	p_after, err := c.decryptPacket(e1)
	assert.NoError(t, err)
	assert.Equal(t, p_before, p_after, "packet mismatch on key 1")

	// Check e2
	p_after, err = c.decryptPacket(e2)
	assert.NoError(t, err)
	assert.Equal(t, p_before, p_after, "packet mismatch on key 2")

	// check that unknown key is detected correctly
	delete(c.decryptionKeys, 1)
	_, err = c.decryptPacket(e1)
	assert.Error(t, err, "Missing decryption key not detected.")
}
