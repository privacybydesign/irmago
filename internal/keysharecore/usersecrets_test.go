package keysharecore

import (
	"crypto/rand"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserSecretsAccess(t *testing.T) {
	var testSecret = big.NewInt(51232)
	testPassword := make([]byte, 64)
	_, err := rand.Read(testPassword)
	require.NoError(t, err)

	var p unencryptedUserSecrets
	require.NoError(t, p.setPin(string(testPassword)))
	err = p.setKeyshareSecret(testSecret)
	require.NoError(t, err)
	assert.Equal(t, testPassword, p.Pin, "password doesn't match")
	assert.Equal(t, 0, p.KeyshareSecret.Cmp(testSecret), "keyshare secret doesn't match")
}

func TestUserSecretsEncryptDecrypt(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key})

	// Test parameters
	var testSecret = big.NewInt(5)
	testPassword := make([]byte, 64)
	_, err = rand.Read(testPassword)
	require.NoError(t, err)

	// Create and encrypt user secrets
	var p_before unencryptedUserSecrets
	require.NoError(t, p_before.setPin(string(testPassword)))
	err = p_before.setKeyshareSecret(testSecret)
	require.NoError(t, err)
	p_encypted, err := c.encryptUserSecrets(p_before)
	require.NoError(t, err)

	// Decrypt and test values
	p_after, err := c.decryptUserSecrets(p_encypted)
	require.NoError(t, err)
	assert.Equal(t, testPassword, p_after.Pin, "passwords don't match")
	assert.Equal(t, 0, p_after.KeyshareSecret.Cmp(testSecret), "keyshare secrets don't match")
}

func TestUserSecretsAuthentication(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key})

	// Test parameters
	var testSecret = big.NewInt(5)
	testPassword := make([]byte, 64)
	_, err = rand.Read(testPassword)
	require.NoError(t, err)

	// Create and encrypt user secrets
	var p_before unencryptedUserSecrets
	require.NoError(t, p_before.setPin(string(testPassword)))
	err = p_before.setKeyshareSecret(testSecret)
	require.NoError(t, err)
	p_encrypted, err := c.encryptUserSecrets(p_before)
	require.NoError(t, err)

	// Modify encrypted user secrets and check that it no longer decrypts
	p_encrypted[33] = 0
	p_encrypted[34] = 15
	_, err = c.decryptUserSecrets(p_encrypted)
	assert.EqualError(t, err, "cipher: message authentication failed", "Tampering not detected")
}

func TestMultiKey(t *testing.T) {
	// Setup keys for test
	var key AESKey
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{DecryptionKeyID: 1, DecryptionKey: key})
	_, err = rand.Read(key[:])
	require.NoError(t, err)
	c.DangerousAddDecryptionKey(2, key)

	// Test parameters
	var testSecret = big.NewInt(5)
	testPassword := make([]byte, 64)
	_, err = rand.Read(testPassword)
	require.NoError(t, err)

	// Create user secrets
	var p_before unencryptedUserSecrets
	require.NoError(t, p_before.setPin(string(testPassword)))
	err = p_before.setKeyshareSecret(testSecret)
	require.NoError(t, err)

	// encrypt with key 1
	c.decryptionKeyID = 1
	c.decryptionKey = c.decryptionKeys[c.decryptionKeyID]
	e1, err := c.encryptUserSecrets(p_before)
	require.NoError(t, err)

	// encrypt with key 2
	c.decryptionKeyID = 2
	c.decryptionKey = c.decryptionKeys[c.decryptionKeyID]
	e2, err := c.encryptUserSecrets(p_before)
	require.NoError(t, err)

	// Check e1
	p_after, err := c.decryptUserSecrets(e1)
	assert.NoError(t, err)
	assert.Equal(t, p_before, p_after, "user secrets mismatch on key 1")

	// Check e2
	p_after, err = c.decryptUserSecrets(e2)
	assert.NoError(t, err)
	assert.Equal(t, p_before, p_after, "user secrets mismatch on key 2")

	// check that unknown key is detected correctly
	delete(c.decryptionKeys, 1)
	_, err = c.decryptUserSecrets(e1)
	assert.Error(t, err, "Missing decryption key not detected.")
}
