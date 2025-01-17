package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/privacybydesign/gabi/signed"
	"github.com/stretchr/testify/require"
)

func TestSchemePrivateKeyWithPassphrase(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	passphrase := []byte("test")
	encryptedKey, err := MarshalSchemePrivateKeyWithPassphrase(key, passphrase)
	require.NoError(t, err)

	// Key should be encrypted, so it should not parse as a normal key anymore.
	_, err = signed.UnmarshalPemPrivateKey(encryptedKey)
	require.Error(t, err)

	// Unmarshal the key again to test the decryption.
	decryptedKey, err := ParseSchemePrivateKeyWithPassphrase(encryptedKey, passphrase)
	require.NoError(t, err)
	require.True(t, decryptedKey.Equal(key))
}
