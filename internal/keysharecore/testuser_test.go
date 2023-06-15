package keysharecore

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

// TestEncryptTestUser creates the keyshare user ciphertext found in
// server/keyshare/keyshareserver/server_test.go and internal/testkeyshare/testkeyshare.go.
// Uncomment the print statements below when necessary and update the ciphertexts in the mentioned files.
//
// (We can't make this a helper invoked by tests requiring these ciphertexts, because this depends
// on unexported methods and structs.)
func TestEncryptTestUser(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	// Read the user's private key to obtain the corresponding public key
	skbts, err := os.ReadFile(filepath.Join(testdataPath, "client", "ecdsa_sk.pem"))
	require.NoError(t, err)
	sk, err := signed.UnmarshalPemPrivateKey(skbts)
	require.NoError(t, err)

	// Start core to encrypt the users with
	keyid, key, err := readAESKey(filepath.Join(testdataPath, "keyshareStorageTestkey"))
	require.NoError(t, err)
	c := NewKeyshareCore(&Configuration{
		DecryptionKey:   key,
		DecryptionKeyID: keyid,
	})

	user := unencryptedUserSecrets{
		Pin:            decodeBase64(t, "AAAAAAAAAAAAAAAAAAAAAAAAAHB1WkdiYUxEbUZ5d0doRkRpNHZXMkc4N1poWHBhVXN2eW1ad05KZkIvU1U9Cg=="),
		ID:             decodeBase64(t, "xMilJA1nLUiaX0PqL175l/TvwwEpBoNX5/FTlmgj6Z4="),
		KeyshareSecret: new(big.Int).SetBytes(decodeBase64(t, "JBx4swn413TzLgEoyScNwXdtnhxue3Y+ZpYaE/ey5N8=")),
	}

	secrets, err := c.encryptUserSecrets(user)
	require.NoError(t, err)
	without := base64.StdEncoding.EncodeToString(secrets)

	user.PublicKey = &sk.PublicKey
	secrets, err = c.encryptUserSecrets(user)
	require.NoError(t, err)
	with := base64.StdEncoding.EncodeToString(secrets)

	// Normally we don't want to print stuff in our tests, so this is commented out.
	// Uncomment when necessary.
	// fmt.Println("Without public key:", without)
	// fmt.Println("With public key:", with)

	// Dummy references to prevent the compiler from thinking the variables are unused
	_ = without
	_ = with
}

// decodeBase64 uses t to check the error
func decodeBase64(t *testing.T, s string) []byte {
	bts, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return bts
}

func readAESKey(filename string) (uint32, AESKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return 0, AESKey{}, err
	}
	if len(keyData) != 32+4 {
		return 0, AESKey{}, errors.New("Invalid aes key")
	}
	var key [32]byte
	copy(key[:], keyData[4:36])
	return binary.LittleEndian.Uint32(keyData[0:4]), key, nil
}
