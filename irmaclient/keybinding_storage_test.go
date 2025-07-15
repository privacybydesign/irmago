package irmaclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func TestKeyBindingStorage(t *testing.T) {
	RunTestWithTempBboltKeyBindingStorage(t, "store many private keys", testStoreManyPrivateKeys)
	RunTestWithTempBboltKeyBindingStorage(t,
		"retrieve single private key can only be done once",
		testRetrieveSinglePrivateKeyCanOnlyBeDoneOnce,
	)
}

func getPubJwk(t *testing.T, priv *ecdsa.PrivateKey) jwk.Key {
	privJwk, err := jwk.Import(priv)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)
	return pubJwk
}

func testRetrieveSinglePrivateKeyCanOnlyBeDoneOnce(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	privateKeys := createPrivateKeys(t, 100)
	require.NoError(t, storage.StorePrivateKeys(privateKeys))

	pubJwk := getPubJwk(t, privateKeys[0])
	privKey, err := storage.GetAndRemovePrivateKey(pubJwk)
	require.NoError(t, err)

	require.Equal(t, privateKeys[0], privKey)

	privKey, err = storage.GetAndRemovePrivateKey(pubJwk)
	require.Error(t, err)

	pubJwk = getPubJwk(t, privateKeys[1])
	privKey, err = storage.GetAndRemovePrivateKey(pubJwk)
	require.NoError(t, err)
}

func testStoreManyPrivateKeys(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	privateKeys := createPrivateKeys(t, 100)
	require.NoError(t, storage.StorePrivateKeys(privateKeys))
}

func createPrivateKeys(t *testing.T, numKeys int) []*ecdsa.PrivateKey {
	privateKeys := make([]*ecdsa.PrivateKey, numKeys)
	for i := range numKeys {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		privateKeys[i] = privKey
	}
	return privateKeys
}

func RunTestWithTempBboltKeyBindingStorage(t *testing.T, name string, test func(t *testing.T, storage sdjwtvc.KeyBindingStorage)) {
	success := t.Run(name, func(t *testing.T) {
		withTempBboltDb(t, "sdjwtvc.db", func(db *bbolt.DB) {
			var aesKey [32]byte
			copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

			storage := NewBboltKeybindingStorage(db, aesKey)
			test(t, storage)
		})
	})
	require.True(t, success)
}
