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
	RunTestWithTempBboltKeyBindingStorage(t,
		"store many private keys",
		testStoreManyPrivateKeys,
	)
	RunTestWithTempBboltKeyBindingStorage(t,
		"retrieve single private key can only be done once",
		testRetrieveSinglePrivateKeyCanOnlyBeDoneOnce,
	)
	RunTestWithTempBboltKeyBindingStorage(t,
		"remove all private keys",
		testRemoveAllPrivateKeys,
	)
	RunTestWithTempBboltKeyBindingStorage(t,
		"remove specific private keys",
		testRemoveSpecificPrivateKeys,
	)
	RunTestWithTempBboltKeyBindingStorage(t,
		"delete no keys from empty storage should be fine",
		testDeletingNoKeysFromEmptyStorageShouldBeFine,
	)
	RunTestWithTempBboltKeyBindingStorage(t,
		"deleting keys from empty storage is error",
		testDeletingKeysFromEmptyStorageIsError,
	)
}

func testDeletingKeysFromEmptyStorageIsError(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	privKeys := createPrivateKeys(t, 10)
	pubKeys := getPubJwkMultiple(t, privKeys)
	require.Error(t, storage.RemovePrivateKeys(pubKeys))
}

func testDeletingNoKeysFromEmptyStorageShouldBeFine(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	require.NoError(t, storage.RemovePrivateKeys([]jwk.Key{}))
}

func getPubJwk(t *testing.T, priv *ecdsa.PrivateKey) jwk.Key {
	privJwk, err := jwk.Import(priv)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)
	return pubJwk
}

func getPubJwkMultiple(t *testing.T, privKeys []*ecdsa.PrivateKey) (result []jwk.Key) {
	for _, key := range privKeys {
		result = append(result, getPubJwk(t, key))
	}
	return
}

func testRetrieveSinglePrivateKeyCanOnlyBeDoneOnce(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	privateKeys := createPrivateKeys(t, 100)
	require.NoError(t, storage.StorePrivateKeys(privateKeys))

	pubJwk := getPubJwk(t, privateKeys[0])
	privKey, err := storage.GetAndRemovePrivateKey(pubJwk)
	require.NoError(t, err)

	require.Equal(t, privateKeys[0], privKey)

	_, err = storage.GetAndRemovePrivateKey(pubJwk)
	require.Error(t, err)

	pubJwk = getPubJwk(t, privateKeys[1])
	privKey, err = storage.GetAndRemovePrivateKey(pubJwk)
	require.NoError(t, err)
	require.Equal(t, privateKeys[1], privKey)
}

func testStoreManyPrivateKeys(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	privateKeys := createPrivateKeys(t, 100)
	require.NoError(t, storage.StorePrivateKeys(privateKeys))
}

func testRemoveSpecificPrivateKeys(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	privateKeys := createPrivateKeys(t, 10)
	require.NoError(t, storage.StorePrivateKeys(privateKeys))

	require.NoError(t, storage.RemovePrivateKeys(getPubJwkMultiple(t, privateKeys[:5])))

	for _, key := range privateKeys[:5] {
		_, err := storage.GetAndRemovePrivateKey(getPubJwk(t, key))
		require.Error(t, err)
	}

	for _, key := range privateKeys[5:] {
		privKey, err := storage.GetAndRemovePrivateKey(getPubJwk(t, key))
		require.NoError(t, err)
		require.Equal(t, key, privKey)
	}
}

func testRemoveAllPrivateKeys(t *testing.T, storage sdjwtvc.KeyBindingStorage) {
	privKeys := createPrivateKeys(t, 100)
	require.NoError(t, storage.StorePrivateKeys(privKeys))
	require.NoError(t, storage.RemoveAllPrivateKeys())

	for _, key := range privKeys {
		_, err := storage.GetAndRemovePrivateKey(getPubJwk(t, key))
		require.Error(t, err)
	}
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

			storage := NewBboltKeyBindingStorage(db, aesKey)
			test(t, storage)
		})
	})
	require.True(t, success)
}
