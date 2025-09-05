package irmaclient

import (
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
	"testing"
)

var secretSample = MFASecret{
	Issuer:      "yivi",
	Secret:      "JBSWY3DPEHPK3PXP",
	Period:      30,
	UserAccount: "test@test.com",
	Algorithm:   "SHA1",
}

var secretsSample = []MFASecret{
	{
		Issuer:      "yivi",
		Secret:      "JBSWY3DPEHPK3PXP",
		Period:      30,
		UserAccount: "test@test.com",
		Algorithm:   "SHA1",
	}, {
		Issuer:      "yivi2",
		Secret:      "JBSWY3DPEHPK3PXP2",
		Period:      30,
		UserAccount: "test2@test.com",
		Algorithm:   "SHA1",
	},
}

func TestMFASecretStorage(t *testing.T) {
	RunTestWithTempBboltMfaStorage(t, "Store and retrieve MFA Secret", testStoreRetrieveMFASecret)
	RunTestWithTempBboltMfaStorage(t, "Store and retrieve multiple MFA Secrets", testStoreRetrieveMultipleMFASecret)
	RunTestWithTempBboltMfaStorage(t, "Remove MFA Secret by secret from multiple", testRemoveSecretBySecretFromMultiple)
	RunTestWithTempBboltMfaStorage(t, "Retrieve from empty storage", testRetrieveFromEmptyStorage)
}

func RunTestWithTempBboltMfaStorage(t *testing.T, name string, test func(t *testing.T, storage MfaSecretStorage)) {
	success := t.Run(name, func(t *testing.T) {
		withTempBboltDb(t, "mfa_secret.db", func(db *bbolt.DB) {
			var aesKey [32]byte
			copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

			storage := NewBboltMFASecretStorage(db, aesKey)
			test(t, storage)
		})
	})
	require.True(t, success)
}

func testStoreRetrieveMFASecret(t *testing.T, storage MfaSecretStorage) {

	err := storage.StoreMFASecret(secretSample)
	require.NoError(t, err)

	secrets, err := storage.GetAllSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 1)
	require.Equal(t, secretSample.Secret, secrets[0].Secret)
}

func testStoreRetrieveMultipleMFASecret(t *testing.T, storage MfaSecretStorage) {
	for _, s := range secretsSample {
		err := storage.StoreMFASecret(s)
		require.NoError(t, err)
	}

	secrets, err := storage.GetAllSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 2)
	require.Equal(t, secrets[0].Secret, secrets[0].Secret)
	require.Equal(t, secrets[1].Secret, secrets[1].Secret)
}

func testRemoveSecretBySecretFromMultiple(t *testing.T, storage MfaSecretStorage) {
	for _, s := range secretsSample {
		err := storage.StoreMFASecret(s)
		require.NoError(t, err)
	}

	err := storage.DeleteSecretBySecret(secretsSample[0].Secret)
	require.NoError(t, err)

	secrets, err := storage.GetAllSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 1)
	require.Equal(t, secretsSample[1].Secret, secrets[0].Secret)
}

func testRetrieveFromEmptyStorage(t *testing.T, storage MfaSecretStorage) {
	secrets, err := storage.GetAllSecrets()
	require.NoError(t, err)

	require.Len(t, secrets, 0)
}
