package irmaclient

import (
	"fmt"
	"os"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func TestSdJwtVcStorage(t *testing.T) {
	RunTestWithTempBboltSdJwtVcStorage(t,
		"store and retrieve single sdjwtvc",
		testStoringSingleSdJwtVc,
	)
	RunTestWithTempBboltSdJwtVcStorage(t,
		"store and retrieve multiple instances of sdjwtvc",
		testStoringMultipleInstancesOfSameSdJwtVc,
	)
	RunTestWithTempBboltSdJwtVcStorage(t,
		"remove instances of sdjwtvc",
		testRemovingInstancesOfSdJwtVc,
	)
}

func testStoringSingleSdJwtVc(t *testing.T, storage SdJwtVcStorage) {
	sdjwt, err := createSdJwtVc("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	require.NoError(t, err)
	info, err := createCredentialInfoFromSdJwtVc(sdjwt)
	require.NoError(t, err)
	err = storage.StoreCredential(*info, []sdjwtvc.SdJwtVc{sdjwt})
	require.NoError(t, err)

	result := storage.GetCredentialsForId("pbdf.pbdf.email")
	require.Equal(t, len(result), 1)

	first := result[0]
	require.Equal(t, first.Info, *info)
}

func testRemovingInstancesOfSdJwtVc(t *testing.T, storage SdJwtVcStorage) {
	info, sdjwts := createMultipleSdJwtVcs(t, "pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 2)

	require.Equal(t, len(sdjwts), 2)
	err := storage.StoreCredential(info, sdjwts)
	require.NoError(t, err)

	// first one, it should be available
	result, err := storage.GetCredentialByHash(info.Hash)
	require.NoError(t, err)
	require.NotNil(t, result)

	// remove the first instance (pretend it has been used)
	err = storage.RemoveLastUsedInstanceOfCredentialByHash(info.Hash)
	require.NoError(t, err)

	// second one, should still be available
	result, err = storage.GetCredentialByHash(info.Hash)
	require.NoError(t, err)
	require.NotNil(t, result)

	// remove the second instance (pretend it has been used)
	err = storage.RemoveLastUsedInstanceOfCredentialByHash(info.Hash)
	require.NoError(t, err)

	// all instances have been used by now, so it should report an error
	result, err = storage.GetCredentialByHash(info.Hash)
	require.Error(t, err)
	require.Nil(t, result)
}

func testStoringMultipleInstancesOfSameSdJwtVc(t *testing.T, storage SdJwtVcStorage) {
	info, sdjwts := createMultipleSdJwtVcs(t, "pbdf.pbdf.mobilenumber", "https://openid4vc.staging.yivi.app", map[string]any{
		"mobilenumber": "12345678",
	}, 3)

	err := storage.StoreCredential(info, sdjwts)
	require.NoError(t, err)

	cred, err := storage.GetCredentialByHash(info.Hash)
	require.NoError(t, err)
	require.NotNil(t, cred)

	require.Equal(t, cred.Info, info)

	result := storage.GetCredentialsForId("pbdf.pbdf.mobilenumber")
	require.Equal(t, len(result), 1)
}

func createMultipleSdJwtVcs(t *testing.T, vct string, issuer string, claims map[string]any, num int) (irma.CredentialInfo, []sdjwtvc.SdJwtVc) {
	result := []sdjwtvc.SdJwtVc{}
	for range num {
		sdjwt, err := createSdJwtVc(vct, issuer, claims)
		require.NoError(t, err)
		result = append(result, sdjwt)
	}
	info, err := createCredentialInfoFromSdJwtVc(result[0])
	require.NoError(t, err)
	return *info, result
}

func RunTestWithTempBboltSdJwtVcStorage(t *testing.T, name string, test func(t *testing.T, storage SdJwtVcStorage)) {
	success := t.Run(name, func(t *testing.T) {
		dir, err := os.MkdirTemp("", "client-*")
		require.NoError(t, err)

		dbFile := fmt.Sprintf("%s/sdjwtvc.db", dir)
		db, err := bbolt.Open(dbFile, 0600, &bbolt.Options{Timeout: 1 * time.Second})
		require.NoError(t, err)
		var aesKey [32]byte
		copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

		storage := NewBBoltSdJwtVcStorage(db, aesKey)

		defer db.Close()
		defer os.Remove(dbFile)
		defer os.Remove(dir)

		test(t, storage)
	})
	require.True(t, success)
}
