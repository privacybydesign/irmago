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
	RunTestWithTempBboltSdJwtVcStorage(t,
		"remove all from storage",
		testRemoveAllFromSdJwtVcStorage,
	)
	RunTestWithTempBboltSdJwtVcStorage(t,
		"adding multiple sets of sdjwts with differing attributes",
		testAddingMultipleAttributePairs,
	)
	RunTestWithTempBboltSdJwtVcStorage(t,
		"adding multiple sets of same attributes should not affect info list",
		testAddingMultipleInstancesWithSameAttributeSets,
	)
}

// Adding sets of sdjwts with the same attributes should add the sdjwts to the list of existing sdjwt instances.
// The result should not affect the info list
func testAddingMultipleInstancesWithSameAttributeSets(t *testing.T, storage SdJwtVcStorage) {
	emailInfo1, emailSdJwts1 := createMultipleSdJwtVcs(t, "pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 5)

	emailInfo2, emailSdJwts2 := createMultipleSdJwtVcs(t, "pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 5)

	err := storage.StoreCredential(emailInfo1, emailSdJwts1)
	require.NoError(t, err)

	infoList := storage.GetCredentialInfoList()
	require.Equal(t, len(infoList), 1)

	err = storage.StoreCredential(emailInfo2, emailSdJwts2)
	require.NoError(t, err)

	infoList = storage.GetCredentialInfoList()
	require.Equal(t, len(infoList), 1)
}

// adding sets of sdjwts with differing attribute sets should result in multiple credential infos in the info list
func testAddingMultipleAttributePairs(t *testing.T, storage SdJwtVcStorage) {
	emailInfo1, emailSdJwts1 := createMultipleSdJwtVcs(t, "pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 5)

	emailInfo2, emailSdJwts2 := createMultipleSdJwtVcs(t, "pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test2@gmail.com",
	}, 5)

	err := storage.StoreCredential(emailInfo1, emailSdJwts1)
	require.NoError(t, err)

	err = storage.StoreCredential(emailInfo2, emailSdJwts2)
	require.NoError(t, err)

	infoList := storage.GetCredentialInfoList()
	require.Equal(t, len(infoList), 2)
}

func testRemoveAllFromSdJwtVcStorage(t *testing.T, storage SdJwtVcStorage) {
	emailInfo, emailSdJwts := createMultipleSdJwtVcs(t, "pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 2)
	mobileInfo, mobileSdJwts := createMultipleSdJwtVcs(t, "pbdf.pbdf.mobilenumber", "https://openid4vc.staging.yivi.app", map[string]any{
		"mobilenumber": "1234567",
	}, 3)

	err := storage.StoreCredential(emailInfo, emailSdJwts)
	require.NoError(t, err)

	err = storage.StoreCredential(mobileInfo, mobileSdJwts)
	require.NoError(t, err)

	infoList := storage.GetCredentialInfoList()
	require.Equal(t, len(infoList), 2)

	err = storage.RemoveAll()
	require.NoError(t, err)

	infoList = storage.GetCredentialInfoList()
	require.Empty(t, infoList)
}

func testStoringSingleSdJwtVc(t *testing.T, storage SdJwtVcStorage) {
	sdjwt, err := createSdJwtVc("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	require.NoError(t, err)
	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwt, sdjwtvc.CreateDefaultVerificationContext())
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

	// there should be one credential showing up in the info list
	infoList := storage.GetCredentialInfoList()
	require.Equal(t, len(infoList), 1)

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

	// the whole credential should now also not show up in the info list
	infoList = storage.GetCredentialInfoList()
	require.Empty(t, infoList)
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
	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(result[0], sdjwtvc.CreateDefaultVerificationContext())
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
