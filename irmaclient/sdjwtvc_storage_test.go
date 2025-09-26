package irmaclient

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func TestSdJwtVcStorage(t *testing.T) {
	require.True(t, t.Run("old storage compatibility", testCompatibilityWithOldStorage))

	RunTestWithTempBboltSdJwtVcStorage(t, "num instances left", testNumInstanceLeft)

	RunTestWithTempBboltSdJwtVcStorage(t,
		"storing same attributes replaces instances",
		testStoringSameAttributesReplacesInstances,
	)

	RunTestWithTempBboltSdJwtVcStorage(t,
		"get credential info list from empty storage",
		testGetCredentialInfoListFromEmptyStorage,
	)
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
	RunTestWithTempBboltSdJwtVcStorage(t,
		"removing instance returns correct holder keys",
		testRemovingInstanceReturnsCorrectHolderKeys,
	)
}

func testStoringSameAttributesReplacesInstances(t *testing.T, storage SdJwtVcStorage) {
	instanceCount := 10
	info, sdjwts := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email": "test@gmail.com",
	}, uint(instanceCount))

	require.NoError(t, storage.StoreCredential(info, sdjwts))

	creds := storage.GetCredentialsForId("test.test.email")

	require.Len(t, creds, 1)
	require.Equal(t, 10, int(creds[0].Metadata.BatchSize))
	require.Equal(t, 10, int(creds[0].Metadata.RemainingInstanceCount))

	info, sdjwts = createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email": "test@gmail.com",
	}, uint(instanceCount))

	require.NoError(t, storage.StoreCredential(info, sdjwts))

	creds = storage.GetCredentialsForId("test.test.email")

	require.Len(t, creds, 1)
	require.Equal(t, 10, int(creds[0].Metadata.BatchSize))
	require.Equal(t, 10, int(creds[0].Metadata.RemainingInstanceCount))
}

func testNumInstanceLeft(t *testing.T, storage SdJwtVcStorage) {
	info, sdjwts := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email": "test@gmail.com",
	}, 2)

	require.NoError(t, storage.StoreCredential(info, sdjwts))

	creds := storage.GetCredentialsForId("test.test.email")

	require.Len(t, creds, 1)
	require.Equal(t, 2, int(creds[0].Metadata.BatchSize))
	require.Equal(t, 2, int(creds[0].Metadata.RemainingInstanceCount))

	require.NoError(t, storage.RemoveLastUsedInstanceOfCredentialByHash(creds[0].Metadata.Hash))

	creds = storage.GetCredentialsForId("test.test.email")

	require.Len(t, creds, 1)
	require.Equal(t, 2, int(creds[0].Metadata.BatchSize))
	require.Equal(t, 1, int(creds[0].Metadata.RemainingInstanceCount))

	require.NoError(t, storage.RemoveLastUsedInstanceOfCredentialByHash(creds[0].Metadata.Hash))

	creds = storage.GetCredentialsForId("test.test.email")
	require.Equal(t, 2, int(creds[0].Metadata.BatchSize))
	require.Equal(t, 0, int(creds[0].Metadata.RemainingInstanceCount))
}

func testRemovingInstanceReturnsCorrectHolderKeys(t *testing.T, storage SdJwtVcStorage) {
	info, sdjwts := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email": "test@gmail.com",
	}, 10)
	storage.StoreCredential(info, sdjwts)
	holderKeys := extractHolderKeys(t, sdjwts)
	deletedKeys, err := storage.RemoveCredentialByHash(info.Hash)
	require.NoError(t, err)

	require.Equal(t, holderKeys, deletedKeys)
}

func testCompatibilityWithOldStorage(t *testing.T) {
	irmaClient, _ := parseStorage(t)
	defer irmaClient.Close()
	sdjwtStorage := NewBboltSdJwtVcStorage(irmaClient.storage.db, irmaClient.storage.aesKey)
	list := sdjwtStorage.GetCredentialMetdataList()
	require.Empty(t, list)
}

func testGetCredentialInfoListFromEmptyStorage(t *testing.T, storage SdJwtVcStorage) {
	list := storage.GetCredentialMetdataList()
	require.Empty(t, list)
}

// Adding sets of sdjwts with the same attributes should add the sdjwts to the list of existing sdjwt instances.
// The result should not affect the info list
func testAddingMultipleInstancesWithSameAttributeSets(t *testing.T, storage SdJwtVcStorage) {
	emailInfo1, emailSdJwts1 := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 5)

	emailInfo2, emailSdJwts2 := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 5)

	err := storage.StoreCredential(emailInfo1, emailSdJwts1)
	require.NoError(t, err)

	infoList := storage.GetCredentialMetdataList()
	require.Equal(t, len(infoList), 1)

	err = storage.StoreCredential(emailInfo2, emailSdJwts2)
	require.NoError(t, err)

	infoList = storage.GetCredentialMetdataList()
	require.Equal(t, len(infoList), 1)
}

// adding sets of sdjwts with differing attribute sets should result in multiple credential infos in the info list
func testAddingMultipleAttributePairs(t *testing.T, storage SdJwtVcStorage) {
	emailInfo1, emailSdJwts1 := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 5)

	emailInfo2, emailSdJwts2 := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test2@gmail.com",
	}, 5)

	err := storage.StoreCredential(emailInfo1, emailSdJwts1)
	require.NoError(t, err)

	err = storage.StoreCredential(emailInfo2, emailSdJwts2)
	require.NoError(t, err)

	infoList := storage.GetCredentialMetdataList()
	require.Equal(t, len(infoList), 2)
}

func testRemoveAllFromSdJwtVcStorage(t *testing.T, storage SdJwtVcStorage) {
	emailInfo, emailSdJwts := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 2)
	mobileInfo, mobileSdJwts := createMultipleSdJwtVcs(t, "test.test.mobilephone", "https://openid4vc.staging.yivi.app", map[string]any{
		"mobilephone": "1234567",
	}, 3)

	err := storage.StoreCredential(emailInfo, emailSdJwts)
	require.NoError(t, err)

	err = storage.StoreCredential(mobileInfo, mobileSdJwts)
	require.NoError(t, err)

	infoList := storage.GetCredentialMetdataList()
	require.Equal(t, len(infoList), 2)

	err = storage.RemoveAll()
	require.NoError(t, err)

	infoList = storage.GetCredentialMetdataList()
	require.Empty(t, infoList)
}

func testStoringSingleSdJwtVc(t *testing.T, storage SdJwtVcStorage) {
	info, sdjwts := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	}, 1)
	err := storage.StoreCredential(info, sdjwts)
	require.NoError(t, err)

	result := storage.GetCredentialsForId("test.test.email")
	require.Equal(t, len(result), 1)

	first := result[0]
	require.Equal(t, first.Metadata, info)
}

func testRemovingInstancesOfSdJwtVc(t *testing.T, storage SdJwtVcStorage) {
	info, sdjwts := createMultipleSdJwtVcs(t, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email": "test@gmail.com",
	}, 2)

	require.Len(t, sdjwts, 2)
	err := storage.StoreCredential(info, sdjwts)
	require.NoError(t, err)

	// there should be one credential showing up in the info list
	infoList := storage.GetCredentialMetdataList()
	require.Len(t, infoList, 1)

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

	// the whole credential should still show up in the info list
	// but with a count of 0
	infoList = storage.GetCredentialMetdataList()
	require.Len(t, infoList, 1)
	require.Equal(t, 0, int(infoList[0].RemainingInstanceCount))
}

func testStoringMultipleInstancesOfSameSdJwtVc(t *testing.T, storage SdJwtVcStorage) {
	info, sdjwts := createMultipleSdJwtVcs(t, "test.test.mobilephone", "https://openid4vc.staging.yivi.app", map[string]any{
		"mobilephone": "12345678",
	}, 3)

	err := storage.StoreCredential(info, sdjwts)
	require.NoError(t, err)

	cred, err := storage.GetCredentialByHash(info.Hash)
	require.NoError(t, err)
	require.NotNil(t, cred)

	require.Equal(t, cred.Metadata, info)

	result := storage.GetCredentialsForId("test.test.mobilephone")
	require.Equal(t, len(result), 1)
}

func createMultipleSdJwtVcsWithCustomKeyBinder[T any](
	t *testing.T, keyBinder sdjwtvc.KeyBinder, vct string, issuer string, claims map[string]T, num uint,
) (SdJwtVcBatchMetadata, []sdjwtvc.SdJwtVc) {
	result := []sdjwtvc.SdJwtVc{}

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	for range num {
		sdjwt, err := createTestSdJwtVc(keyBinder, vct, issuer, claims, certChain)
		require.NoError(t, err)
		result = append(result, sdjwt)
	}
	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(result[0], sdjwtvc.CreateDefaultVerificationContext(chain))
	require.NoError(t, err)
	return SdJwtVcBatchMetadata{
		BatchSize:              num,
		RemainingInstanceCount: num,
		SignedOn:               info.SignedOn,
		Expires:                info.Expires,
		Attributes:             info.Attributes,
		Hash:                   info.Hash,
		CredentialType:         info.CredentialType,
	}, result
}

func createTestSdJwtVc[T any](keyBinder sdjwtvc.KeyBinder, vct, issuerUrl string, claims map[string]T, x5c []string) (sdjwtvc.SdJwtVc, error) {
	contents, err := sdjwtvc.MultipleNewDisclosureContents(claims)
	if err != nil {
		return "", err
	}

	holderKey, err := keyBinder.CreateKeyPairs(1)
	if err != nil {
		return "", fmt.Errorf("failed to create holder keys: %v", err)
	}

	signer := sdjwtvc.NewEcdsaJwtCreatorWithIssuerTestkey()
	return sdjwtvc.NewSdJwtVcBuilder().
		WithDisclosures(contents).
		WithHolderKey(holderKey[0]).
		WithHashingAlgorithm(sdjwtvc.HashAlg_Sha256).
		WithVerifiableCredentialType(vct).
		WithIssuerUrl(issuerUrl).
		WithIssuedAt(sdjwtvc.NewSystemClock().Now().Unix()).
		WithExpiresAt(sdjwtvc.NewSystemClock().Now().Unix() + 10000).
		WithIssuerCertificateChain(x5c).
		Build(signer)
}

func createMultipleSdJwtVcs[T any](t *testing.T, vct string, issuer string, claims map[string]T, num uint) (SdJwtVcBatchMetadata, []sdjwtvc.SdJwtVc) {
	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	result := []sdjwtvc.SdJwtVc{}

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	for range num {
		sdjwt, err := createTestSdJwtVc(keyBinder, vct, issuer, claims, certChain)
		require.NoError(t, err)
		result = append(result, sdjwt)
	}
	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(result[0], sdjwtvc.CreateDefaultVerificationContext(chain))
	require.NoError(t, err)
	return SdJwtVcBatchMetadata{
		BatchSize:              num,
		RemainingInstanceCount: num,
		SignedOn:               info.SignedOn,
		Expires:                info.Expires,
		Attributes:             info.Attributes,
		Hash:                   info.Hash,
		CredentialType:         info.CredentialType,
	}, result
}

func RunTestWithTempBboltSdJwtVcStorage(t *testing.T, name string, test func(t *testing.T, storage SdJwtVcStorage)) {
	success := t.Run(name, func(t *testing.T) {
		withTempBboltDb(t, "sdjwtvc.db", func(db *bbolt.DB) {
			var aesKey [32]byte
			copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

			storage := NewBboltSdJwtVcStorage(db, aesKey)
			test(t, storage)
		})
	})
	require.True(t, success)
}

func withTempBboltDb(t *testing.T, fileName string, closure func(db *bbolt.DB)) {
	dir, err := os.MkdirTemp("", "client-*")
	require.NoError(t, err)

	dbFile := fmt.Sprintf("%s/%s", dir, fileName)
	db, err := bbolt.Open(dbFile, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	require.NoError(t, err)
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	defer db.Close()
	defer os.Remove(dbFile)
	defer os.Remove(dir)
	closure(db)
}

func extractHolderKeys(t *testing.T, sdjwts []sdjwtvc.SdJwtVc) (result []jwk.Key) {
	for _, cred := range sdjwts {
		_, pubKey, err := sdjwtvc.ExtractHashingAlgorithmAndHolderPubKey(cred)
		require.NoError(t, err)
		result = append(result, pubKey)
	}
	return
}
