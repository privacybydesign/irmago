package services

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// --- mock CredentialStore ---

type mockCredentialStore struct {
	storedBatches   []*models.CredentialBatch
	batchListResult []*models.CredentialBatch
	storeBatchErr   error
	batchListErr    error
}

func (m *mockCredentialStore) StoreBatch(batch *models.CredentialBatch) error {
	if m.storeBatchErr != nil {
		return m.storeBatchErr
	}
	m.storedBatches = append(m.storedBatches, batch)
	return nil
}

func (m *mockCredentialStore) GetCredentialBatchList() ([]*models.CredentialBatch, error) {
	return m.batchListResult, m.batchListErr
}

func (m *mockCredentialStore) GetBatchByHash(hash string) (*models.CredentialBatch, error) {
	return nil, db.ErrNotFound
}

func (m *mockCredentialStore) GetBatchesByVCT(vct string) ([]*models.CredentialBatch, error) {
	return nil, nil
}

func (m *mockCredentialStore) GetUnusedInstance(batchID datatypes.UUID) (*models.IssuedCredentialInstance, error) {
	return nil, db.ErrNotFound
}

func (m *mockCredentialStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	return nil
}

func (m *mockCredentialStore) DeleteBatch(batchID datatypes.UUID) error {
	return nil
}

func (m *mockCredentialStore) DeleteBatchByHash(hash string) error {
	return nil
}

// --- helpers ---

func newServiceWithMocks(storeMock *mockCredentialStore, fileStorageMock filesystem.FileSystemStorage) *credentialService {
	return &credentialService{
		credentialStore: storeMock,
		fileStorage:     fileStorageMock,
	}
}

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }

func newVerifiedVc(vct, issuer string, issuedAt, expiry, notBefore int64) *sdjwtvc.VerifiedSdJwtVc {
	return &sdjwtvc.VerifiedSdJwtVc{
		IssuerSignedJwtPayload: sdjwtvc.IssuerSignedJwtPayload{
			Issuer:                   issuer,
			VerifiableCredentialType: vct,
			IssuedAt:                 issuedAt,
			Expiry:                   expiry,
			NotBefore:                notBefore,
		},
		ProcessedSdJwtPayload: sdjwtvc.ProcessedSdJwtPayload{
			"sub": "user123",
		},
	}
}

func newMinimalIssuerMetadata(configID string, format metadata.CredentialFormatIdentifier) metadata.CredentialIssuerMetadata {
	return metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		Display: metadata.CredentialIssuerDisplays{
			{Display: metadata.Display{Name: "Test Issuer", Locale: strPtr("en")}},
		},
		CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{
			configID: {Format: format},
		},
	}
}

func newFullIssuerMetadata(configID string) metadata.CredentialIssuerMetadata {
	return metadata.CredentialIssuerMetadata{
		CredentialIssuer: "https://issuer.example.com",
		Display: metadata.CredentialIssuerDisplays{
			{Display: metadata.Display{Name: "Test Issuer", Locale: strPtr("en")}},
			{Display: metadata.Display{Name: "Test Issuer NL", Locale: strPtr("nl")}},
		},
		CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{
			configID: {
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				CredentialMetadata: &metadata.CredentialMetadata{
					Display: metadata.CredentialDisplays{
						{Display: metadata.Display{Name: "My Credential", Locale: strPtr("en")}},
					},
					Claims: []metadata.ClaimsDescription{
						{
							Path:      metadata.ClaimsPathPointer{"family_name"},
							Mandatory: boolPtr(true),
							Display: []metadata.Display{
								{Name: "Family Name", Locale: strPtr("en")},
								{Name: "Achternaam", Locale: strPtr("nl")},
							},
						},
					},
				},
			},
		},
	}
}

// newStorageBatch builds a models.CredentialBatch suitable for GetCredentialBatchList results.
func newStorageBatch() *models.CredentialBatch {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(24 * time.Hour)
	remaining := uint(1)
	return &models.CredentialBatch{
		IssuerURL:                "https://issuer.example.com",
		VerifiableCredentialType: "https://vct.example.com/MyCredential",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     "testhash",
		ProcessedSdJwtPayload:    datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                 now,
		ExpiresAt:                datatypes.NullTime{V: exp, Valid: true},
		BatchSize:                1,
		RemainingCount:           remaining,
		CredentialIssuer:         "https://issuer.example.com",
		IssuerDisplay: []models.IssuerMetadataDisplay{
			{Name: "Test Issuer", Locale: datatypes.NullString{V: "en", Valid: true}},
		},
		CredentialMetadata: &models.CredentialMetadata{
			Display: []models.CredentialDisplay{
				{Name: "My Credential", Locale: datatypes.NullString{V: "en", Valid: true}},
			},
			Claims: []models.CredentialClaim{
				{
					Path:      datatypes.JSON(`["family_name"]`),
					Mandatory: true,
					Display: []models.ClaimDisplay{
						{Name: "Family Name", Locale: datatypes.NullString{V: "en", Valid: true}},
					},
				},
			},
		},
		Instances: []models.IssuedCredentialInstance{
			{RawCredential: []byte("raw-token")},
		},
	}
}

// ========== GetCredentialMetadataList ==========

func TestGetCredentialMetadataList_EmptyStore(t *testing.T) {
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestGetCredentialMetadataList_StoreError(t *testing.T) {
	mock := &mockCredentialStore{batchListErr: errors.New("db failure")}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	_, err := svc.GetCredentialMetadataList()

	require.Error(t, err)
}

func TestGetCredentialMetadataList_ReturnsSingleCredential(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestGetCredentialMetadataList_MapsCredentialId(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.VerifiableCredentialType, result[0].CredentialId)
}

func TestGetCredentialMetadataList_MapsHash(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.Hash, result[0].Hash)
}

func TestGetCredentialMetadataList_MapsIssuerDisplay(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.CredentialIssuer, result[0].Issuer.Id)
	assert.Equal(t, "Test Issuer", result[0].Issuer.Name["en"])
}

func TestGetCredentialMetadataList_MapsCredentialDisplay(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, "My Credential", result[0].Name["en"])
}

func TestGetCredentialMetadataList_MapsAttributes(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	require.Len(t, result[0].Attributes, 1)
	assert.Equal(t, "Family Name", (*result[0].Attributes[0].DisplayName)["en"])
}

func TestGetCredentialMetadataList_MapsIssuanceAndExpiry(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.IssuedAt.Unix(), result[0].IssuanceDate)
	require.True(t, batch.ExpiresAt.Valid)
	assert.Equal(t, batch.ExpiresAt.V.Unix(), result[0].ExpiryDate)
}

func TestGetCredentialMetadataList_MapsRemainingCount(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	require.Len(t, result, 1)
	counts := result[0].BatchInstanceCountsRemaining
	require.Len(t, counts, 1)
	for _, v := range counts {
		// Batch size 1 → nil (unlimited), batch size > 1 → remaining count.
		if batch.BatchSize <= 1 {
			assert.Nil(t, v, "batch-of-1 should have nil remaining count")
		} else {
			require.NotNil(t, v)
			assert.Equal(t, batch.RemainingCount, *v)
		}
	}
}

func TestGetCredentialMetadataList_NilCredentialMetadata(t *testing.T) {
	batch := newStorageBatch()
	batch.CredentialMetadata = nil
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Empty(t, result[0].Attributes)
	assert.Empty(t, result[0].Name)
}

func TestGetCredentialMetadataList_IssuerDisplayWithoutLocale_ResultsInDefaultLocale(t *testing.T) {
	batch := newStorageBatch()
	batch.IssuerDisplay = []models.IssuerMetadataDisplay{
		{Name: "No Locale Issuer", Locale: datatypes.NullString{Valid: false}},
	}
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, "No Locale Issuer", result[0].Issuer.Name[clientmodels.DefaultFallbackLanguage])
}

func TestGetCredentialMetadataList_MultipleCredentials(t *testing.T) {
	batch1 := newStorageBatch()
	batch2 := newStorageBatch()
	batch2.Hash = "testhash2"
	batch2.VerifiableCredentialType = "https://vct.example.com/OtherCredential"
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch1, batch2}}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

// ========== VerifyAndStoreIssuedCredentials ==========

func TestVerifyAndStoreIssuedCredentials_EmptySlice(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)

	err := svc.VerifyAndStoreIssuedCredentials(
		nil,
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	assert.Empty(t, mock.storedBatches)
}

func TestVerifyAndStoreIssuedCredentials_KeyBindingMismatch(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		true,                              // requireCryptographicKeyBinding
		[]models.PublicHolderBindingKey{}, // zero key IDs — mismatch with 1 VC
	)

	require.Error(t, err)
}

func TestVerifyAndStoreIssuedCredentials_KeyBindingMismatch_TooManyKeys(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		true,
		[]models.PublicHolderBindingKey{
			{ID: datatypes.NewUUIDv4()},
			{ID: datatypes.NewUUIDv4()},
		}, // 2 key IDs for 1 VC
	)

	require.Error(t, err)
}

func TestVerifyAndStoreIssuedCredentials_NoKeyBinding_CallsStoreBatch(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	require.Len(t, mock.storedBatches, 1)
}

// TODO: in the future, we need to link the private key used for holder binding to the stored credential batch, and then we can test that the correct key ID is set on the batch.
// func TestVerifyAndStoreIssuedCredentials_WithKeyBinding_SetsHolderBindingKeyID(t *testing.T) {
// 	mock := &mockCredentialStore{}
// 	svc := newServiceWithMock(mock)
// 	keyID := datatypes.NewUUIDv4()
// 	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

// 	err := svc.VerifyAndStoreIssuedCredentials(
// 		[]*sdjwtvc.VerifiedSdJwtVc{vc},
// 		"config-id",
// 		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
// 		true,
// 		[]models.PublicHolderBindingKey{{ID: keyID}},
// 	)

// 	require.NoError(t, err)
// 	require.Len(t, mock.storedBatches, 1)
// 	require.Len(t, mock.storedBatches[0].Instances, 1)
// 	assert.Equal(t, &keyID, mock.storedBatches[0].Instances[0].HolderBindingKeyID)
// }

func TestVerifyAndStoreIssuedCredentials_NoKeyBinding_NilHolderBindingKeyID(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	require.Len(t, mock.storedBatches, 1)
	assert.Nil(t, mock.storedBatches[0].Instances[0].HolderBindingKeyID)
}

func TestVerifyAndStoreIssuedCredentials_BatchSize(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc1 := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)
	vc2 := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)
	keyID1, keyID2 := datatypes.NewUUIDv4(), datatypes.NewUUIDv4()

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc1, vc2},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		true,
		[]models.PublicHolderBindingKey{{ID: keyID1}, {ID: keyID2}},
	)

	require.NoError(t, err)
	require.Len(t, mock.storedBatches, 1)
	batch := mock.storedBatches[0]
	assert.Equal(t, uint(2), batch.BatchSize)
	assert.Equal(t, uint(2), batch.RemainingCount)
	assert.Len(t, batch.Instances, 2)
}

func TestVerifyAndStoreIssuedCredentials_SetsIssuerMetadata(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	issuer := "https://issuer.example.com"
	vc := newVerifiedVc("https://vct.example.com/Cred", issuer, time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	batch := mock.storedBatches[0]
	assert.Equal(t, issuer, batch.IssuerURL)
	assert.Equal(t, issuer, batch.CredentialIssuer)
}

func TestVerifyAndStoreIssuedCredentials_SetsVCT(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vct := "https://vct.example.com/Cred"
	vc := newVerifiedVc(vct, "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, vct, mock.storedBatches[0].VerifiableCredentialType)
}

func TestVerifyAndStoreIssuedCredentials_SetsFormat(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, models.CredentialFormatSdJwtVc, mock.storedBatches[0].Format)
}

func TestVerifyAndStoreIssuedCredentials_ExpirySet(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	expiry := time.Now().Add(24 * time.Hour).Unix()
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), expiry, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	require.True(t, mock.storedBatches[0].ExpiresAt.Valid)
	assert.Equal(t, expiry, mock.storedBatches[0].ExpiresAt.V.Unix())
}

func TestVerifyAndStoreIssuedCredentials_ExpiryZero_NilExpiresAt(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, mock.storedBatches[0].ExpiresAt.Valid, true)
	assert.Equal(t, mock.storedBatches[0].ExpiresAt.V, time.Unix(0, 0))
}

func TestVerifyAndStoreIssuedCredentials_NotBeforeSet(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	nbf := time.Now().Add(-1 * time.Hour).Unix()
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, nbf)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	require.True(t, mock.storedBatches[0].NotBefore.Valid)
	assert.Equal(t, nbf, mock.storedBatches[0].NotBefore.V.Unix())
}

func TestVerifyAndStoreIssuedCredentials_NotBeforeZero_NilNotBefore(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, mock.storedBatches[0].NotBefore.Valid, true)
	assert.Equal(t, mock.storedBatches[0].NotBefore.V, time.Unix(0, 0))
}

func TestVerifyAndStoreIssuedCredentials_StoreError_Propagated(t *testing.T) {
	storeErr := errors.New("storage failure")
	mock := &mockCredentialStore{storeBatchErr: storeErr}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc),
		false,
		nil,
	)

	require.Error(t, err)
}

func TestVerifyAndStoreIssuedCredentials_FullMetadata_ClaimsConverted(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"full-config",
		newFullIssuerMetadata("full-config"),
		false,
		nil,
	)

	require.NoError(t, err)
	require.Len(t, mock.storedBatches, 1)
	batch := mock.storedBatches[0]
	require.NotNil(t, batch.CredentialMetadata)
	require.Len(t, batch.CredentialMetadata.Claims, 1)
	assert.True(t, batch.CredentialMetadata.Claims[0].Mandatory)
	require.Len(t, batch.CredentialMetadata.Claims[0].Display, 2)
}

func TestVerifyAndStoreIssuedCredentials_NilCredentialMetadata_StoredWithEmptyClaims(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)

	// metadata config with nil CredentialMetadata
	m := newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc)

	err := svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id",
		m,
		false,
		nil,
	)

	require.NoError(t, err)
	require.Len(t, mock.storedBatches, 1)
	batch := mock.storedBatches[0]
	require.NotNil(t, batch.CredentialMetadata)
	assert.Empty(t, batch.CredentialMetadata.Claims)
}

func TestVerifyAndStoreIssuedCredentials_HashIsDeterministic(t *testing.T) {
	mock := &mockCredentialStore{}
	fileStorageMock := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	svc := newServiceWithMocks(mock, fileStorageMock)
	vc := newVerifiedVc("https://vct.example.com/Cred", "https://issuer.example.com", time.Now().Unix(), 0, 0)
	m := newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVc)

	_ = svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id", m, false, nil,
	)
	_ = svc.VerifyAndStoreIssuedCredentials(
		[]*sdjwtvc.VerifiedSdJwtVc{vc},
		"config-id", m, false, nil,
	)

	require.Len(t, mock.storedBatches, 2)
	assert.Equal(t, mock.storedBatches[0].Hash, mock.storedBatches[1].Hash)
}

// ========== hashForSdJwtVc ==========

func TestHashForSdJwtVc_NonEmpty(t *testing.T) {
	h, err := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"given_name":"Alice"}`))
	require.NoError(t, err)
	assert.NotEmpty(t, h)
}

func TestHashForSdJwtVc_Deterministic(t *testing.T) {
	h1, err := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"given_name":"Alice"}`))
	require.NoError(t, err)
	h2, err := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"given_name":"Alice"}`))
	require.NoError(t, err)
	assert.Equal(t, h1, h2)
}

func TestHashForSdJwtVc_DifferentVCT(t *testing.T) {
	h1, err := hashForSdJwtVc("https://vct.example.com/CredA", []byte(`{"given_name":"Alice"}`))
	require.NoError(t, err)
	h2, err := hashForSdJwtVc("https://vct.example.com/CredB", []byte(`{"given_name":"Alice"}`))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2)
}

func TestHashForSdJwtVc_DifferentPayload(t *testing.T) {
	h1, err := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"given_name":"Alice"}`))
	require.NoError(t, err)
	h2, err := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"given_name":"Bob"}`))
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2)
}

func TestHashForSdJwtVc_IgnoresIssuerMetadata(t *testing.T) {
	// Two payloads with identical claim values but different issuer metadata (iat, exp, nbf, sub, cnf).
	// The hash should be the same because only the actual claims matter for deduplication.
	payload1 := []byte(`{"email":"a@b.com","given_name":"Alice","iat":1000,"exp":2000,"nbf":900,"iss":"https://issuer.example","sub":"user1","vct":"TestCred","cnf":{"jwk":{"kty":"EC"}}}`)
	payload2 := []byte(`{"email":"a@b.com","given_name":"Alice","iat":9999,"exp":9998,"nbf":9997,"iss":"https://issuer.example","sub":"user2","vct":"TestCred","cnf":{"jwk":{"kty":"OKP"}}}`)

	h1, err := hashForSdJwtVc("https://vct.example.com/Cred", payload1)
	require.NoError(t, err)
	h2, err := hashForSdJwtVc("https://vct.example.com/Cred", payload2)
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "hashes should be equal when only issuer metadata differs")
}

func TestHashForSdJwtVc_IgnoresAllKnownMetadataKeys(t *testing.T) {
	// A payload containing every known metadata key alongside actual claims.
	withMetadata := []byte(`{"given_name":"Alice","iss":"https://issuer","iat":1000,"exp":2000,"nbf":900,"sub":"subj","vct":"type","cnf":{"jwk":{}},"status":"active","_sd":["abc"],"_sd_alg":"sha-256"}`)
	withoutMetadata := []byte(`{"given_name":"Alice"}`)

	h1, err := hashForSdJwtVc("https://vct.example.com/Cred", withMetadata)
	require.NoError(t, err)
	h2, err := hashForSdJwtVc("https://vct.example.com/Cred", withoutMetadata)
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "metadata keys should not affect the hash")
}

func TestHashForSdJwtVc_ClaimValuesDetermineHash(t *testing.T) {
	// Same metadata, different actual claim values → different hash.
	base := `{"iat":1000,"exp":2000,"iss":"https://issuer","given_name":"%s"}`
	payload1 := []byte(fmt.Sprintf(base, "Alice"))
	payload2 := []byte(fmt.Sprintf(base, "Bob"))

	h1, err := hashForSdJwtVc("https://vct.example.com/Cred", payload1)
	require.NoError(t, err)
	h2, err := hashForSdJwtVc("https://vct.example.com/Cred", payload2)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "different claim values should produce different hashes")
}

func TestHashForSdJwtVc_KeyOrderIrrelevant(t *testing.T) {
	tests := []struct {
		name     string
		payload1 string
		payload2 string
	}{
		{
			name:     "flat claims",
			payload1: `{"given_name":"Alice","email":"a@b.com"}`,
			payload2: `{"email":"a@b.com","given_name":"Alice"}`,
		},
		{
			name:     "nested object with swapped keys",
			payload1: `{"address":{"city":"Amsterdam","street":"Main St"},"name":"Alice"}`,
			payload2: `{"name":"Alice","address":{"street":"Main St","city":"Amsterdam"}}`,
		},
		{
			name:     "deeply nested with swapped keys at every level",
			payload1: `{"university":{"name":"TU Delft","faculties":[{"departments":[{"dept_name":"CS","courses":["ML","AI"]}],"faculty_name":"EEMCS"}],"founded":1842}}`,
			payload2: `{"university":{"founded":1842,"faculties":[{"faculty_name":"EEMCS","departments":[{"courses":["ML","AI"],"dept_name":"CS"}]}],"name":"TU Delft"}}`,
		},
		{
			name:     "nested with issuer metadata mixed in",
			payload1: `{"iat":1000,"address":{"street":"A","city":"B"},"name":"Alice","exp":2000}`,
			payload2: `{"exp":9999,"name":"Alice","iat":5555,"address":{"city":"B","street":"A"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h1, err := hashForSdJwtVc("https://vct.example.com/Cred", []byte(tt.payload1))
			require.NoError(t, err)
			h2, err := hashForSdJwtVc("https://vct.example.com/Cred", []byte(tt.payload2))
			require.NoError(t, err)
			assert.Equal(t, h1, h2, "key order should not affect the hash")
		})
	}
}

func TestHashForSdJwtVc_ArrayOrderMatters(t *testing.T) {
	// Array element order is semantically meaningful in SD-JWT claims,
	// so different orderings must produce different hashes.
	payload1 := []byte(`{"courses":["ML","AI"]}`)
	payload2 := []byte(`{"courses":["AI","ML"]}`)

	h1, err := hashForSdJwtVc("https://vct.example.com/Cred", payload1)
	require.NoError(t, err)
	h2, err := hashForSdJwtVc("https://vct.example.com/Cred", payload2)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "different array ordering should produce different hashes")
}
