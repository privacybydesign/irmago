package services

import (
	"errors"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
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
	return nil, storage.ErrNotFound
}

func (m *mockCredentialStore) GetBatchesByVCT(vct string) ([]*models.CredentialBatch, error) {
	return nil, nil
}

func (m *mockCredentialStore) GetUnusedInstance(batchID datatypes.UUID) (*models.IssuedCredentialInstance, error) {
	return nil, storage.ErrNotFound
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

func newServiceWithMock(mock *mockCredentialStore) *credentialService {
	return &credentialService{credentialStore: mock}
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
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestGetCredentialMetadataList_StoreError(t *testing.T) {
	mock := &mockCredentialStore{batchListErr: errors.New("db failure")}
	svc := newServiceWithMock(mock)

	_, err := svc.GetCredentialMetadataList()

	require.Error(t, err)
}

func TestGetCredentialMetadataList_ReturnsSingleCredential(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	require.Len(t, result, 1)
}

func TestGetCredentialMetadataList_MapsCredentialId(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.VerifiableCredentialType, result[0].CredentialId)
}

func TestGetCredentialMetadataList_MapsHash(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.Hash, result[0].Hash)
}

func TestGetCredentialMetadataList_MapsIssuerDisplay(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.CredentialIssuer, result[0].Issuer.Id)
	assert.Equal(t, "Test Issuer", result[0].Issuer.Name["en"])
}

func TestGetCredentialMetadataList_MapsCredentialDisplay(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, "My Credential", result[0].Name["en"])
}

func TestGetCredentialMetadataList_MapsAttributes(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	require.Len(t, result[0].Attributes, 1)
	assert.Equal(t, "Family Name", result[0].Attributes[0].DisplayName["en"])
}

func TestGetCredentialMetadataList_MapsIssuanceAndExpiry(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Equal(t, batch.IssuedAt.Unix(), result[0].IssuanceDate)
	require.True(t, batch.ExpiresAt.Valid)
	assert.Equal(t, batch.ExpiresAt.V.Unix(), result[0].ExpiryDate)
}

func TestGetCredentialMetadataList_MapsRemainingCount(t *testing.T) {
	batch := newStorageBatch()
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	require.Len(t, result, 1)
	counts := result[0].BatchInstanceCountsRemaining
	require.Len(t, counts, 1)
	for _, v := range counts {
		assert.Equal(t, batch.RemainingCount, *v)
	}
}

func TestGetCredentialMetadataList_NilCredentialMetadata(t *testing.T) {
	batch := newStorageBatch()
	batch.CredentialMetadata = nil
	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMock(mock)

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
	svc := newServiceWithMock(mock)

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
	svc := newServiceWithMock(mock)

	result, err := svc.GetCredentialMetadataList()

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

// ========== VerifyAndStoreIssuedCredentials ==========

func TestVerifyAndStoreIssuedCredentials_EmptySlice(t *testing.T) {
	mock := &mockCredentialStore{}
	svc := newServiceWithMock(mock)

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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	svc := newServiceWithMock(mock)
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
	h := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"sub":"user"}`))
	assert.NotEmpty(t, h)
}

func TestHashForSdJwtVc_Deterministic(t *testing.T) {
	h1 := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"sub":"user"}`))
	h2 := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"sub":"user"}`))
	assert.Equal(t, h1, h2)
}

func TestHashForSdJwtVc_DifferentVCT(t *testing.T) {
	h1 := hashForSdJwtVc("https://vct.example.com/CredA", []byte(`{"sub":"user"}`))
	h2 := hashForSdJwtVc("https://vct.example.com/CredB", []byte(`{"sub":"user"}`))
	assert.NotEqual(t, h1, h2)
}

func TestHashForSdJwtVc_DifferentPayload(t *testing.T) {
	h1 := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"sub":"user1"}`))
	h2 := hashForSdJwtVc("https://vct.example.com/Cred", []byte(`{"sub":"user2"}`))
	assert.NotEqual(t, h1, h2)
}
