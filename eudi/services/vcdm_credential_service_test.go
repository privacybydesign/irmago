package services

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

const testVcdmIssuer = "https://openid4vc.staging.yivi.app"

// newVerifiedVcdm builds and holder-verifies a real SD-JWT-secured VCDM
// credential with the test issuer key, so the verified result carries the raw
// credential the store persists per instance.
func newVerifiedVcdm(t *testing.T, subjectClaims ...*sdjwt.ClaimElement) *vcdmsdjwt.VerifiedSdJwtVcdm {
	t.Helper()
	x5c, err := utils.ParsePemCertificateChainToX5cFormat(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)

	subject := append([]*sdjwt.ClaimElement{sdjwt.Claim("id", "did:example:holder")}, subjectClaims...)
	claims := []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2)),
		sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential")),
		sdjwt.Claim(vcdm.IssuerKey, testVcdmIssuer),
		sdjwt.Claim(vcdm.ValidFromKey, "2020-01-01T00:00:00Z"),
		sdjwt.Claim(vcdm.ValidUntilKey, "2035-01-01T00:00:00Z"),
		sdjwt.Object(vcdm.CredentialSubjectKey, subject...),
		cnf,
	}

	built, err := sdjwt.NewBuilder().
		WithPayload(claims...).
		WithIssuerCertificateChain(x5c).
		WithTyp(vcdmsdjwt.MediaTypeVcSdJwt).
		Build(sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey())
	require.NoError(t, err)

	verifier := vcdmsdjwt.NewHolderVerificationProcessor(
		vcdmsdjwt.CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
	)
	verified, err := verifier.ParseAndVerifySdJwtVcdm(vcdmsdjwt.SdJwtVcdmKb(built))
	require.NoError(t, err)
	return verified
}

func TestVerifyAndStoreIssuedVcdmCredentials_EmptySlice(t *testing.T) {
	mock := &mockCredentialStore{}
	svc := newServiceWithMocks(mock, filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()))

	err := svc.VerifyAndStoreIssuedVcdmCredentials(
		nil, "config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVcdm),
		false, nil,
	)

	require.NoError(t, err)
	assert.Empty(t, mock.storedBatches)
}

func TestVerifyAndStoreIssuedVcdmCredentials_StoresBatch(t *testing.T) {
	mock := &mockCredentialStore{}
	svc := newServiceWithMocks(mock, filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()))
	verified := newVerifiedVcdm(t, sdjwt.SdClaim("given_name", "Alice"))

	err := svc.VerifyAndStoreIssuedVcdmCredentials(
		[]*vcdmsdjwt.VerifiedSdJwtVcdm{verified}, "config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVcdm),
		false, nil,
	)

	require.NoError(t, err)
	require.Len(t, mock.storedBatches, 1)
	batch := mock.storedBatches[0]

	assert.Equal(t, models.CredentialFormatSdJwtVcdm, batch.Format)
	assert.Equal(t, vcdm.ContextV2+" "+vcdm.TypeVerifiableCredential+" ExampleCredential", batch.VerifiableCredentialType)
	assert.Equal(t, testVcdmIssuer, batch.IssuerURL)
	assert.Equal(t, testVcdmIssuer, batch.CredentialIssuer)
	assert.NotEmpty(t, batch.Hash)

	// Validity comes from the document: no JWT iat/exp were signed, so
	// IssuedAt falls back to validFrom and ExpiresAt to validUntil.
	require.True(t, batch.IssuedAt.Valid)
	assert.Equal(t, int64(1577836800), batch.IssuedAt.V.Unix()) // 2020-01-01T00:00:00Z
	require.True(t, batch.ExpiresAt.Valid)
	assert.Equal(t, int64(2051222400), batch.ExpiresAt.V.Unix()) // 2035-01-01T00:00:00Z

	// The raw secured credential is persisted per instance; VCDM status
	// (credentialStatus / BitstringStatusList) is not seeded — the IETF
	// Token Status List fields stay empty.
	require.Len(t, batch.Instances, 1)
	assert.Equal(t, []byte(verified.GetRawSdJwtVcdm()), batch.Instances[0].RawCredential)
	assert.Nil(t, batch.Instances[0].StatusListURI)
	assert.Nil(t, batch.Instances[0].StatusListIdx)
}

func TestVerifyAndStoreIssuedVcdmCredentials_SameContentSameHash(t *testing.T) {
	mock := &mockCredentialStore{}
	svc := newServiceWithMocks(mock, filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()))
	issuerMetadata := newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVcdm)

	first := newVerifiedVcdm(t, sdjwt.SdClaim("given_name", "Alice"))
	second := newVerifiedVcdm(t, sdjwt.SdClaim("given_name", "Alice"))
	different := newVerifiedVcdm(t, sdjwt.SdClaim("given_name", "Bob"))

	for _, v := range []*vcdmsdjwt.VerifiedSdJwtVcdm{first, second, different} {
		require.NoError(t, svc.VerifyAndStoreIssuedVcdmCredentials(
			[]*vcdmsdjwt.VerifiedSdJwtVcdm{v}, "config-id", issuerMetadata, false, nil))
	}

	require.Len(t, mock.storedBatches, 3)
	// Re-issuance of the same logical credential reproduces the hash (so the
	// stored batch is replaced); different content gets its own batch.
	assert.Equal(t, mock.storedBatches[0].Hash, mock.storedBatches[1].Hash)
	assert.NotEqual(t, mock.storedBatches[0].Hash, mock.storedBatches[2].Hash)
}

func TestVerifyAndStoreIssuedVcdmCredentials_KeyBindingMismatch(t *testing.T) {
	mock := &mockCredentialStore{}
	svc := newServiceWithMocks(mock, filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()))
	verified := newVerifiedVcdm(t)

	err := svc.VerifyAndStoreIssuedVcdmCredentials(
		[]*vcdmsdjwt.VerifiedSdJwtVcdm{verified}, "config-id",
		newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVcdm),
		true,                              // requireCryptographicKeyBinding
		[]models.PublicHolderBindingKey{}, // zero key IDs — mismatch with 1 credential
	)

	require.Error(t, err)
	assert.Empty(t, mock.storedBatches)
}

func TestGetCredentialMetadataList_VcdmBatch_SubjectRootedAttributes(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		vcdm.ContextKey: []any{vcdm.ContextV2},
		vcdm.TypeKey:    []any{vcdm.TypeVerifiableCredential, "ExampleCredential"},
		vcdm.IssuerKey:  testVcdmIssuer,
		vcdm.CredentialSubjectKey: map[string]any{
			"given_name": "Alice",
		},
	})
	require.NoError(t, err)

	batch := &models.CredentialBatch{
		ID:                       datatypes.NewUUIDv4(),
		IssuerURL:                testVcdmIssuer,
		VerifiableCredentialType: vcdm.ContextV2 + " " + vcdm.TypeVerifiableCredential + " ExampleCredential",
		Format:                   models.CredentialFormatSdJwtVcdm,
		Hash:                     "vcdm-hash",
		ProcessedSdJwtPayload:    datatypes.JSON(payload),
		CredentialIssuer:         testVcdmIssuer,
		BatchSize:                1,
		RemainingCount:           1,
	}

	mock := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}
	svc := newServiceWithMocks(mock, filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()))

	list, err := svc.GetCredentialMetadataList()
	require.NoError(t, err)
	require.Len(t, list, 1)

	cred := list[0]
	assert.Equal(t, batch.VerifiableCredentialType, cred.CredentialId)
	assert.Equal(t, map[clientmodels.CredentialFormat]string{clientmodels.Format_SdJwtVcdm: "vcdm-hash"}, cred.CredentialInstanceIds)

	// Attributes are the credentialSubject tree with document-rooted paths;
	// the VCDM envelope properties are not attributes.
	require.Len(t, cred.Attributes, 1)
	assert.Equal(t, []any{vcdm.CredentialSubjectKey, "given_name"}, cred.Attributes[0].ClaimPath)
	require.NotNil(t, cred.Attributes[0].Value)
}
