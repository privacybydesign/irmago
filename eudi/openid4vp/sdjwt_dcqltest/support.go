// Package sdjwt_dcqltest provides shared test scaffolding for the SD-JWT DCQL
// engine and its per-format handlers: an in-memory SQLCipher store, a batch
// builder, a DCQL query parser, and a claim-path assertion helper. It links cgo
// (SQLCipher), so importing tests type-check locally but run in CI.
package sdjwt_dcqltest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// init guarantees a logger for any test package that imports this scaffolding:
// the engine warns (via eudi.Logger) when it can't compute a post-disclosure
// view — e.g. for the synthetic fake-raw batches NewTestBatch builds — and a nil
// logger would panic. This replaces the per-package TestMain that would
// otherwise be needed in every importer.
func init() {
	if eudi.Logger == nil {
		eudi.Logger = logrus.StandardLogger()
	}
}

// testStorage is an in-memory SQLCipher-backed storage.Storage for handler tests.
type testStorage struct {
	db *gorm.DB
	fs filesystem.FileSystemStorage
}

func (s *testStorage) Db() *gorm.DB                             { return s.db }
func (s *testStorage) FileSystem() filesystem.FileSystemStorage { return s.fs }
func (s *testStorage) Close() error                             { return nil }
func (s *testStorage) RemoveAll() error                         { return nil }

var _ storage.Storage = (*testStorage)(nil)

// NewTestStorage opens an in-memory SQLCipher database with the holder models
// of both SD-JWT-secured data models migrated.
func NewTestStorage(t *testing.T) storage.Storage {
	t.Helper()
	d, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("test-key-123"))}, &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, d.AutoMigrate(
		&models.SdJwtVcBatch{},
		&models.SdJwtVcBatchInstance{},
		&models.VcdmBatch{},
		&models.VcdmBatchInstance{},
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
	))

	fs := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir())
	return &testStorage{db: d, fs: fs}
}

// NewTestBatch builds a single-instance SD-JWT VC batch with a fake raw
// credential and the given processed payload.
func NewTestBatch(hash, vct string, payload map[string]any) *models.SdJwtVcBatch {
	payloadJSON, _ := json.Marshal(payload)
	iss := "https://issuer.example.com"
	return &models.SdJwtVcBatch{
		IssuerIdentifier:           iss,
		VerifiableCredentialType:   vct,
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       hash,
		ProcessedSdJwtPayload:      datatypes.JSON(payloadJSON),
		IssuedAt:                   datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		CredentialIssuerIdentifier: iss,
		Instances: []models.SdJwtVcBatchInstance{
			{RawCredential: []byte("fake-raw-credential")},
		},
	}
}

// NewTestVcdmBatch builds a single-instance SD-JWT-secured VCDM batch with a
// fake raw credential and the given processed payload (the VCDM document).
func NewTestVcdmBatch(hash, typeIdentity string, payload map[string]any) *models.VcdmBatch {
	payloadJSON, _ := json.Marshal(payload)
	iss := "https://issuer.example.com"
	return &models.VcdmBatch{
		TypeIdentity:     typeIdentity,
		IssuerIdentifier: iss,
		CredentialIssuer: iss,
		Format:           models.CredentialFormatSdJwtVcdm,
		Hash:             hash,
		ProcessedPayload: datatypes.JSON(payloadJSON),
		IssuedAt:         time.Now().UTC().Truncate(time.Second),
		BatchSize:        1,
		RemainingCount:   1,
		Instances: []models.VcdmBatchInstance{
			{RawCredential: []byte("fake-raw-credential")},
		},
	}
}

// ParseDcqlQuery unmarshals a DCQL credential query from JSON.
func ParseDcqlQuery(t *testing.T, raw string) dcql.CredentialQuery {
	t.Helper()
	var q dcql.CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(raw), &q))
	return q
}

// HasClaimPath reports whether attrs contains an attribute at the given claim path.
func HasClaimPath(attrs []clientmodels.Attribute, path []any) bool {
	key := clientmodels.ClaimPathKey(path)
	for _, a := range attrs {
		if clientmodels.ClaimPathKey(a.ClaimPath) == key {
			return true
		}
	}
	return false
}
