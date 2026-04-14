package eudi_sdjwt_dcql

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// testStorage implements storage.Storage with an in-memory SQLCipher database.
type testStorage struct {
	db *gorm.DB
}

func (s *testStorage) Db() *gorm.DB     { return s.db }
func (s *testStorage) Close() error     { return nil }
func (s *testStorage) RemoveAll() error { return nil }

var _ storage.Storage = (*testStorage)(nil)

func newTestHandler(t *testing.T) (*SdJwtVcDcqlHandler, storage.CredentialStore) {
	t.Helper()
	dsn := sqlcipher.DSN(":memory:", "test-key-123")
	db, err := gorm.Open(sqlcipher.Dialector{DSN: dsn}, &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
		&models.CredentialBatch{},
		&models.IssuedCredentialInstance{},
	))

	ts := &testStorage{db: db}
	credStore := storage.NewCredentialStore(ts)
	handler := &SdJwtVcDcqlHandler{
		credentialStore: credStore,
	}
	return handler, credStore
}

func newTestBatch(hash, vct string, payload map[string]any) *models.CredentialBatch {
	payloadJSON, _ := json.Marshal(payload)
	return &models.CredentialBatch{
		IssuerURL:                "https://issuer.example.com",
		VerifiableCredentialType: vct,
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(payloadJSON),
		IssuedAt:                 time.Now().UTC().Truncate(time.Second),
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         "https://issuer.example.com",
		Instances: []models.IssuedCredentialInstance{
			{RawCredential: []byte("fake-raw-credential")},
		},
	}
}

func parseDcqlQuery(t *testing.T, raw string) dcql.CredentialQuery {
	t.Helper()
	var q dcql.CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(raw), &q))
	return q
}

// ========================================================================
// Expired / not-yet-valid credential filtering
// ========================================================================

func TestFindCandidates_ExpiredCredentialExcluded(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-expired", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	batch.ExpiresAt = datatypes.NullTime{V: time.Now().Add(-1 * time.Hour), Valid: true}
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "expired credential should not appear as candidate")
}

func TestFindCandidates_NotYetValidCredentialExcluded(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-future", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	batch.NotBefore = datatypes.NullTime{V: time.Now().Add(1 * time.Hour), Valid: true}
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "not-yet-valid credential should not appear as candidate")
}

func TestFindCandidates_ValidCredentialIncluded(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-valid", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	batch.ExpiresAt = datatypes.NullTime{V: time.Now().Add(24 * time.Hour), Valid: true}
	batch.NotBefore = datatypes.NullTime{V: time.Now().Add(-24 * time.Hour), Valid: true}
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "valid credential should appear as candidate")
}

func TestFindCandidates_NoExpiryOrNotBefore_Included(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-no-expiry", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	// ExpiresAt and NotBefore left as zero values (Valid = false)
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "credential without expiry/notBefore should be included")
}

func TestFindCandidates_MixedValidAndExpired(t *testing.T) {
	h, store := newTestHandler(t)

	valid := newTestBatch("hash-mix-valid", "https://example.com/EmailCredential", map[string]any{
		"email": "valid@example.com",
	})
	valid.ExpiresAt = datatypes.NullTime{V: time.Now().Add(24 * time.Hour), Valid: true}
	require.NoError(t, store.StoreBatch(valid))

	expired := newTestBatch("hash-mix-expired", "https://example.com/EmailCredential", map[string]any{
		"email": "expired@example.com",
	})
	expired.ExpiresAt = datatypes.NullTime{V: time.Now().Add(-1 * time.Hour), Valid: true}
	require.NoError(t, store.StoreBatch(expired))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "only the valid credential should be returned")
	assert.Equal(t, "hash-mix-valid", result.OwnedCandidates[0].Hash)
}

// ========================================================================
// Multiple VCT values in a single credential query
// ========================================================================

func TestFindCandidates_MultipleVctValues_MatchesAll(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-email", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})))
	require.NoError(t, store.StoreBatch(newTestBatch("hash-phone", "https://example.com/PhoneCredential", map[string]any{
		"email": "test@example.com", // same claim for simplicity
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential", "https://example.com/PhoneCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Len(t, result.OwnedCandidates, 2, "both VCT-matching credentials should be returned")
}

func TestFindCandidates_MultipleVctValues_PartialMatch(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-email-only", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential", "https://example.com/PhoneCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "only the matching VCT credential should be returned")
	assert.Equal(t, "hash-email-only", result.OwnedCandidates[0].Hash)
}

func TestFindCandidates_MultipleVctValues_NoneMatch(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-other", "https://example.com/OtherCredential", map[string]any{
		"email": "test@example.com",
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential", "https://example.com/PhoneCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "no credentials should match")
}

func TestFindCandidates_NoVctValues_MatchesNone(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-a", "https://example.com/A", map[string]any{"email": "a@example.com"})))
	require.NoError(t, store.StoreBatch(newTestBatch("hash-b", "https://example.com/B", map[string]any{"email": "b@example.com"})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "no batches should match when no vct_values specified")
}

// ========================================================================
// Malformed DCQL queries (missing required fields)
// ========================================================================

// TestFindCandidates_NoClaims_MatchesCredential verifies that a query without
// claims still matches credentials per OpenID4VP Section 6.4.1: "If claims is
// absent, the Verifier is requesting no claims that are selectively disclosable."
func TestFindCandidates_NoClaims_MatchesCredential(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-noclaims", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]}
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "credential should match even without claims")
}

func TestFindCandidates_ClaimPathDoesNotExist_NoMatch(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-missing-claim", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})))

	// Request a claim that doesn't exist in the credential payload.
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["phone_number"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "credential missing required claim should not match")
}

func TestFindCandidates_ClaimValueMismatch_NoMatch(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-value-mismatch", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"], "values": ["other@example.com"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "credential with mismatched claim value should not match")
}

func TestFindCandidates_ClaimValueMatchesBoolean(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-bool", "https://example.com/StudentCredential", map[string]any{
		"is_student": true,
		"name":       "Alice",
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/StudentCredential"]},
		"claims": [{"path": ["is_student"], "values": [true]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "boolean value constraint should match")
}

func TestFindCandidates_ClaimValueBooleanMismatch_NoMatch(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-bool-mismatch", "https://example.com/StudentCredential", map[string]any{
		"is_student": false,
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/StudentCredential"]},
		"claims": [{"path": ["is_student"], "values": [true]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "boolean false should not match constraint true")
}

func TestFindCandidates_ClaimValueMatchesInteger(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-int", "https://example.com/AgeCredential", map[string]any{
		"age": float64(25), // JSON numbers are float64
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/AgeCredential"]},
		"claims": [{"path": ["age"], "values": [25]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "integer value constraint should match")
}

func TestFindCandidates_ClaimValueIntegerMismatch_NoMatch(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-int-mismatch", "https://example.com/AgeCredential", map[string]any{
		"age": float64(30),
	})))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/AgeCredential"]},
		"claims": [{"path": ["age"], "values": [25]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates, "age 30 should not match constraint 25")
}

func TestFindCandidates_ClaimValueMixedTypes(t *testing.T) {
	h, store := newTestHandler(t)

	require.NoError(t, store.StoreBatch(newTestBatch("hash-mixed", "https://example.com/ProfileCredential", map[string]any{
		"status": "active",
	})))

	// Query accepts either "active" (string) or 1 (integer) — credential has the string.
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/ProfileCredential"]},
		"claims": [{"path": ["status"], "values": ["active", 1]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "string value should match when listed among mixed-type constraints")
}

// ========================================================================
// ExpiryDate correctness (expiryUnix bug fix verification)
// ========================================================================

func TestFindCandidates_ExpiryDateSetCorrectly(t *testing.T) {
	h, store := newTestHandler(t)

	expiryTime := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	batch := newTestBatch("hash-expiry-check", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	batch.ExpiresAt = datatypes.NullTime{V: expiryTime, Valid: true}
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	assert.Equal(t, expiryTime.Unix(), result.OwnedCandidates[0].ExpiryDate,
		"ExpiryDate should match ExpiresAt, not IssuedAt")
}
