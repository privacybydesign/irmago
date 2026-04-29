package eudi_sdjwt_dcql

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// testStorage implements storage.Storage with an in-memory SQLCipher database.
type testStorage struct {
	db *gorm.DB
	fs filesystem.FileSystemStorage
}

func (s *testStorage) Db() *gorm.DB                             { return s.db }
func (s *testStorage) FileSystem() filesystem.FileSystemStorage { return s.fs }
func (s *testStorage) Close() error                             { return nil }
func (s *testStorage) RemoveAll() error                         { return nil }

var _ storage.Storage = (*testStorage)(nil)

func newTestHandler(t *testing.T) (*SdJwtVcDcqlHandler, db.CredentialStore) {
	t.Helper()
	dsn := sqlcipher.DSN(":memory:", "test-key-123")
	d, err := gorm.Open(sqlcipher.Dialector{DSN: dsn}, &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, d.AutoMigrate(
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

	fs := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, t.TempDir())
	ts := &testStorage{db: d, fs: fs}
	credStore := db.NewCredentialStore(ts.Db())
	handler := &SdJwtVcDcqlHandler{
		storage:         ts,
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

// validTestSdJwtVc is a valid SD-JWT VC with typ "dc+sd-jwt", vct "test.test.email",
// and two disclosures: "email" ("test@gmail.com") and "domain" ("gmail.com").
// Copied from eudi/credentials/sdjwtvc/test_data.go (unexported).
const validTestSdJwtVc = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsIng1YyI6WyJNSUlEUERDQ0F1T2dBd0lCQWdJVWVLTzR0L2NOcGo2NTNNaVB6Vk4xL2U2azRKd3dDZ1lJS29aSXpqMEVBd0l3UVRFTE1Ba0dBMVVFQmhNQ1Rrd3hEVEFMQmdOVkJBb01CRmxwZG1reEl6QWhCZ05WQkFNTUdtOXdaVzVwWkRSMll5NXpkR0ZuYVc1bkxubHBkbWt1WVhCd01CNFhEVEkyTURFd09ERTFNemt3T1ZvWERUTTJNREV3TmpFMU16a3dPVm93UVRFTE1Ba0dBMVVFQmhNQ1Rrd3hEVEFMQmdOVkJBb01CRmxwZG1reEl6QWhCZ05WQkFNTUdtOXdaVzVwWkRSMll5NXpkR0ZuYVc1bkxubHBkbWt1WVhCd01Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVNyN2JNckRURGUrUi9ISTF3eXdZdEVZcitESmE1SGRUbkk4ZHNqWmVyNmdyUHlaNHZ4VGVPbWRqVTl3cDBXa3pmT05teWs0eHNQZVBvbjRBaHdDSythT0NBYmN3Z2dHek1Fa0dBMVVkRVFSQ01FQ0dJbWgwZEhCek9pOHZiM0JsYm1sa05IWmpMbk4wWVdkcGJtY3VlV2wyYVM1aGNIQ0NHbTl3Wlc1cFpEUjJZeTV6ZEdGbmFXNW5MbmxwZG1rdVlYQndNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3Q3dZRFZSMFBCQVFEQWdFR01JSUJKQVlEVVhzQkJJSUJHd3lDQVJkN0luSmxaMmx6ZEhKaGRHbHZiaUk2SW1oMGRIQnpPaTh2Y0c5eWRHRnNMbVJsZGk5dmNtZGhibWw2WVhScGIyNXpMM2xwZG1rdklpd2liM0puWVc1cGVtRjBhVzl1SWpwN0lteGxaMkZzVG1GdFpTSTZleUpsYmlJNklsbHBkbWtnUWk1V0xpSXNJbTVzSWpvaVdXbDJhU0JDTGxZdUluMTlMQ0poY0NJNmV5SmhkWFJvYjNKcGVtVmtJanBiZXlKamNtVmtaVzUwYVdGc0lqb2lkR1Z6ZEM1MFpYTjBMbVZ0WVdsc0lpd2lZWFIwY21saWRYUmxjeUk2V3lKbGJXRnBiQ0lzSUNKa2IyMWhhVzRpWFgwc0lIc2lZM0psWkdWdWRHbGhiQ0k2SW5SbGMzUXVkR1Z6ZEM1dGIySnBiR1Z3YUc5dVpTSXNJbUYwZEhKcFluVjBaWE1pT2xzaWJXOWlhV3hsY0dodmJtVWlYWDFkZlgwd0hRWURWUjBPQkJZRUZEUmFmeUU1YXpacTJrMkRMRGQ0NG8yRkppMTdNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJRHMwRkNsdEpaNEdtTDhCVEhRS05OUk10Tzd3MVFKUk15Yk11VzZETUI1UkFpQm1rNFRwbWRzZEl1UTFNOHp3YU14RHNDYkxoaW9QUWRRYWVSWk5OKzhzOVE9PSJdfQ.eyJfc2QiOlsiN0JHNnJ6SWpMdHdGNlI5ZlVhYndEV25GaURlcDNHVmF0UHc5Z09lc05nWSIsIjRKTkZMa1BiWXNmdjBWQ1kyeE1hTDZJbXhTcjZSZ0pZNG9uYWN4X0o2UFkiXSwiY25mIjp7Imp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkpENUVJNmlqT2k2OVd2WUdqVVd4Sm5nYlJEQndCd3NPRjdqMUVSRFdPSjQiLCJ5IjoiNjR1Z0ppcUhvcXRvdGRKZGE5UVVVVURzb3ZWWE9sU3R0eEdDZktNMXlxUSJ9fSwiZXhwIjoxOTQ1Mzk0MTI2LCJpYXQiOjE3NDUzOTQxMjYsImlzcyI6Imh0dHBzOi8vb3BlbmlkNHZjLnN0YWdpbmcueWl2aS5hcHAiLCJuYmYiOjUwLCJ2Y3QiOiJ0ZXN0LnRlc3QuZW1haWwifQ.b3LxuCTv4H3yxFduNNtpUTn89quju6A3NEk1rnrTv76fxilJKnsbMyt_CjoFiJtl6uZ38d5SpfF6M3UCr5gWyg~WyJTV1RJYWY2RjNiOENJMVQwbk1leTd3IiwiZW1haWwiLCJ0ZXN0QGdtYWlsLmNvbSJd~WyJmU21KeXR4Qk01Z3pCOWtXaHhDcG5nIiwiZG9tYWluIiwiZ21haWwuY29tIl0~"

// ========================================================================
// PrepareDisclosure — batch-of-1 vs batch-of-many
// ========================================================================

func TestPrepareDisclosure_BatchOfOne_RemainsUsableAfterDisclosure(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-batch1", "https://example.com/EmailCredential", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	batch.BatchSize = 1
	batch.RemainingCount = 1
	batch.Instances = []models.IssuedCredentialInstance{
		{RawCredential: []byte(validTestSdJwtVc)},
	}
	require.NoError(t, store.StoreBatch(batch))

	selections := []dcql.DisclosureSelection{{
		QueryId:        "q1",
		CredentialHash: "hash-batch1",
		ClaimPaths:     [][]any{{"email"}},
	}}

	// First disclosure should succeed.
	result, err := h.PrepareDisclosure(selections, "nonce1", "client1")
	require.NoError(t, err)
	require.Len(t, result.QueryResponses, 1)
	assert.NotEmpty(t, result.QueryResponses[0].Credentials)

	// Second disclosure should also succeed — the single instance must stay reusable.
	result2, err := h.PrepareDisclosure(selections, "nonce2", "client2")
	require.NoError(t, err, "batch-of-1 credential must remain usable after disclosure")
	require.Len(t, result2.QueryResponses, 1)
	assert.NotEmpty(t, result2.QueryResponses[0].Credentials)

	// RemainingCount must still be 1.
	reloaded, err := store.GetBatchByHash("hash-batch1")
	require.NoError(t, err)
	assert.Equal(t, uint(1), reloaded.RemainingCount)
}

func TestPrepareDisclosure_BatchOfTwo_MarksInstanceUsed(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-batch2", "https://example.com/EmailCredential", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	batch.BatchSize = 2
	batch.RemainingCount = 2
	batch.Instances = []models.IssuedCredentialInstance{
		{RawCredential: []byte(validTestSdJwtVc)},
		{RawCredential: []byte(validTestSdJwtVc)},
	}
	require.NoError(t, store.StoreBatch(batch))

	selections := []dcql.DisclosureSelection{{
		QueryId:        "q1",
		CredentialHash: "hash-batch2",
		ClaimPaths:     [][]any{{"email"}},
	}}

	// First disclosure — uses one instance.
	_, err := h.PrepareDisclosure(selections, "nonce1", "client1")
	require.NoError(t, err)

	reloaded, err := store.GetBatchByHash("hash-batch2")
	require.NoError(t, err)
	assert.Equal(t, uint(1), reloaded.RemainingCount)

	// Second disclosure — uses the last instance.
	_, err = h.PrepareDisclosure(selections, "nonce2", "client2")
	require.NoError(t, err)

	reloaded, err = store.GetBatchByHash("hash-batch2")
	require.NoError(t, err)
	assert.Equal(t, uint(0), reloaded.RemainingCount)

	// Third disclosure — no unused instances left, should fail.
	_, err = h.PrepareDisclosure(selections, "nonce3", "client3")
	require.Error(t, err, "batch-of-2 with all instances used should fail")
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
