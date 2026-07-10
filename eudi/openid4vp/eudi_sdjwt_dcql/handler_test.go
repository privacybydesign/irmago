package eudi_sdjwt_dcql

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
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
	d, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("test-key-123"))}, &gorm.Config{})
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

	fs := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir())
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
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
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

// TestFindCandidates_RevokedViaLiveCheck pins the IRMA-parity contract using a
// live Token Status List check: a revoked SD-JWT VC is NOT dropped or refused
// during planning. It still appears as an owned candidate carrying Revoked=true
// (read live from the status list), so the frontend can decide — the verifier's
// own status check is the backstop.
func TestFindCandidates_RevokedViaLiveCheck(t *testing.T) {
	h, store := newTestHandler(t)

	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example.com", // matches newTestBatch IssuerURL
		Bits:     1,
		Statuses: map[uint64]uint8{3: 1}, // idx 3 -> invalid (revoked)
	})
	h.statusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	batch := newTestBatch("hash-revoked", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	uri := srv.URL()
	idx := uint64(3)
	batch.Instances[0].StatusListURI = &uri
	batch.Instances[0].StatusListIdx = &idx
	// Stored status is deliberately left Valid so a green assertion proves the
	// live check (not the stored value) drove Revoked=true.
	batch.Instances[0].LastKnownStatus = uint8(statuslist.StatusValid)
	require.NoError(t, store.StoreBatch(batch))

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1, "revoked credential must still be offered, not dropped")
	assert.True(t, result.OwnedCandidates[0].Revoked, "live check reads the bit as invalid -> Revoked")
	assert.True(t, result.OwnedCandidates[0].RevocationSupported)
}

// TestFindCandidates_ValidViaLiveCheck: a live check reading StatusValid leaves
// the candidate not revoked, even though the stored status is Invalid — proving
// the live value (respecting the token's own ttl) overrides the stored one.
func TestFindCandidates_ValidViaLiveCheck(t *testing.T) {
	h, store := newTestHandler(t)

	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example.com",
		Bits:     1,
		Statuses: map[uint64]uint8{3: 0}, // idx 3 -> valid
	})
	h.statusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	batch := newTestBatch("hash-valid-live", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	uri := srv.URL()
	idx := uint64(3)
	batch.Instances[0].StatusListURI = &uri
	batch.Instances[0].StatusListIdx = &idx
	batch.Instances[0].LastKnownStatus = uint8(statuslist.StatusInvalid) // overridden by live check
	require.NoError(t, store.StoreBatch(batch))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	assert.False(t, result.OwnedCandidates[0].Revoked, "live StatusValid -> not revoked")
	assert.True(t, result.OwnedCandidates[0].RevocationSupported)
}

// TestFindCandidates_LiveCheckFails_FailsSafeRevoked: when the status list can't
// be checked and no in-ttl cached value remains, the candidate is treated as
// revoked. A stored status is NOT trusted past the token's own ttl (we do not
// use a blanket TTLMax).
func TestFindCandidates_LiveCheckFails_FailsSafeRevoked(t *testing.T) {
	h, store := newTestHandler(t)

	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer: "https://issuer.example.com", Bits: 1, Statuses: map[uint64]uint8{3: 0},
	})
	srv.SetBody([]byte("not-a-status-list-jwt")) // fetch succeeds, verify fails -> Check errors
	h.statusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache()) // empty cache -> Check must fetch

	batch := newTestBatch("hash-live-fail", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	uri := srv.URL()
	idx := uint64(3)
	batch.Instances[0].StatusListURI = &uri
	batch.Instances[0].StatusListIdx = &idx
	// Stored status Valid and freshly checked: must NOT be trusted, because the
	// live check failed and there is no in-ttl cached token to fall back to.
	now := time.Now()
	batch.Instances[0].LastKnownStatus = uint8(statuslist.StatusValid)
	batch.Instances[0].LastStatusCheckAt = &now
	require.NoError(t, store.StoreBatch(batch))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	assert.True(t, result.OwnedCandidates[0].Revoked, "no in-ttl status -> fail-safe revoked")
}

// TestFindCandidates_NoChecker_UsesStoredStatus: with no checker wired, the flag
// reflects the last stored status (best effort).
func TestFindCandidates_NoChecker_UsesStoredStatus(t *testing.T) {
	h, store := newTestHandler(t) // no statusChecker

	batch := newTestBatch("hash-nochecker", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	uri := "https://issuer.example.com/statuslist"
	idx := uint64(7)
	batch.Instances[0].StatusListURI = &uri
	batch.Instances[0].StatusListIdx = &idx
	batch.Instances[0].LastKnownStatus = uint8(statuslist.StatusInvalid)
	require.NoError(t, store.StoreBatch(batch))

	result, err := h.FindCandidates(parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/EmailCredential"]},
		"claims": [{"path": ["email"]}]
	}`))
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	assert.True(t, result.OwnedCandidates[0].Revoked, "stored StatusInvalid surfaces when no checker")
}

// TestFindCandidates_RegionalLocale_KeyedByBaseLanguage pins the contract
// that issuer name, credential name, and claim display name on OpenID4VP
// disclosure candidates are keyed by BCP 47 base language — the same
// reduction the issuance permission dialog applies via
// metadata.ConvertDisplayToTranslatedString. Without this, an issuer
// (or VCT) that advertises display under "en-US" shows correctly during
// issuance but appears under "en-US" rather than "en" at disclosure
// time, so a wallet UI looking up by base language loses the name.
func TestFindCandidates_RegionalLocale_KeyedByBaseLanguage(t *testing.T) {
	h, store := newTestHandler(t)

	batch := newTestBatch("hash-regional", "https://example.com/EmailCredential", map[string]any{
		"email": "test@example.com",
	})
	batch.ExpiresAt = datatypes.NullTime{V: time.Now().Add(24 * time.Hour), Valid: true}
	batch.IssuerDisplay = []models.IssuerMetadataDisplay{
		{Name: "Example Issuer", Locale: datatypes.NullString{V: "en-US", Valid: true}},
	}
	batch.CredentialMetadata = &models.CredentialMetadata{
		Display: []models.CredentialDisplay{
			{Name: "Email Credential", Locale: datatypes.NullString{V: "en-US", Valid: true}},
		},
		Claims: []models.CredentialClaim{
			{
				Path: datatypes.JSON(`["email"]`),
				Display: []models.ClaimDisplay{
					{Name: "Email", Locale: datatypes.NullString{V: "en-US", Valid: true}},
				},
			},
		},
	}
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

	cand := result.OwnedCandidates[0]
	assert.Equal(t, "Example Issuer", cand.Issuer.Name["en"], "issuer name must collapse en-US to en")
	assert.Equal(t, "Email Credential", cand.Name["en"], "credential name must collapse en-US to en")
	require.NotEmpty(t, cand.Attributes)
	require.NotNil(t, cand.Attributes[0].DisplayName)
	assert.Equal(t, "Email", (*cand.Attributes[0].DisplayName)["en"], "claim display must collapse en-US to en")
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
	assert.Equal(t, expiryTime.Unix(), *result.OwnedCandidates[0].ExpiryDate,
		"ExpiryDate should match ExpiresAt, not IssuedAt")
}

// ========================================================================
// composeUnobtainableDescriptor — VCT/issuer fetch failure cascade
// ========================================================================

// stubVctFetcher returns canned VctTypeMetadata or errors keyed by VCT URL.
type stubVctFetcher struct {
	docs map[string]*typemetadata.VctTypeMetadata
	errs map[string]error
}

func (s *stubVctFetcher) Fetch(_ context.Context, vctURL string) (*typemetadata.VctTypeMetadata, error) {
	if err, ok := s.errs[vctURL]; ok {
		return nil, err
	}
	if doc, ok := s.docs[vctURL]; ok {
		return doc, nil
	}
	return nil, errors.New("not found")
}

// stubIssuerFetcher returns canned IssuerMetadata or errors keyed by issuer URL.
type stubIssuerFetcher struct {
	docs map[string]*typemetadata.IssuerMetadata
	errs map[string]error
}

func (s *stubIssuerFetcher) Fetch(_ context.Context, issuerURL string) (*typemetadata.IssuerMetadata, error) {
	if err, ok := s.errs[issuerURL]; ok {
		return nil, err
	}
	if doc, ok := s.docs[issuerURL]; ok {
		return doc, nil
	}
	return nil, errors.New("not found")
}

func newHandlerWithFetchers(vct typemetadata.VctFetcher, issuer typemetadata.IssuerFetcher) *SdJwtVcDcqlHandler {
	return &SdJwtVcDcqlHandler{vctFetcher: vct, issuerFetcher: issuer}
}

func TestComposeUnobtainableDescriptor_VctFetchFails_UrlOnlyFallback(t *testing.T) {
	vctFetcher := &stubVctFetcher{errs: map[string]error{
		"https://example.com/vct/missing": errors.New("404"),
	}}
	h := newHandlerWithFetchers(vctFetcher, nil)
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/missing"]},
		"claims": [{"path": ["email"]}]
	}`)

	desc := h.composeUnobtainableDescriptor(query)
	require.NotNil(t, desc)
	assert.Equal(t, "https://example.com/vct/missing", desc.CredentialId)
	assert.Empty(t, desc.Name, "no Name when VCT fetch fails")
	assert.Empty(t, desc.Issuer.Id, "no Issuer when VCT fetch fails")
	assert.Nil(t, desc.IssueURL, "IssueURL signals unobtainable")
	require.Len(t, desc.Attributes, 1)
	assert.Equal(t, []any{"email"}, desc.Attributes[0].ClaimPath)
}

func TestComposeUnobtainableDescriptor_VctOk_NoIssuerField(t *testing.T) {
	vctFetcher := &stubVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{
		"https://example.com/vct/email": {
			Name:    "Email Credential",
			Display: []typemetadata.DisplayEntry{{Locale: "en", Name: "Email Credential"}},
			Claims: []typemetadata.ClaimMetadata{
				{Path: []any{"email"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: "en", Name: "Email"}}},
			},
		},
	}}
	h := newHandlerWithFetchers(vctFetcher, nil)
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/email"]},
		"claims": [{"path": ["email"]}]
	}`)

	desc := h.composeUnobtainableDescriptor(query)
	require.NotNil(t, desc)
	assert.Equal(t, "https://example.com/vct/email", desc.CredentialId)
	assert.Equal(t, "Email Credential", desc.Name["en"])
	assert.Empty(t, desc.Issuer.Id, "no issuer URL means no TrustedParty")
	assert.Nil(t, desc.IssueURL)
	require.Len(t, desc.Attributes, 1)
	assert.Equal(t, "Email", (*desc.Attributes[0].DisplayName)["en"], "claim display from VCT metadata")
}

func TestComposeUnobtainableDescriptor_VctOk_IssuerFetchFails(t *testing.T) {
	vctFetcher := &stubVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{
		"https://example.com/vct/email": {
			Name:      "Email Credential",
			IssuerURL: "https://issuer.example.com",
		},
	}}
	issuerFetcher := &stubIssuerFetcher{errs: map[string]error{
		"https://issuer.example.com": errors.New("500"),
	}}
	h := newHandlerWithFetchers(vctFetcher, issuerFetcher)
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/email"]},
		"claims": [{"path": ["email"]}]
	}`)

	desc := h.composeUnobtainableDescriptor(query)
	require.NotNil(t, desc)
	assert.Equal(t, "https://issuer.example.com", desc.Issuer.Id, "Issuer.Id from VCT even when issuer fetch fails")
	assert.Empty(t, desc.Issuer.Name, "no localized issuer Name when issuer fetch fails")
	assert.Nil(t, desc.IssueURL)
}

func TestComposeUnobtainableDescriptor_VctAndIssuerOk(t *testing.T) {
	vctFetcher := &stubVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{
		"https://example.com/vct/email": {
			Name:      "Email Credential",
			Display:   []typemetadata.DisplayEntry{{Locale: "en", Name: "Email Credential"}},
			IssuerURL: "https://issuer.example.com",
			Claims: []typemetadata.ClaimMetadata{
				{Path: []any{"email"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: "en", Name: "Email"}}},
			},
		},
	}}
	issuerFetcher := &stubIssuerFetcher{docs: map[string]*typemetadata.IssuerMetadata{
		"https://issuer.example.com": {
			Id:   "https://issuer.example.com",
			Name: clientmodels.TranslatedString{"en": "Example Issuer"},
		},
	}}
	h := newHandlerWithFetchers(vctFetcher, issuerFetcher)
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/email"]},
		"claims": [{"path": ["email"]}]
	}`)

	desc := h.composeUnobtainableDescriptor(query)
	require.NotNil(t, desc)
	assert.Equal(t, "Email Credential", desc.Name["en"])
	assert.Equal(t, "https://issuer.example.com", desc.Issuer.Id)
	assert.Equal(t, "Example Issuer", desc.Issuer.Name["en"])
	assert.Nil(t, desc.IssueURL)
}

func TestComposeUnobtainableDescriptor_MultiVct_FirstFailsSecondSucceeds(t *testing.T) {
	vctFetcher := &stubVctFetcher{
		errs: map[string]error{
			"https://example.com/vct/bad": errors.New("404"),
		},
		docs: map[string]*typemetadata.VctTypeMetadata{
			"https://example.com/vct/good": {
				Name:    "Good Credential",
				Display: []typemetadata.DisplayEntry{{Locale: "en", Name: "Good Credential"}},
			},
		},
	}
	h := newHandlerWithFetchers(vctFetcher, nil)
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/bad", "https://example.com/vct/good"]},
		"claims": [{"path": ["email"]}]
	}`)

	desc := h.composeUnobtainableDescriptor(query)
	require.NotNil(t, desc)
	assert.Equal(t, "https://example.com/vct/good", desc.CredentialId, "should pick the first VCT whose fetch succeeded")
	assert.Equal(t, "Good Credential", desc.Name["en"])
}

func TestComposeUnobtainableDescriptor_MultiVct_AllFail_UrlOnlyForFirst(t *testing.T) {
	vctFetcher := &stubVctFetcher{errs: map[string]error{
		"https://example.com/vct/bad1": errors.New("404"),
		"https://example.com/vct/bad2": errors.New("500"),
	}}
	h := newHandlerWithFetchers(vctFetcher, nil)
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/bad1", "https://example.com/vct/bad2"]},
		"claims": [{"path": ["email"]}]
	}`)

	desc := h.composeUnobtainableDescriptor(query)
	require.NotNil(t, desc)
	assert.Equal(t, "https://example.com/vct/bad1", desc.CredentialId, "URL-only fallback uses the first VCT")
	assert.Empty(t, desc.Name)
	assert.Empty(t, desc.Issuer.Id)
}

func TestComposeUnobtainableDescriptor_NoVctValues_ReturnsNil(t *testing.T) {
	h := newHandlerWithFetchers(&stubVctFetcher{}, nil)
	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {},
		"claims": [{"path": ["email"]}]
	}`)
	desc := h.composeUnobtainableDescriptor(query)
	assert.Nil(t, desc, "without vct_values there is no missing credential to describe")
}

func TestFindCandidates_NoBatches_AppendsUnobtainableDescriptor(t *testing.T) {
	h, _ := newTestHandler(t)
	h.vctFetcher = &stubVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{
		"https://example.com/vct/email": {
			Name:    "Email Credential",
			Display: []typemetadata.DisplayEntry{{Locale: "en", Name: "Email Credential"}},
		},
	}}

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/email"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 1)
	assert.Equal(t, "https://example.com/vct/email", result.ObtainableDescriptors[0].CredentialId)
	assert.Nil(t, result.ObtainableDescriptors[0].IssueURL, "IssueURL is the unobtainable signal")
}

func TestFindCandidates_NoBatches_NilFetcher_NoDescriptor(t *testing.T) {
	h, _ := newTestHandler(t)
	// h.vctFetcher intentionally left nil

	query := parseDcqlQuery(t, `{
		"id": "q1",
		"format": "dc+sd-jwt",
		"meta": {"vct_values": ["https://example.com/vct/email"]},
		"claims": [{"path": ["email"]}]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates)
	assert.Empty(t, result.ObtainableDescriptors, "no fetcher means no descriptor (preserves old behaviour)")
}

func TestIsIrmaStyleVct(t *testing.T) {
	cases := []struct {
		vct  string
		want bool
	}{
		{"test.test.email", true},                 // 3 non-empty dot segments — IRMA shape
		{"pbdf.sidn-pbdf.irma", true},             // hyphens are fine inside segments
		{"test.test", false},                      // only 2 segments
		{"test.test.email.extra", false},          // 4 segments
		{"test..email", false},                    // empty middle segment
		{".test.email", false},                    // empty leading segment
		{"test.test.", false},                     // empty trailing segment
		{"urn:eudi:pid:1", false},                 // URN — colons rule out IRMA shape
		{"https://issuer.example.com/foo", false}, // URL with slashes and colons
		{"a.b:c.d", false},                        // a colon anywhere disqualifies
		{"", false},                               // empty string
	}
	for _, c := range cases {
		assert.Equal(t, c.want, isIrmaStyleVct(c.vct), "vct=%q", c.vct)
	}
}

func TestCanHandleCredentialQuery(t *testing.T) {
	h := &SdJwtVcDcqlHandler{}

	mkQuery := func(format string, vcts ...string) dcql.CredentialQuery {
		q := dcql.CredentialQuery{Format: format}
		if vcts != nil {
			q.Meta = &dcql.Meta{VctValues: vcts}
		}
		return q
	}

	cases := []struct {
		name  string
		query dcql.CredentialQuery
		want  bool
	}{
		{"urn vct routes to EUDI", mkQuery("dc+sd-jwt", "urn:eudi:pid:1"), true},
		{"https url vct routes to EUDI", mkQuery("dc+sd-jwt", "https://example.com/foo"), true},
		{"IRMA-style vct does NOT route to EUDI", mkQuery("dc+sd-jwt", "test.test.email"), false},
		{"no vct_values still routes to EUDI", mkQuery("dc+sd-jwt"), true},
		{"vc+sd-jwt also handled", mkQuery("vc+sd-jwt", "urn:eudi:pid:1"), true},
		{"non-sd-jwt format rejected", mkQuery("mso_mdoc", "urn:eudi:pid:1"), false},
		{"mixed list with one non-IRMA value routes to EUDI", mkQuery("dc+sd-jwt", "test.test.email", "urn:eudi:pid:1"), true},
		{"all IRMA-style values rejected", mkQuery("dc+sd-jwt", "test.test.email", "test.test.mobilephone"), false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, h.CanHandleCredentialQuery(c.query), c.name)
	}
}

func TestIsHttpVct(t *testing.T) {
	cases := []struct {
		vct  string
		want bool
	}{
		{"https://issuer.example.com/vct/pid", true},
		{"http://localhost:8080/vct", true},
		{"urn:eudi:pid:1", false},
		{"test.test.email", false},
		{"", false},
		{"https://", true}, // structurally a URL prefix; fetcher will fail downstream, no warning concern
	}
	for _, c := range cases {
		assert.Equal(t, c.want, isHttpVct(c.vct), "vct=%q", c.vct)
	}
}
