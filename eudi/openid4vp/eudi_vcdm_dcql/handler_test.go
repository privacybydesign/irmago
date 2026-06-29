package eudi_vcdm_dcql

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

func jwtVcWithPayload(t *testing.T, payload map[string]any) string {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return "header." + encodedPayload + ".signature"
}

func splitHolderBoundPresentation(t *testing.T, presentation string) (string, string) {
	t.Helper()
	parts := strings.SplitN(presentation, "~", 2)
	require.Len(t, parts, 2)
	require.NotEmpty(t, parts[0])
	require.NotEmpty(t, parts[1])
	return parts[0], parts[1]
}

func mustNewHolderBindingFixture(t *testing.T) (map[string]any, string, sdjwtvc.KeyBinder) {
	t.Helper()
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	doc, err := (&didjwk.DocumentBuilder{}).FromJwk(keys[0])
	require.NoError(t, err)
	require.NotEmpty(t, doc.ID)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var keyMap map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &keyMap))
	return keyMap, doc.ID + "#0", binder
}

type mockCredentialStore struct {
	batches []*models.CredentialBatch
	err     error
}

type mockHolderBindingKeyStore struct {
	byThumbprint map[string]*models.HolderBindingKey
}

func (m *mockHolderBindingKeyStore) StoreKey(key *models.HolderBindingKey) error    { return nil }
func (m *mockHolderBindingKeyStore) StoreKeys(keys []models.HolderBindingKey) error { return nil }
func (m *mockHolderBindingKeyStore) GetByID(id datatypes.UUID) (*models.HolderBindingKey, error) {
	return nil, db.ErrNotFound
}
func (m *mockHolderBindingKeyStore) GetByDidUrl(didUrl string) (*models.HolderBindingKey, error) {
	return nil, db.ErrNotFound
}
func (m *mockHolderBindingKeyStore) LinkToInstance(keyID datatypes.UUID, instanceID datatypes.UUID) error {
	return nil
}
func (m *mockHolderBindingKeyStore) DeleteKey(id datatypes.UUID) error     { return nil }
func (m *mockHolderBindingKeyStore) DeleteKeys(ids []datatypes.UUID) error { return nil }
func (m *mockHolderBindingKeyStore) DeleteAll() error                      { return nil }
func (m *mockHolderBindingKeyStore) GetByThumbprint(thumbprint string) (*models.HolderBindingKey, error) {
	if key, ok := m.byThumbprint[thumbprint]; ok {
		return key, nil
	}
	return nil, db.ErrNotFound
}

func mustJktFromJwk(t *testing.T, holderJwk map[string]any) string {
	t.Helper()
	keyJSON, err := json.Marshal(holderJwk)
	require.NoError(t, err)
	key, err := jwk.ParseKey(keyJSON)
	require.NoError(t, err)
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(thumbprint)
}

func (m *mockCredentialStore) StoreBatch(batch *models.CredentialBatch) error {
	return nil
}

func (m *mockCredentialStore) GetCredentialBatchList() ([]*models.CredentialBatch, error) {
	return m.batches, m.err
}

func (m *mockCredentialStore) GetBatchByHash(hash string) (*models.CredentialBatch, error) {
	for _, b := range m.batches {
		if b.Hash == hash {
			return b, nil
		}
	}
	return nil, db.ErrNotFound
}

func (m *mockCredentialStore) GetBatchesByCredentialType(credentialType string) ([]*models.CredentialBatch, error) {
	return nil, nil
}

func (m *mockCredentialStore) GetBatchesByCredentialTypeAndFormat(credentialType string, format models.CredentialFormat) ([]*models.CredentialBatch, error) {
	return nil, nil
}

func (m *mockCredentialStore) GetBatchesByVCT(credentialType string) ([]*models.CredentialBatch, error) {
	return nil, nil
}

func (m *mockCredentialStore) GetUnusedInstance(batchID datatypes.UUID) (*models.IssuedCredentialInstance, error) {
	for _, b := range m.batches {
		if b.ID == batchID {
			for i := range b.Instances {
				if !b.Instances[i].Used {
					return &b.Instances[i], nil
				}
			}
			return nil, db.ErrNotFound
		}
	}
	return nil, db.ErrNotFound
}

func (m *mockCredentialStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	for _, b := range m.batches {
		for i := range b.Instances {
			if b.Instances[i].ID == instanceID {
				if b.Instances[i].Used {
					return db.ErrNotFound
				}
				b.Instances[i].Used = true
				if b.RemainingCount > 0 {
					b.RemainingCount--
				}
				return nil
			}
		}
	}
	return db.ErrNotFound
}

func (m *mockCredentialStore) DeleteBatch(batchID datatypes.UUID) error {
	return nil
}

func (m *mockCredentialStore) DeleteBatchByHash(hash string) error {
	return nil
}

func TestCanHandleCredentialQuery(t *testing.T) {
	h := NewVcdmDcqlHandlerWithStore(&mockCredentialStore{})

	assert.True(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{Format: string(models.CredentialFormatW3CVC)}))
	assert.False(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{Format: string(models.CredentialFormatSdJwtVc)}))
}

func TestFindCandidates_MixedFormats_OnlyW3CVCIncluded(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	h := NewVcdmDcqlHandlerWithStore(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			CredentialType:  "https://example.com/EmailCredential",
			Format:          models.CredentialFormatW3CVC,
			Hash:            "jwt-hash",
			ProcessedClaims: datatypes.JSON(`{"email":"alice@example.com","age":30}`),
			IssuanceDate:    datatypes.NullTime{V: now, Valid: true},
			BatchSize:       1,
			RemainingCount:  1,
		},
		{
			CredentialType:  "https://example.com/EmailCredential",
			Format:          models.CredentialFormatSdJwtVc,
			Hash:            "sd-hash",
			ProcessedClaims: datatypes.JSON(`{"email":"bob@example.com"}`),
			IssuanceDate:    datatypes.NullTime{V: now, Valid: true},
			BatchSize:       1,
			RemainingCount:  1,
		},
	}})

	query := dcql.CredentialQuery{
		Id:     "q1",
		Format: string(models.CredentialFormatW3CVC),
		Meta:   &dcql.Meta{VctValues: []string{"https://example.com/EmailCredential"}},
	}

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	assert.Equal(t, "jwt-hash", result.OwnedCandidates[0].Hash)
	assert.Equal(t, "https://example.com/EmailCredential", result.OwnedCandidates[0].CredentialId)
	assert.Equal(t, "jwt_vc_json", string(result.OwnedCandidates[0].Format))
}

func TestFindCandidates_ClaimValueFiltering(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	h := NewVcdmDcqlHandlerWithStore(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			CredentialType:  "https://example.com/EmailCredential",
			Format:          models.CredentialFormatW3CVC,
			Hash:            "jwt-hash",
			ProcessedClaims: datatypes.JSON(`{"email":"alice@example.com","age":30}`),
			IssuanceDate:    datatypes.NullTime{V: now, Valid: true},
			BatchSize:       1,
			RemainingCount:  1,
		},
	}})

	query := dcql.CredentialQuery{
		Id:     "q1",
		Format: string(models.CredentialFormatW3CVC),
		Claims: []dcql.Claim{
			{Path: []any{"email"}, Values: []any{"alice@example.com"}},
			{Path: []any{"age"}, Values: []any{30}},
		},
	}

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	require.Len(t, result.OwnedCandidates, 1)
	require.Len(t, result.OwnedCandidates[0].Attributes, 2)
}

func TestFindCandidates_ExcludesExpiredAndExhausted(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	h := NewVcdmDcqlHandlerWithStore(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			CredentialType:  "https://example.com/EmailCredential",
			Format:          models.CredentialFormatW3CVC,
			Hash:            "expired",
			ProcessedClaims: datatypes.JSON(`{"email":"alice@example.com"}`),
			IssuanceDate:    datatypes.NullTime{V: now, Valid: true},
			ExpiresAt:       datatypes.NullTime{V: now.Add(-1 * time.Hour), Valid: true},
			BatchSize:       1,
			RemainingCount:  1,
		},
		{
			CredentialType:  "https://example.com/EmailCredential",
			Format:          models.CredentialFormatW3CVC,
			Hash:            "exhausted",
			ProcessedClaims: datatypes.JSON(`{"email":"alice@example.com"}`),
			IssuanceDate:    datatypes.NullTime{V: now, Valid: true},
			BatchSize:       2,
			RemainingCount:  0,
		},
	}})

	query := dcql.CredentialQuery{
		Id:     "q1",
		Format: string(models.CredentialFormatW3CVC),
	}

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	assert.Empty(t, result.OwnedCandidates)
}

func TestPrepareDisclosure_ReturnsRawCredentialAndLog(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batchID := datatypes.NewUUIDv4()
	instanceID := datatypes.NewUUIDv4()
	h := NewVcdmDcqlHandlerWithStore(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			ID:               batchID,
			CredentialType:   "https://example.com/EmailCredential",
			Format:           models.CredentialFormatW3CVC,
			Hash:             "jwt-hash",
			ProcessedClaims:  datatypes.JSON(`{"email":"alice@example.com","age":30}`),
			IssuanceDate:     datatypes.NullTime{V: now, Valid: true},
			BatchSize:        1,
			RemainingCount:   1,
			CredentialIssuer: "https://issuer.example.com",
			Instances: []models.IssuedCredentialInstance{
				{ID: instanceID, CredentialBatchID: batchID, RawCredential: []byte("header.payload.signature")},
			},
		},
	}})

	prepared, err := h.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:        "q1",
		CredentialHash: "jwt-hash",
		ClaimPaths:     [][]any{{"email"}},
	}}, "nonce", "client")

	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
	assert.Equal(t, "q1", prepared.QueryResponses[0].QueryId)
	assert.Equal(t, []string{"header.payload.signature"}, prepared.QueryResponses[0].Credentials)

	require.Len(t, prepared.CredentialLogs, 1)
	assert.Equal(t, "https://example.com/EmailCredential", prepared.CredentialLogs[0].CredentialId)
	require.Len(t, prepared.CredentialLogs[0].Attributes, 1)
	assert.Equal(t, []any{"email"}, prepared.CredentialLogs[0].Attributes[0].ClaimPath)
}

func TestPrepareDisclosure_HolderBindingRequired_WithCnf_ReturnsCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batchID := datatypes.NewUUIDv4()
	instanceID := datatypes.NewUUIDv4()
	holderJwk, _, binder := mustNewHolderBindingFixture(t)
	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})
	h := NewVcdmDcqlHandlerWithStoreAndKeyBinder(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			ID:               batchID,
			CredentialType:   "https://example.com/EmailCredential",
			Format:           models.CredentialFormatW3CVC,
			Hash:             "jwt-hash",
			ProcessedClaims:  datatypes.JSON(`{"email":"alice@example.com"}`),
			IssuanceDate:     datatypes.NullTime{V: now, Valid: true},
			BatchSize:        1,
			RemainingCount:   1,
			CredentialIssuer: "https://issuer.example.com",
			Instances: []models.IssuedCredentialInstance{
				{ID: instanceID, CredentialBatchID: batchID, RawCredential: []byte(rawCredential)},
			},
		},
	}}, binder)

	prepared, err := h.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "q1",
		CredentialHash:       "jwt-hash",
		ClaimPaths:           [][]any{{"email"}},
		RequireHolderBinding: true,
	}}, "nonce", "client")

	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
	credentialPart, kbjwtPart := splitHolderBoundPresentation(t, prepared.QueryResponses[0].Credentials[0])
	assert.Equal(t, rawCredential, credentialPart)
	assert.NotEmpty(t, kbjwtPart)
}

func TestPrepareDisclosure_HolderBindingRequired_WithoutCnf_ReturnsError(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batchID := datatypes.NewUUIDv4()
	instanceID := datatypes.NewUUIDv4()
	rawCredential := jwtVcWithPayload(t, map[string]any{"email": "alice@example.com"})
	h := NewVcdmDcqlHandlerWithStore(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			ID:               batchID,
			CredentialType:   "https://example.com/EmailCredential",
			Format:           models.CredentialFormatW3CVC,
			Hash:             "jwt-hash",
			ProcessedClaims:  datatypes.JSON(`{"email":"alice@example.com"}`),
			IssuanceDate:     datatypes.NullTime{V: now, Valid: true},
			BatchSize:        1,
			RemainingCount:   1,
			CredentialIssuer: "https://issuer.example.com",
			Instances: []models.IssuedCredentialInstance{
				{ID: instanceID, CredentialBatchID: batchID, RawCredential: []byte(rawCredential)},
			},
		},
	}})

	_, err := h.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "q1",
		CredentialHash:       "jwt-hash",
		ClaimPaths:           [][]any{{"email"}},
		RequireHolderBinding: true,
	}}, "nonce", "client")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "holder binding required")
}

func TestPrepareDisclosure_HolderBindingOptional_WithoutCnf_ReturnsCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batchID := datatypes.NewUUIDv4()
	instanceID := datatypes.NewUUIDv4()
	rawCredential := jwtVcWithPayload(t, map[string]any{"email": "alice@example.com"})
	h := NewVcdmDcqlHandlerWithStore(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			ID:               batchID,
			CredentialType:   "https://example.com/EmailCredential",
			Format:           models.CredentialFormatW3CVC,
			Hash:             "jwt-hash",
			ProcessedClaims:  datatypes.JSON(`{"email":"alice@example.com"}`),
			IssuanceDate:     datatypes.NullTime{V: now, Valid: true},
			BatchSize:        1,
			RemainingCount:   1,
			CredentialIssuer: "https://issuer.example.com",
			Instances: []models.IssuedCredentialInstance{
				{ID: instanceID, CredentialBatchID: batchID, RawCredential: []byte(rawCredential)},
			},
		},
	}})

	prepared, err := h.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "q1",
		CredentialHash:       "jwt-hash",
		ClaimPaths:           [][]any{{"email"}},
		RequireHolderBinding: false,
	}}, "nonce", "client")

	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
	assert.Equal(t, []string{rawCredential}, prepared.QueryResponses[0].Credentials)
}

func TestPrepareDisclosure_HolderBindingRequired_WithCnfKid_ReturnsCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batchID := datatypes.NewUUIDv4()
	instanceID := datatypes.NewUUIDv4()
	_, holderKid, binder := mustNewHolderBindingFixture(t)
	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"kid": holderKid,
		},
	})
	h := NewVcdmDcqlHandlerWithStoreAndKeyBinder(&mockCredentialStore{batches: []*models.CredentialBatch{
		{
			ID:               batchID,
			CredentialType:   "https://example.com/EmailCredential",
			Format:           models.CredentialFormatW3CVC,
			Hash:             "jwt-hash",
			ProcessedClaims:  datatypes.JSON(`{"email":"alice@example.com"}`),
			IssuanceDate:     datatypes.NullTime{V: now, Valid: true},
			BatchSize:        1,
			RemainingCount:   1,
			CredentialIssuer: "https://issuer.example.com",
			Instances: []models.IssuedCredentialInstance{
				{ID: instanceID, CredentialBatchID: batchID, RawCredential: []byte(rawCredential)},
			},
		},
	}}, binder)

	prepared, err := h.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:              "q1",
		CredentialHash:       "jwt-hash",
		ClaimPaths:           [][]any{{"email"}},
		RequireHolderBinding: true,
	}}, "nonce", "client")

	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
	credentialPart, kbjwtPart := splitHolderBoundPresentation(t, prepared.QueryResponses[0].Credentials[0])
	assert.Equal(t, rawCredential, credentialPart)
	assert.NotEmpty(t, kbjwtPart)
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnAudienceMismatch(t *testing.T) {
	holderJwk, _, binder := mustNewHolderBindingFixture(t)
	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})
	h := NewVcdmDcqlHandlerWithStoreAndKeyBinder(&mockCredentialStore{}, binder)
	presentation, err := createHolderBoundJwtVcPresentation(rawCredential, "nonce", "client-a", h.keyBinder, h.resolveHolderKeyFromJkt)
	require.NoError(t, err)

	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client-b", h.resolveHolderKeyFromJkt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience mismatch")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnNonceMismatch(t *testing.T) {
	holderJwk, _, binder := mustNewHolderBindingFixture(t)
	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})
	h := NewVcdmDcqlHandlerWithStoreAndKeyBinder(&mockCredentialStore{}, binder)
	presentation, err := createHolderBoundJwtVcPresentation(rawCredential, "nonce-a", "client", h.keyBinder, h.resolveHolderKeyFromJkt)
	require.NoError(t, err)

	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce-b", "client", h.resolveHolderKeyFromJkt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnCredentialTamper(t *testing.T) {
	holderJwk, _, binder := mustNewHolderBindingFixture(t)
	originalRawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})
	h := NewVcdmDcqlHandlerWithStoreAndKeyBinder(&mockCredentialStore{}, binder)
	presentation, err := createHolderBoundJwtVcPresentation(originalRawCredential, "nonce", "client", h.keyBinder, h.resolveHolderKeyFromJkt)
	require.NoError(t, err)

	tamperedRawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "mallory@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})
	_, kbjwt := splitHolderBoundPresentation(t, presentation)
	tamperedPresentation := tamperedRawCredential + "~" + kbjwt

	err = verifyHolderBoundJwtVcPresentation(tamperedPresentation, "nonce", "client", h.resolveHolderKeyFromJkt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sd_hash mismatch")
}

func TestCreateHolderBoundJwtVcPresentation_WithCnfJkt_ReturnsPresentation(t *testing.T) {
	holderJwk, _, binder := mustNewHolderBindingFixture(t)
	jkt := mustJktFromJwk(t, holderJwk)

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jkt": jkt,
		},
	})

	resolver := func(gotJkt string) (jwk.Key, error) {
		if gotJkt != jkt {
			return nil, assert.AnError
		}
		keyJSON, err := json.Marshal(holderJwk)
		if err != nil {
			return nil, err
		}
		return jwk.ParseKey(keyJSON)
	}

	presentation, err := createHolderBoundJwtVcPresentation(rawCredential, "nonce", "client", binder, resolver)
	require.NoError(t, err)

	credentialPart, kbjwtPart := splitHolderBoundPresentation(t, presentation)
	assert.Equal(t, rawCredential, credentialPart)
	assert.NotEmpty(t, kbjwtPart)

	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", resolver)
	require.NoError(t, err)
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnIssuedAtInFuture(t *testing.T) {
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var holderJwk map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &holderJwk))

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	hash, err := sdjwtvc.CreateUrlEncodedHash("sha-256", rawCredential)
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJwk, err := jwk.Import(privKey)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)

	// Build a kbjwt signed by matching key, but with iat far in the future.
	claims := map[string]any{
		"nonce":   "nonce",
		"aud":     "client",
		"sd_hash": hash,
		"iat":     time.Now().Unix() + sdjwtvc.ClockSkewInSeconds + 60,
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtCreator := sdjwtvc.NewJwtCreator(privKey)
	kbjwt, err := jwtCreator.CreateSignedJwt(map[string]any{"typ": sdjwtvc.KbJwtTyp}, string(claimsJSON))
	require.NoError(t, err)

	// Ensure cnf contains the same pub key as kbjwt signer.
	pubKeyJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubKeyJSON, &holderJwk))
	rawCredential = jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	presentation := rawCredential + "~" + kbjwt
	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issued-at is in the future")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnMissingIssuedAt(t *testing.T) {
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var holderJwk map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &holderJwk))

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	hash, err := sdjwtvc.CreateUrlEncodedHash("sha-256", rawCredential)
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJwk, err := jwk.Import(privKey)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)

	claims := map[string]any{
		"nonce":   "nonce",
		"aud":     "client",
		"sd_hash": hash,
		// no iat
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtCreator := sdjwtvc.NewJwtCreator(privKey)
	kbjwt, err := jwtCreator.CreateSignedJwt(map[string]any{"typ": sdjwtvc.KbJwtTyp}, string(claimsJSON))
	require.NoError(t, err)

	pubKeyJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubKeyJSON, &holderJwk))
	rawCredential = jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	presentation := rawCredential + "~" + kbjwt
	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing issued-at claim")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnInvalidIssuedAtType(t *testing.T) {
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var holderJwk map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &holderJwk))

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	hash, err := sdjwtvc.CreateUrlEncodedHash("sha-256", rawCredential)
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJwk, err := jwk.Import(privKey)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)

	claims := map[string]any{
		"nonce":   "nonce",
		"aud":     "client",
		"sd_hash": hash,
		"iat":     "invalid",
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtCreator := sdjwtvc.NewJwtCreator(privKey)
	kbjwt, err := jwtCreator.CreateSignedJwt(map[string]any{"typ": sdjwtvc.KbJwtTyp}, string(claimsJSON))
	require.NoError(t, err)

	pubKeyJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubKeyJSON, &holderJwk))
	rawCredential = jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	presentation := rawCredential + "~" + kbjwt
	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid issued-at claim")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnMissingSdHash(t *testing.T) {
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var holderJwk map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &holderJwk))

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJwk, err := jwk.Import(privKey)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)

	claims := map[string]any{
		"nonce": "nonce",
		"aud":   "client",
		"iat":   time.Now().Unix(),
		// no sd_hash
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtCreator := sdjwtvc.NewJwtCreator(privKey)
	kbjwt, err := jwtCreator.CreateSignedJwt(map[string]any{"typ": sdjwtvc.KbJwtTyp}, string(claimsJSON))
	require.NoError(t, err)

	pubKeyJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubKeyJSON, &holderJwk))
	rawCredential = jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	presentation := rawCredential + "~" + kbjwt
	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sd_hash mismatch")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnEmptySdHash(t *testing.T) {
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var holderJwk map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &holderJwk))

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJwk, err := jwk.Import(privKey)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)

	claims := map[string]any{
		"nonce":   "nonce",
		"aud":     "client",
		"sd_hash": "",
		"iat":     time.Now().Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtCreator := sdjwtvc.NewJwtCreator(privKey)
	kbjwt, err := jwtCreator.CreateSignedJwt(map[string]any{"typ": sdjwtvc.KbJwtTyp}, string(claimsJSON))
	require.NoError(t, err)

	pubKeyJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubKeyJSON, &holderJwk))
	rawCredential = jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	presentation := rawCredential + "~" + kbjwt
	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sd_hash mismatch")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnMissingTypHeader(t *testing.T) {
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var holderJwk map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &holderJwk))

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	hash, err := sdjwtvc.CreateUrlEncodedHash("sha-256", rawCredential)
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJwk, err := jwk.Import(privKey)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)

	claims := map[string]any{
		"nonce":   "nonce",
		"aud":     "client",
		"sd_hash": hash,
		"iat":     time.Now().Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtCreator := sdjwtvc.NewJwtCreator(privKey)
	kbjwt, err := jwtCreator.CreateSignedJwt(map[string]any{}, string(claimsJSON))
	require.NoError(t, err)

	pubKeyJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubKeyJSON, &holderJwk))
	rawCredential = jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	presentation := rawCredential + "~" + kbjwt
	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key binding jwt typ")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnInvalidTypHeader(t *testing.T) {
	binder := sdjwtvc.NewDefaultKeyBinder(sdjwtvc.NewInMemoryKeyBindingStorage())
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	keyJSON, err := json.Marshal(keys[0])
	require.NoError(t, err)

	var holderJwk map[string]any
	require.NoError(t, json.Unmarshal(keyJSON, &holderJwk))

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	hash, err := sdjwtvc.CreateUrlEncodedHash("sha-256", rawCredential)
	require.NoError(t, err)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJwk, err := jwk.Import(privKey)
	require.NoError(t, err)
	pubJwk, err := privJwk.PublicKey()
	require.NoError(t, err)

	claims := map[string]any{
		"nonce":   "nonce",
		"aud":     "client",
		"sd_hash": hash,
		"iat":     time.Now().Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	jwtCreator := sdjwtvc.NewJwtCreator(privKey)
	kbjwt, err := jwtCreator.CreateSignedJwt(map[string]any{"typ": "not-kb+jwt"}, string(claimsJSON))
	require.NoError(t, err)

	pubKeyJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(pubKeyJSON, &holderJwk))
	rawCredential = jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	presentation := rawCredential + "~" + kbjwt
	err = verifyHolderBoundJwtVcPresentation(presentation, "nonce", "client", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key binding jwt typ")
}

func TestVerifyHolderBoundJwtVcPresentation_FailsOnReplay(t *testing.T) {
	holderJwk, _, binder := mustNewHolderBindingFixture(t)
	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jwk": holderJwk,
		},
	})

	h := NewVcdmDcqlHandlerWithStoreAndKeyBinder(&mockCredentialStore{}, binder)
	presentation, err := createHolderBoundJwtVcPresentation(rawCredential, "nonce", "client", h.keyBinder, h.resolveHolderKeyFromJkt)
	require.NoError(t, err)

	replayGuard := newInMemoryKbJwtReplayGuard()
	err = verifyHolderBoundJwtVcPresentationWithReplay(presentation, "nonce", "client", h.resolveHolderKeyFromJkt, replayGuard)
	require.NoError(t, err)

	err = verifyHolderBoundJwtVcPresentationWithReplay(presentation, "nonce", "client", h.resolveHolderKeyFromJkt, replayGuard)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay detected")
}

func TestInMemoryKbJwtReplayGuard_PrunesExpiredEntries(t *testing.T) {
	guard := newInMemoryKbJwtReplayGuard()
	require.NotNil(t, guard)

	oldIssuedAt := time.Now().Add(-time.Duration(sdjwtvc.ClockSkewInSeconds+60) * time.Second)
	err := guard.CheckAndStore("old-kbjwt", oldIssuedAt)
	require.NoError(t, err)

	currentIssuedAt := time.Now()
	err = guard.CheckAndStore("current-kbjwt", currentIssuedAt)
	require.NoError(t, err)

	err = guard.CheckAndStore("current-kbjwt", currentIssuedAt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay detected")
}

func TestCreateHolderBoundJwtVcPresentation_WithCnfJktResolverMismatch_ReturnsError(t *testing.T) {
	holderJwk, _, binder := mustNewHolderBindingFixture(t)
	jkt := mustJktFromJwk(t, holderJwk)

	rawCredential := jwtVcWithPayload(t, map[string]any{
		"email": "alice@example.com",
		"cnf": map[string]any{
			"jkt": jkt,
		},
	})

	resolver := func(gotJkt string) (jwk.Key, error) {
		return nil, assert.AnError
	}

	_, err := createHolderBoundJwtVcPresentation(rawCredential, "nonce", "client", binder, resolver)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cnf.jkt")
}

func TestResolveHolderKeyFromJkt_Valid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)

	pubJwk, err := jwk.Import(privKey.Public())
	require.NoError(t, err)
	thumbprintBytes, err := pubJwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	store := &mockHolderBindingKeyStore{byThumbprint: map[string]*models.HolderBindingKey{
		hex.EncodeToString(thumbprintBytes): {
			PrivateKey: privKeyBytes,
		},
	}}

	h := &VcdmDcqlHandler{holderKeyStore: store}
	resolved, err := h.resolveHolderKeyFromJkt(base64.RawURLEncoding.EncodeToString(thumbprintBytes))
	require.NoError(t, err)

	resolvedThumbprint, err := resolved.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, thumbprintBytes, resolvedThumbprint)
}

func TestResolveHolderKeyFromJkt_InvalidEncoding(t *testing.T) {
	h := &VcdmDcqlHandler{holderKeyStore: &mockHolderBindingKeyStore{}}
	_, err := h.resolveHolderKeyFromJkt("%%%")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid jkt")
}

func TestResolveHolderKeyFromJkt_UnknownThumbprint(t *testing.T) {
	h := &VcdmDcqlHandler{holderKeyStore: &mockHolderBindingKeyStore{byThumbprint: map[string]*models.HolderBindingKey{}}}
	unknown := base64.RawURLEncoding.EncodeToString([]byte("unknown-thumbprint"))
	_, err := h.resolveHolderKeyFromJkt(unknown)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown jkt")
}

func TestPrepareDisclosure_BatchWithMultipleInstances_MarksUsed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batchID := datatypes.NewUUIDv4()
	instanceID := datatypes.NewUUIDv4()
	store := &mockCredentialStore{batches: []*models.CredentialBatch{
		{
			ID:               batchID,
			CredentialType:   "https://example.com/EmailCredential",
			Format:           models.CredentialFormatW3CVC,
			Hash:             "jwt-hash",
			ProcessedClaims:  datatypes.JSON(`{"email":"alice@example.com"}`),
			IssuanceDate:     datatypes.NullTime{V: now, Valid: true},
			BatchSize:        2,
			RemainingCount:   2,
			CredentialIssuer: "https://issuer.example.com",
			Instances: []models.IssuedCredentialInstance{
				{ID: instanceID, CredentialBatchID: batchID, RawCredential: []byte("header.payload.signature")},
			},
		},
	}}
	h := NewVcdmDcqlHandlerWithStore(store)

	_, err := h.PrepareDisclosure([]dcql.DisclosureSelection{{
		QueryId:        "q1",
		CredentialHash: "jwt-hash",
	}}, "nonce", "client")

	require.NoError(t, err)
	assert.True(t, store.batches[0].Instances[0].Used)
	assert.Equal(t, uint(1), store.batches[0].RemainingCount)
}
