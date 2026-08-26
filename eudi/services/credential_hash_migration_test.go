package services

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

const (
	testHashType   = "eu.europa.ec.av.1"
	testHashClaims = `{"eu.europa.ec.av.1":{"age_over_18":true}}`
)

// The issuer is part of a credential's identity. Two issuers minting the same
// type with the same claims are two different credentials, and because Hash is a
// unique index the storage layer could previously hold only one of them —
// the second was refused as a duplicate of the first, or replaced it.
func TestCredentialHash_IssuerIsPartOfIdentity(t *testing.T) {
	stateIssued := credentialHash(testHashType, "https://issuer.state.example", []byte(testHashClaims))
	shopIssued := credentialHash(testHashType, "https://issuer.shop.example", []byte(testHashClaims))

	require.NotEqual(t, stateIssued, shopIssued,
		"same type and claims from different issuers must hash differently")
}

// The property that constrains the change: an issuer does not change when it
// re-issues, so renewal still produces the same hash and is still recognised as
// the same credential rather than arriving as a second one.
func TestCredentialHash_StableAcrossReissuanceBySameIssuer(t *testing.T) {
	first := credentialHash(testHashType, "https://issuer.state.example", []byte(testHashClaims))
	renewed := credentialHash(testHashType, "https://issuer.state.example", []byte(testHashClaims))

	require.Equal(t, first, renewed)
}

// Length prefixing, not concatenation. Concatenated fields cannot be told apart,
// so moving a character from the end of the type to the start of the issuer
// produced identical bytes and therefore an identical hash — two different
// credentials sharing one identity.
func TestCredentialHash_FieldBoundariesCannotBeConfused(t *testing.T) {
	claims := []byte(`{}`)

	require.NotEqual(t,
		credentialHash("a.b", "cd", claims),
		credentialHash("a.bc", "d", claims),
		"a character moved across the type/issuer boundary must change the hash")

	require.NotEqual(t,
		credentialHash("x", "", claims),
		credentialHash("", "x", claims),
		"an empty field must not be interchangeable with its neighbour")
}

func TestCredentialHash_ClaimsStillMatter(t *testing.T) {
	issuer := "https://issuer.state.example"

	require.NotEqual(t,
		credentialHash(testHashType, issuer, []byte(`{"age_over_18":true}`)),
		credentialHash(testHashType, issuer, []byte(`{"age_over_18":false}`)),
		"the claims must still decide identity")
}

// ========== MigrateCredentialHashes ==========

func TestMigrateCredentialHashes_RewritesIssuerlessHash(t *testing.T) {
	batchID := datatypes.NewUUIDv4()
	// A row as an older wallet wrote it: the hash covered type and claims only.
	stale := &models.CredentialBatch{
		ID:                       batchID,
		Format:                   models.CredentialFormatMsoMdoc,
		VerifiableCredentialType: testHashType,
		IssuerIdentifier:         "https://issuer.state.example",
		ProcessedSdJwtPayload:    datatypes.JSON(testHashClaims),
		Hash:                     "an-old-style-hash-without-the-issuer",
	}
	store := &mockCredentialStore{batchListResult: []*models.CredentialBatch{stale}}

	require.NoError(t, MigrateCredentialHashes(store))

	require.Len(t, store.updatedHashes, 1)
	require.Equal(t, batchID, store.updatedHashes[0].batchID)
	require.Equal(t,
		credentialHash(testHashType, "https://issuer.state.example", []byte(testHashClaims)),
		store.updatedHashes[0].hash,
		"the rewritten hash must be what issuance would compute today")
}

// Idempotence matters because this runs on every startup: a wallet already on the
// current scheme must be left alone rather than rewritten to the same value.
func TestMigrateCredentialHashes_LeavesCurrentHashesAlone(t *testing.T) {
	current := &models.CredentialBatch{
		ID:                       datatypes.NewUUIDv4(),
		Format:                   models.CredentialFormatMsoMdoc,
		VerifiableCredentialType: testHashType,
		IssuerIdentifier:         "https://issuer.state.example",
		ProcessedSdJwtPayload:    datatypes.JSON(testHashClaims),
		Hash:                     credentialHash(testHashType, "https://issuer.state.example", []byte(testHashClaims)),
	}
	store := &mockCredentialStore{batchListResult: []*models.CredentialBatch{current}}

	require.NoError(t, MigrateCredentialHashes(store))
	require.Empty(t, store.updatedHashes)
}

// A batch that cannot be re-hashed is skipped rather than failing the migration,
// so one bad row cannot stop a wallet from starting. An empty Format is the real
// case: batches were once stored with it unset.
func TestMigrateCredentialHashes_SkipsUnhashableBatchAndContinues(t *testing.T) {
	unhashable := &models.CredentialBatch{
		ID:                       datatypes.NewUUIDv4(),
		Format:                   "",
		VerifiableCredentialType: testHashType,
		ProcessedSdJwtPayload:    datatypes.JSON(testHashClaims),
		Hash:                     "left-alone",
	}
	good := &models.CredentialBatch{
		ID:                       datatypes.NewUUIDv4(),
		Format:                   models.CredentialFormatMsoMdoc,
		VerifiableCredentialType: testHashType,
		IssuerIdentifier:         "https://issuer.state.example",
		ProcessedSdJwtPayload:    datatypes.JSON(testHashClaims),
		Hash:                     "stale",
	}
	store := &mockCredentialStore{batchListResult: []*models.CredentialBatch{unhashable, good}}

	require.NoError(t, MigrateCredentialHashes(store))

	require.Len(t, store.updatedHashes, 1, "the unhashable batch must be skipped, the good one still migrated")
	require.Equal(t, good.ID, store.updatedHashes[0].batchID)
}

func TestMigrateCredentialHashes_SdJwtVcUsesTheSdJwtFunction(t *testing.T) {
	// Standard claims are stripped for dc+sd-jwt, so a payload carrying them must
	// hash the same as one without — proving the migration picked the right
	// function for the format rather than hashing the raw payload.
	withStandardClaims := datatypes.JSON(`{"given_name":"Alice","iss":"https://issuer.state.example","iat":1700000000}`)
	batch := &models.CredentialBatch{
		ID:                       datatypes.NewUUIDv4(),
		Format:                   models.CredentialFormatSdJwtVc,
		VerifiableCredentialType: "https://vct.example.com/Cred",
		IssuerIdentifier:         "https://issuer.state.example",
		ProcessedSdJwtPayload:    withStandardClaims,
		Hash:                     "stale",
	}
	store := &mockCredentialStore{batchListResult: []*models.CredentialBatch{batch}}

	require.NoError(t, MigrateCredentialHashes(store))
	require.Len(t, store.updatedHashes, 1)

	want, err := hashForSdJwtVc("https://vct.example.com/Cred", "https://issuer.state.example", withStandardClaims)
	require.NoError(t, err)
	require.Equal(t, want, store.updatedHashes[0].hash)
}
