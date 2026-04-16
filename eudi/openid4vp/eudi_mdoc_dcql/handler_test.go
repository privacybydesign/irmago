package eudi_mdoc_dcql

import (
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/testissuer"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/models"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipher"
)

type testStorage struct{ db *gorm.DB }

func (s *testStorage) Db() *gorm.DB     { return s.db }
func (s *testStorage) Close() error     { return nil }
func (s *testStorage) RemoveAll() error { return nil }

var _ storage.Storage = (*testStorage)(nil)

// newTestSetup spins up an in-memory SQLCipher DB, migrates the wallet schema,
// seeds a fresh Age-Verification credential via the mdoc service, and returns
// the handler + credential so tests can drive it.
func newTestSetup(t *testing.T) (*MdocDcqlHandler, *testissuer.AVCredential, *models.CredentialBatch) {
	t.Helper()
	dsn := sqlcipher.DSN(":memory:", "test-key-av")
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

	cred, err := testissuer.BuildAVCredential(testissuer.AVRequest{
		AgeOver18: true,
		AgeOverNN: map[int]bool{21: true},
	})
	require.NoError(t, err)

	svc := services.NewMdocCredentialService(ts)
	batch, err := svc.StoreMdocCredential(cred.IssuerSignedCBOR, cred.DeviceKey)
	require.NoError(t, err)

	return NewMdocDcqlHandler(ts), cred, batch
}

func TestMdocHandler_CanHandle(t *testing.T) {
	h := &MdocDcqlHandler{}

	assert.True(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{
		Format: "mso_mdoc",
		Meta:   &dcql.Meta{DocTypeValue: testissuer.AVDocType},
	}))

	assert.False(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{
		Format: "dc+sd-jwt",
		Meta:   &dcql.Meta{DocTypeValue: testissuer.AVDocType},
	}))

	assert.False(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{
		Format: "mso_mdoc",
		Meta:   nil,
	}))

	assert.False(t, h.CanHandleCredentialQuery(dcql.CredentialQuery{
		Format: "mso_mdoc",
		Meta:   &dcql.Meta{DocTypeValue: ""},
	}))
}

func TestMdocHandler_FindCandidates_MatchesDocType(t *testing.T) {
	h, _, batch := newTestSetup(t)

	res, err := h.FindCandidates(dcql.CredentialQuery{
		Id:     "q1",
		Format: "mso_mdoc",
		Meta:   &dcql.Meta{DocTypeValue: testissuer.AVDocType},
		Claims: []dcql.Claim{
			{Path: []any{testissuer.AVNamespace, "age_over_18"}},
		},
	})
	require.NoError(t, err)
	require.Len(t, res.OwnedCandidates, 1)
	assert.Equal(t, batch.Hash, res.OwnedCandidates[0].Hash)
}

func TestMdocHandler_FindCandidates_RejectsMismatchedDocType(t *testing.T) {
	h, _, _ := newTestSetup(t)

	res, err := h.FindCandidates(dcql.CredentialQuery{
		Id:     "q1",
		Format: "mso_mdoc",
		Meta:   &dcql.Meta{DocTypeValue: "org.iso.18013.5.1.mDL"},
	})
	require.NoError(t, err)
	assert.Empty(t, res.OwnedCandidates)
}

func TestMdocHandler_FindCandidates_ValueConstraintFiltersOut(t *testing.T) {
	h, _, _ := newTestSetup(t)

	// Age-Verification credential has age_over_18=true. Asking for =false
	// should match no credential.
	res, err := h.FindCandidates(dcql.CredentialQuery{
		Id:     "q1",
		Format: "mso_mdoc",
		Meta:   &dcql.Meta{DocTypeValue: testissuer.AVDocType},
		Claims: []dcql.Claim{
			{Path: []any{testissuer.AVNamespace, "age_over_18"}, Values: []any{false}},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, res.OwnedCandidates)
}

// TestMdocHandler_PrepareDisclosure_EndToEnd exercises the full OpenID4VP
// happy path against our own credential: build a DeviceResponse, re-parse it,
// check the disclosed element is exactly what was asked for, and verify the
// DeviceAuth signature against the stored device public key.
func TestMdocHandler_PrepareDisclosure_EndToEnd(t *testing.T) {
	h, cred, batch := newTestSetup(t)

	selections := []dcql.DisclosureSelection{{
		QueryId:              "q1",
		CredentialHash:       batch.Hash,
		ClaimPaths:           [][]any{{testissuer.AVNamespace, "age_over_18"}},
		RequireHolderBinding: true,
	}}

	ctx := dcql.DisclosureContext{
		Nonce:       "nonce-e2e",
		ClientId:    "x509_san_dns:verifier.example.com",
		ResponseUri: "https://verifier.example.com/callback",
	}
	prepared, err := h.PrepareDisclosure(selections, ctx)
	require.NoError(t, err)
	require.Len(t, prepared.QueryResponses, 1)
	require.Len(t, prepared.QueryResponses[0].Credentials, 1)

	// Decode the vp_token string back into the DeviceResponse CBOR bytes.
	deviceResponse, err := base64.RawURLEncoding.DecodeString(prepared.QueryResponses[0].Credentials[0])
	require.NoError(t, err)

	// Parse the embedded IssuerSigned and confirm selective disclosure worked.
	issuerSigned, err := mdoc.ExtractIssuerSignedFromDeviceResponse(deviceResponse)
	require.NoError(t, err)
	items := issuerSigned.Namespaces[testissuer.AVNamespace]
	require.Len(t, items, 1, "only the requested element should be present")
	assert.Equal(t, "age_over_18", items[0].ElementIdentifier)

	// Verify digest integrity survived filter + encode.
	mso, err := issuerSigned.IssuerAuth.MobileSecurityObject()
	require.NoError(t, err)
	want := mso.ValueDigests[testissuer.AVNamespace][items[0].DigestID]
	got, err := items[0].Digest(mso.DigestAlgorithm)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// Verify DeviceAuth against the stored device key. Rebuild the exact
	// SessionTranscript the handler used.
	sessionTranscript, err := mdoc.BuildOID4VPSessionTranscript(
		ctx.ClientId, ctx.ResponseUri, ctx.Nonce,
	)
	require.NoError(t, err)

	// Re-extract the raw deviceSigned map from the DeviceResponse so we can
	// pass it back into VerifyDeviceAuth.
	deviceSignedBytes := mustExtractDeviceSignedBytes(t, deviceResponse)
	require.NoError(t, mdoc.VerifyDeviceAuth(
		deviceSignedBytes,
		sessionTranscript,
		batch.VerifiableCredentialType,
		&cred.DeviceKey.PublicKey,
	))
}

func TestMdocHandler_PrepareDisclosure_RejectsInvalidClaimPath(t *testing.T) {
	h, _, batch := newTestSetup(t)

	_, err := h.PrepareDisclosure(
		[]dcql.DisclosureSelection{{
			QueryId:        "q1",
			CredentialHash: batch.Hash,
			ClaimPaths:     [][]any{{"single-component"}}, // missing element
		}},
		dcql.DisclosureContext{Nonce: "n", ClientId: "c", ResponseUri: "r"},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "want 2")
}

// TestMdocHandler_PrepareDisclosure_RegistersAsDcqlHandler proves that
// MdocDcqlHandler satisfies the DcqlCredentialQueryHandler interface.
// This ensures NewClient can accept it without further changes.
func TestMdocHandler_PrepareDisclosure_RegistersAsDcqlHandler(t *testing.T) {
	h, _, _ := newTestSetup(t)
	var _ dcql.DcqlCredentialQueryHandler = h
}

// ---- helpers ---------------------------------------------------------------

func mustExtractDeviceSignedBytes(t *testing.T, deviceResponse []byte) []byte {
	t.Helper()
	type wrapper struct {
		Documents []struct {
			DeviceSigned cbor.RawMessage `cbor:"deviceSigned"`
		} `cbor:"documents"`
	}
	var w wrapper
	require.NoError(t, cbor.Unmarshal(deviceResponse, &w))
	require.NotEmpty(t, w.Documents)
	return []byte(w.Documents[0].DeviceSigned)
}
