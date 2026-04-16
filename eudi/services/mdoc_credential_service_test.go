package services

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/testissuer"
	"github.com/privacybydesign/irmago/eudi/storage/models"
)

// The tests below use testissuer.BuildAVCredential to obtain a well-formed,
// signed mdoc + device key pair and then exercise the service layer against
// the existing mockCredentialStore from credential_service_test.go. This
// isolates the service logic (hash derivation, attribute projection,
// key-binding wiring) from the SQLite storage itself, which has its own tests.

func TestStoreMdocCredential_PersistsBatch(t *testing.T) {
	cred, err := testissuer.BuildAVCredential(testissuer.AVRequest{
		AgeOver18: true,
		AgeOverNN: map[int]bool{21: true},
	})
	require.NoError(t, err)

	mock := &mockCredentialStore{}
	svc := &mdocCredentialService{credentialStore: mock}

	batch, err := svc.StoreMdocCredential(cred.IssuerSignedCBOR, cred.DeviceKey)
	require.NoError(t, err)
	require.NotNil(t, batch)

	require.Len(t, mock.storedBatches, 1)
	stored := mock.storedBatches[0]

	assert.Equal(t, models.CredentialFormatMdoc, stored.Format)
	assert.Equal(t, testissuer.AVDocType, stored.VerifiableCredentialType)
	assert.NotEmpty(t, stored.Hash)
	assert.NotEmpty(t, stored.IssuerURL)
	assert.NotEmpty(t, stored.CredentialIssuer)
	assert.Equal(t, uint(1), stored.BatchSize)
	assert.Equal(t, uint(1), stored.RemainingCount)

	// ProcessedSdJwtPayload is reused as a format-neutral attribute projection.
	// It should hold {namespace: {element: value}} so the UI can render it.
	var projection map[string]map[string]any
	require.NoError(t, json.Unmarshal(stored.ProcessedSdJwtPayload, &projection))
	nsAttrs, ok := projection[testissuer.AVNamespace]
	require.True(t, ok, "expected namespace %q in projection", testissuer.AVNamespace)
	assert.Equal(t, true, nsAttrs["age_over_18"])
	assert.Equal(t, true, nsAttrs["age_over_21"])
}

func TestStoreMdocCredential_StoresRawCBORAndDeviceKey(t *testing.T) {
	cred, err := testissuer.BuildAVCredential(testissuer.AVRequest{AgeOver18: true})
	require.NoError(t, err)

	mock := &mockCredentialStore{}
	svc := &mdocCredentialService{credentialStore: mock}

	_, err = svc.StoreMdocCredential(cred.IssuerSignedCBOR, cred.DeviceKey)
	require.NoError(t, err)

	require.Len(t, mock.storedBatches, 1)
	stored := mock.storedBatches[0]
	require.Len(t, stored.Instances, 1)

	inst := stored.Instances[0]
	assert.Equal(t, cred.IssuerSignedCBOR, []byte(inst.RawCredential),
		"RawCredential should be the IssuerSigned CBOR bytes byte-for-byte")

	require.NotNil(t, inst.HolderBindingKey, "device key must be persisted via HolderBindingKey")
	hbk := inst.HolderBindingKey
	assert.Equal(t, models.KeyAlgorithmECDSA, hbk.Algorithm)
	assert.True(t, hbk.PublicKeyThumbprint.Valid, "thumbprint must be set")
	assert.NotEmpty(t, hbk.PrivateKey, "PKCS#8 private key bytes must be set")
	require.NotNil(t, hbk.ECDSA)
	assert.Equal(t, "P-256", hbk.ECDSA.CurveName)
}

func TestStoreMdocCredential_HashIsDeterministic(t *testing.T) {
	// Two issuances of identical AV claims should collide on Hash so the
	// unique index in storage refuses to double-store the same content.
	// (They are not binary-identical because random salts differ each call.)
	first, err := testissuer.BuildAVCredential(testissuer.AVRequest{AgeOver18: true})
	require.NoError(t, err)
	second, err := testissuer.BuildAVCredential(testissuer.AVRequest{AgeOver18: true})
	require.NoError(t, err)
	require.NotEqual(t, first.IssuerSignedCBOR, second.IssuerSignedCBOR,
		"precondition: random salts should make the raw bytes differ")

	mock := &mockCredentialStore{}
	svc := &mdocCredentialService{credentialStore: mock}

	b1, err := svc.StoreMdocCredential(first.IssuerSignedCBOR, first.DeviceKey)
	require.NoError(t, err)
	b2, err := svc.StoreMdocCredential(second.IssuerSignedCBOR, second.DeviceKey)
	require.NoError(t, err)

	assert.Equal(t, b1.Hash, b2.Hash,
		"same docType + same attributes/values should hash identically")
}

func TestStoreMdocCredential_ValidityPulledFromMSO(t *testing.T) {
	cred, err := testissuer.BuildAVCredential(testissuer.AVRequest{AgeOver18: true})
	require.NoError(t, err)

	mock := &mockCredentialStore{}
	svc := &mdocCredentialService{credentialStore: mock}
	_, err = svc.StoreMdocCredential(cred.IssuerSignedCBOR, cred.DeviceKey)
	require.NoError(t, err)

	stored := mock.storedBatches[0]
	require.False(t, stored.IssuedAt.IsZero(), "IssuedAt must be populated from MSO.signed")
	require.True(t, stored.NotBefore.Valid)
	require.True(t, stored.ExpiresAt.Valid)
	assert.True(t, stored.ExpiresAt.V.After(stored.NotBefore.V),
		"validUntil must be after validFrom")
}

func TestStoreMdocCredential_RejectsGarbageCBOR(t *testing.T) {
	mock := &mockCredentialStore{}
	svc := &mdocCredentialService{credentialStore: mock}
	_, err := svc.StoreMdocCredential([]byte{0xff, 0xff, 0xff}, nil)
	require.Error(t, err)
	assert.Empty(t, mock.storedBatches, "no batch should be stored on parse failure")
}
