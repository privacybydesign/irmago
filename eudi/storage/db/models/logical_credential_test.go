package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

func TestLogicalCredential_BeforeCreate_AssignsIDAndStampsChildren(t *testing.T) {
	lc := &LogicalCredential{
		Identity:  "abc123",
		IssuerURL: "https://issuer.example",
		FormatBindings: []FormatBinding{
			{Format: CredentialFormatSdJwtVcdm, ProcessedPayload: datatypes.JSON("{}"), BatchSize: 1, RemainingCount: 1},
		},
	}
	require.NoError(t, lc.BeforeCreate(nil))
	require.False(t, lc.ID.IsNil())
	require.Equal(t, lc.ID, lc.FormatBindings[0].LogicalCredentialID, "child FK stamped from owner ID")
}

func TestLogicalCredential_Validate(t *testing.T) {
	require.Error(t, (&LogicalCredential{IssuerURL: "https://i"}).BeforeCreate(nil), "missing Identity")
	require.Error(t, (&LogicalCredential{Identity: "x"}).BeforeCreate(nil), "missing IssuerURL")
	require.NoError(t, (&LogicalCredential{Identity: "x", IssuerURL: "https://i"}).BeforeCreate(nil))
}

func TestFormatBinding_BeforeCreate_AssignsID(t *testing.T) {
	fb := &FormatBinding{Format: CredentialFormatSdJwtVc, ProcessedPayload: datatypes.JSON("{}"), BatchSize: 2, RemainingCount: 2}
	require.NoError(t, fb.BeforeCreate(nil))
	require.False(t, fb.ID.IsNil())
}

func TestFormatBinding_Validate(t *testing.T) {
	valid := func() *FormatBinding {
		return &FormatBinding{Format: CredentialFormatSdJwtVc, ProcessedPayload: datatypes.JSON("{}"), BatchSize: 1, RemainingCount: 1}
	}
	require.NoError(t, valid().BeforeCreate(nil))

	noFormat := valid()
	noFormat.Format = ""
	require.Error(t, noFormat.BeforeCreate(nil), "missing Format")

	noPayload := valid()
	noPayload.ProcessedPayload = nil
	require.Error(t, noPayload.BeforeCreate(nil), "missing ProcessedPayload")

	zeroBatch := valid()
	zeroBatch.BatchSize = 0
	require.Error(t, zeroBatch.BeforeCreate(nil), "BatchSize must be >= 1")

	tooMany := valid()
	tooMany.RemainingCount = 5
	require.Error(t, tooMany.BeforeCreate(nil), "RemainingCount cannot exceed BatchSize")
}

func TestFormatBinding_BeforeCreate_StampsChildFKs(t *testing.T) {
	fb := &FormatBinding{
		Format:             CredentialFormatSdJwtVcdm,
		ProcessedPayload:   datatypes.JSON("{}"),
		BatchSize:          1,
		RemainingCount:     1,
		Instances:          []IssuedCredentialInstance{{RawCredential: []byte("raw")}},
		IssuerDisplay:      []IssuerMetadataDisplay{{Name: "Issuer"}},
		CredentialMetadata: &CredentialMetadata{},
	}
	require.NoError(t, fb.BeforeCreate(nil))
	require.False(t, fb.ID.IsNil())
	require.NotNil(t, fb.Instances[0].FormatBindingID)
	require.Equal(t, fb.ID, *fb.Instances[0].FormatBindingID, "instance FK stamped from binding ID")
	require.NotNil(t, fb.IssuerDisplay[0].FormatBindingID)
	require.Equal(t, fb.ID, *fb.IssuerDisplay[0].FormatBindingID)
	require.NotNil(t, fb.CredentialMetadata.FormatBindingID)
	require.Equal(t, fb.ID, *fb.CredentialMetadata.FormatBindingID)
}

func TestIssuedCredentialInstance_Validate_AcceptsEitherParent(t *testing.T) {
	fbID := datatypes.NewUUIDv4()
	batchID := datatypes.NewUUIDv4()

	// Neither parent → invalid.
	require.Error(t, (&IssuedCredentialInstance{RawCredential: []byte("r")}).validate())
	// FormatBinding parent only → valid (three-layer model).
	require.NoError(t, (&IssuedCredentialInstance{FormatBindingID: &fbID, RawCredential: []byte("r")}).validate())
	// Batch parent only → valid (legacy flat model).
	require.NoError(t, (&IssuedCredentialInstance{CredentialBatchID: &batchID, RawCredential: []byte("r")}).validate())
	// Parent set but no raw credential → invalid.
	require.Error(t, (&IssuedCredentialInstance{FormatBindingID: &fbID}).validate())
}
