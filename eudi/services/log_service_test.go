package services

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestLogService(t *testing.T) EudiLogService {
	t.Helper()

	const passphrase = "test-passphrase-1234567890123456"
	database, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte(passphrase))}, &gorm.Config{})
	require.NoError(t, err)

	err = database.AutoMigrate(
		&models.EudiLogEntry{},
		&models.EudiLogCredential{},
	)
	require.NoError(t, err)

	var aesKey [32]byte
	copy(aesKey[:], passphrase)
	fs := filesystem.NewFileSystemStorage(aesKey, t.TempDir())

	return &eudiLogService{
		store:               db.NewEudiLogStore(database),
		credLogoManager:     fs.Credentials().LogoManager(),
		issuerLogoManager:   fs.Issuers().LogoManager(),
		verifierLogoManager: fs.Verifiers().LogoManager(),
	}
}

func TestDisclosureLogRoundTrip_PreservesCredentialAndIssuerImages(t *testing.T) {
	svc := newTestLogService(t)

	credImageData := base64.StdEncoding.EncodeToString([]byte("fake-credential-png"))
	issuerImageData := base64.StdEncoding.EncodeToString([]byte("fake-issuer-png"))

	boolVal := true
	intVal := int64(42)

	input := []clientmodels.LogCredential{
		{
			CredentialId: "https://example.com/vct/test",
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Name:         clientmodels.TranslatedString{"en": "Test Credential"},
			Image:        &clientmodels.Image{Base64: credImageData},
			Issuer: clientmodels.TrustedParty{
				Id:       "https://example.com/issuer",
				Name:     clientmodels.TranslatedString{"en": "Test Issuer"},
				Image:    &clientmodels.Image{Base64: issuerImageData},
				Verified: true,
			},
			Attributes: []clientmodels.Attribute{
				{
					ClaimPath: []any{"name"},
					Value:     &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: strPtr("Alice")},
				},
				{
					ClaimPath: []any{"is_student"},
					Value:     &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Bool, Bool: &boolVal},
				},
				{
					ClaimPath: []any{"age"},
					Value:     &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Int, Int: &intVal},
				},
			},
			IssuanceDate: 1700000000,
			ExpiryDate:   1800000000,
		},
	}

	verifier := clientmodels.TrustedParty{
		Id:   "https://verifier.example.com",
		Name: clientmodels.TranslatedString{"en": "Test Verifier"},
	}

	require.NoError(t, svc.AddDisclosureLog(verifier, input))

	logs, err := svc.GetNewestLogs(10)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	require.NotNil(t, logs[0].DisclosureLog)
	require.Len(t, logs[0].DisclosureLog.Credentials, 1)

	cred := logs[0].DisclosureLog.Credentials[0]

	// Credential image survives round-trip.
	require.NotNil(t, cred.Image, "credential image should survive log round-trip")
	require.NotEmpty(t, cred.Image.Base64)

	// Issuer image survives round-trip.
	require.NotNil(t, cred.Issuer.Image, "issuer image should survive log round-trip")
	require.NotEmpty(t, cred.Issuer.Image.Base64)

	// Issuer ID, name, and verified flag survive round-trip.
	require.Equal(t, "https://example.com/issuer", cred.Issuer.Id)
	require.Equal(t, "Test Issuer", cred.Issuer.Name["en"])
	require.True(t, cred.Issuer.Verified, "Verified flag should survive log round-trip")

	// Credential metadata survives round-trip.
	require.Equal(t, "https://example.com/vct/test", cred.CredentialId)
	require.Equal(t, "Test Credential", cred.Name["en"])
	require.Equal(t, int64(1700000000), cred.IssuanceDate)
	require.Equal(t, int64(1800000000), cred.ExpiryDate)

	// Attribute values survive round-trip with correct types.
	require.Len(t, cred.Attributes, 3)

	require.Equal(t, clientmodels.AttributeType_String, cred.Attributes[0].Value.Type)
	require.Equal(t, "Alice", *cred.Attributes[0].Value.String)

	require.Equal(t, clientmodels.AttributeType_Bool, cred.Attributes[1].Value.Type)
	require.Equal(t, true, *cred.Attributes[1].Value.Bool)

	require.Equal(t, clientmodels.AttributeType_Int, cred.Attributes[2].Value.Type)
	require.Equal(t, int64(42), *cred.Attributes[2].Value.Int)
}

func TestIssuanceLogRoundTrip_PreservesCredentialAndIssuerImages(t *testing.T) {
	svc := newTestLogService(t)

	credImageData := base64.StdEncoding.EncodeToString([]byte("fake-credential-png"))
	issuerImageData := base64.StdEncoding.EncodeToString([]byte("fake-issuer-png"))

	creds := []clientmodels.LogCredential{
		{
			CredentialId: "https://example.com/vct/test",
			Image:        &clientmodels.Image{Base64: credImageData},
			Name:         clientmodels.TranslatedString{"en": "Test Credential"},
			Issuer: clientmodels.TrustedParty{
				Id:       "https://example.com/issuer",
				Name:     clientmodels.TranslatedString{"en": "Test Issuer"},
				Image:    &clientmodels.Image{Base64: issuerImageData},
				Verified: true,
			},
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Attributes:   []clientmodels.Attribute{},
			IssuanceDate: 1700000000,
			ExpiryDate:   1800000000,
		},
	}

	issuer := clientmodels.TrustedParty{
		Id:   "https://example.com/issuer",
		Name: clientmodels.TranslatedString{"en": "Test Issuer"},
	}

	require.NoError(t, svc.AddIssuanceLog(clientmodels.Protocol_OpenID4VCI, issuer, creds))

	logs, err := svc.GetNewestLogs(10)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	require.NotNil(t, logs[0].IssuanceLog)
	require.Len(t, logs[0].IssuanceLog.Credentials, 1)

	cred := logs[0].IssuanceLog.Credentials[0]

	// Credential image survives round-trip.
	require.NotNil(t, cred.Image, "credential image should survive log round-trip")
	require.NotEmpty(t, cred.Image.Base64)

	// Issuer image survives round-trip.
	require.NotNil(t, cred.Issuer.Image, "issuer image should survive log round-trip")
	require.NotEmpty(t, cred.Issuer.Image.Base64)

	// Issuer ID and verified flag survive round-trip.
	require.Equal(t, "https://example.com/issuer", cred.Issuer.Id)
	require.True(t, cred.Issuer.Verified, "Verified flag should survive log round-trip")
}

func TestRemovalLogRoundTrip(t *testing.T) {
	svc := newTestLogService(t)

	creds := []clientmodels.LogCredential{
		{
			CredentialId: "https://example.com/vct/removed",
			Name:         clientmodels.TranslatedString{"en": "Removed Credential"},
			Issuer: clientmodels.TrustedParty{
				Id:   "https://example.com/issuer",
				Name: clientmodels.TranslatedString{"en": "Test Issuer"},
			},
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Attributes:   []clientmodels.Attribute{},
			IssuanceDate: 1700000000,
			ExpiryDate:   1800000000,
		},
	}

	require.NoError(t, svc.AddRemovalLog(creds))

	logs, err := svc.GetNewestLogs(10)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	require.Equal(t, clientmodels.LogType_CredentialRemoval, logs[0].Type)
	require.NotNil(t, logs[0].RemovalLog)
	require.Len(t, logs[0].RemovalLog.Credentials, 1)

	cred := logs[0].RemovalLog.Credentials[0]
	require.Equal(t, "https://example.com/vct/removed", cred.CredentialId)
	require.Equal(t, "Removed Credential", cred.Name["en"])
	require.Equal(t, "https://example.com/issuer", cred.Issuer.Id)
	require.Equal(t, int64(1700000000), cred.IssuanceDate)
}

func TestGetLogsBefore_Pagination(t *testing.T) {
	svc := newTestLogService(t)

	// Create 3 logs with distinct timestamps.
	for i, name := range []string{"first", "second", "third"} {
		creds := []clientmodels.LogCredential{
			{
				CredentialId: "https://example.com/vct/" + name,
				Name:         clientmodels.TranslatedString{"en": name},
				Issuer:       clientmodels.TrustedParty{Id: "https://example.com/issuer"},
				Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
				Attributes:   []clientmodels.Attribute{},
			},
		}
		issuer := clientmodels.TrustedParty{Id: "issuer-" + name}
		require.NoError(t, svc.AddIssuanceLog(clientmodels.Protocol_OpenID4VCI, issuer, creds))
		// Ensure distinct timestamps (SQLite has millisecond precision).
		if i < 2 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	all, err := svc.GetNewestLogs(10)
	require.NoError(t, err)
	require.Len(t, all, 3)
	// Newest first.
	require.Equal(t, "third", all[0].IssuanceLog.Credentials[0].Name["en"])

	// Get logs before the newest entry → should return the 2 older ones.
	older, err := svc.GetLogsBefore(all[0].Time, 10)
	require.NoError(t, err)
	require.Len(t, older, 2)
	require.Equal(t, "second", older[0].IssuanceLog.Credentials[0].Name["en"])
	require.Equal(t, "first", older[1].IssuanceLog.Credentials[0].Name["en"])
}
