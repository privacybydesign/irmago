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
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestLogService(t *testing.T) EudiLogService {
	return newTestLogServiceWithLocale(t, "en")
}

func newTestLogServiceWithLocale(t *testing.T, locale string) *eudiLogService {
	t.Helper()

	const passphrase = "test-passphrase-1234567890123456"
	database, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte(passphrase))}, &gorm.Config{})
	require.NoError(t, err)

	err = database.AutoMigrate(
		&models.EudiLogEntry{},
		&models.EudiLogCredential{},
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
	)
	require.NoError(t, err)

	var aesKey [32]byte
	copy(aesKey[:], passphrase)
	fs := filesystem.NewFileSystemStorage(aesKey, t.TempDir())

	return &eudiLogService{
		locale:              locale,
		store:               db.NewEudiLogStore(database),
		credentialStore:     db.NewCredentialStore(database),
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

	issuanceDate := int64(1700000000)
	expiryDate := int64(1800000000)

	input := []clientmodels.LogCredential{
		{
			CredentialId: "https://example.com/vct/test",
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Name:         "Test Credential",
			Image:        &clientmodels.Image{Base64: credImageData},
			Issuer: clientmodels.TrustedParty{
				Id:       "https://example.com/issuer",
				Name:     "Test Issuer",
				Image:    &clientmodels.Image{Base64: issuerImageData},
				Verified: true,
			},
			Attributes: []clientmodels.Attribute{
				{
					ClaimPath: []any{"name"},
					Value:     &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: new("Alice")},
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
			IssuanceDate: &issuanceDate,
			ExpiryDate:   &expiryDate,
		},
	}

	verifier := clientmodels.TrustedParty{
		Id:   "https://verifier.example.com",
		Name: "Test Verifier",
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
	require.Equal(t, "Test Issuer", cred.Issuer.Name)
	require.True(t, cred.Issuer.Verified, "Verified flag should survive log round-trip")

	// Credential metadata survives round-trip.
	require.Equal(t, "https://example.com/vct/test", cred.CredentialId)
	require.Equal(t, "Test Credential", cred.Name)
	require.Equal(t, issuanceDate, *cred.IssuanceDate)
	require.Equal(t, expiryDate, *cred.ExpiryDate)

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

	issuanceDate := int64(1700000000)
	expiryDate := int64(1800000000)

	creds := []clientmodels.LogCredential{
		{
			CredentialId: "https://example.com/vct/test",
			Image:        &clientmodels.Image{Base64: credImageData},
			Name:         "Test Credential",
			Issuer: clientmodels.TrustedParty{
				Id:       "https://example.com/issuer",
				Name:     "Test Issuer",
				Image:    &clientmodels.Image{Base64: issuerImageData},
				Verified: true,
			},
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Attributes:   []clientmodels.Attribute{},
			IssuanceDate: &issuanceDate,
			ExpiryDate:   &expiryDate,
		},
	}

	issuer := clientmodels.TrustedParty{
		Id:   "https://example.com/issuer",
		Name: "Test Issuer",
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

	issuanceDate := int64(1700000000)
	expiryDate := int64(1800000000)

	creds := []clientmodels.LogCredential{
		{
			CredentialId: "https://example.com/vct/removed",
			Name:         "Removed Credential",
			Issuer: clientmodels.TrustedParty{
				Id:   "https://example.com/issuer",
				Name: "Test Issuer",
			},
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Attributes:   []clientmodels.Attribute{},
			IssuanceDate: &issuanceDate,
			ExpiryDate:   &expiryDate,
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
	require.Equal(t, "Removed Credential", cred.Name)
	require.Equal(t, "https://example.com/issuer", cred.Issuer.Id)
	require.Equal(t, issuanceDate, *cred.IssuanceDate)
}

func TestGetLogsBefore_Pagination(t *testing.T) {
	svc := newTestLogService(t)

	// Create 3 logs with distinct timestamps.
	for i, name := range []string{"first", "second", "third"} {
		creds := []clientmodels.LogCredential{
			{
				CredentialId: "https://example.com/vct/" + name,
				Name:         name,
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
	require.Equal(t, "third", all[0].IssuanceLog.Credentials[0].Name)

	// Get logs before the newest entry → should return the 2 older ones.
	older, err := svc.GetLogsBefore(all[0].Time, 10)
	require.NoError(t, err)
	require.Len(t, older, 2)
	require.Equal(t, "second", older[0].IssuanceLog.Credentials[0].Name)
	require.Equal(t, "first", older[1].IssuanceLog.Credentials[0].Name)
}

// newLiveBatch stores a credential batch with en+nl display metadata so log
// read paths can re-resolve text against it.
func newLiveBatch(t *testing.T, svc *eudiLogService, vct, issuer string) {
	t.Helper()
	batch := &models.CredentialBatch{
		IssuerURL:                issuer,
		VerifiableCredentialType: vct,
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     "live-batch-hash",
		ProcessedSdJwtPayload:    datatypes.JSON(`{"email":"a@b.com"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now(), Valid: true},
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         issuer,
		IssuerDisplay: []models.IssuerMetadataDisplay{
			{Name: "Test Issuer", Locale: datatypes.NullString{V: "en", Valid: true}},
			{Name: "Test Uitgever", Locale: datatypes.NullString{V: "nl", Valid: true}},
		},
		CredentialMetadata: &models.CredentialMetadata{
			Display: []models.CredentialDisplay{
				{Name: "Test Credential", Locale: datatypes.NullString{V: "en", Valid: true}},
				{Name: "Testgegeven", Locale: datatypes.NullString{V: "nl", Valid: true}},
			},
			Claims: []models.CredentialClaim{
				{
					Path: datatypes.JSON(`["email"]`),
					Display: []models.ClaimDisplay{
						{Name: "Email", Locale: datatypes.NullString{V: "en", Valid: true}},
						{Name: "E-mailadres", Locale: datatypes.NullString{V: "nl", Valid: true}},
					},
				},
			},
		},
		Instances: []models.IssuedCredentialInstance{{RawCredential: []byte("raw")}},
	}
	require.NoError(t, svc.credentialStore.StoreBatch(batch))
}

// TestLogReadReResolvesTextFromLiveMetadata pins that the activity log follows
// the active locale for credentials still in the wallet: the persisted
// snapshot (resolved at log-creation time) is overridden by the stored
// batch's metadata, while verifier names — which have no stored metadata —
// keep their snapshot.
func TestLogReadReResolvesTextFromLiveMetadata(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "en")

	const vct = "https://example.com/vct/test"
	const issuer = "https://example.com/issuer"
	newLiveBatch(t, svc, vct, issuer)

	emailName := "Email"
	require.NoError(t, svc.AddDisclosureLog(
		clientmodels.TrustedParty{Id: "https://verifier.example.com", Name: "Test Verifier"},
		[]clientmodels.LogCredential{{
			CredentialId: vct,
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Name:         "Test Credential",
			Issuer:       clientmodels.TrustedParty{Id: issuer, Name: "Test Issuer"},
			Attributes: []clientmodels.Attribute{{
				ClaimPath:   []any{"email"},
				DisplayName: &emailName,
				Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: new("a@b.com")},
			}},
		}},
	))

	// Switch the active locale and read the log back.
	svc.locale = "nl"
	logs, err := svc.GetNewestLogs(10)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	cred := logs[0].DisclosureLog.Credentials[0]
	require.Equal(t, "Testgegeven", cred.Name, "credential name re-resolves from live metadata")
	require.Equal(t, "Test Uitgever", cred.Issuer.Name, "issuer name re-resolves from live metadata")
	require.Equal(t, "E-mailadres", *cred.Attributes[0].DisplayName, "attribute names re-resolve from live claim metadata")
	require.Equal(t, "a@b.com", *cred.Attributes[0].Value.String, "values are data, not translations")
	require.Equal(t, "Test Verifier", logs[0].DisclosureLog.Verifier.Name,
		"verifier names have no stored metadata and keep the snapshot")
}

// TestLogReadFallsBackToSnapshotWhenCredentialDeleted pins that log entries
// for credentials no longer in the wallet show their creation-time snapshot.
func TestLogReadFallsBackToSnapshotWhenCredentialDeleted(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "en")

	require.NoError(t, svc.AddRemovalLog([]clientmodels.LogCredential{{
		CredentialId: "https://example.com/vct/removed",
		Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
		Name:         "Removed Credential",
		Issuer:       clientmodels.TrustedParty{Id: "https://example.com/issuer", Name: "Test Issuer"},
		Attributes:   []clientmodels.Attribute{},
	}}))

	svc.locale = "nl"
	logs, err := svc.GetNewestLogs(10)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	cred := logs[0].RemovalLog.Credentials[0]
	require.Equal(t, "Removed Credential", cred.Name)
	require.Equal(t, "Test Issuer", cred.Issuer.Name)
}

// TestLogReadDoesNotBorrowIssuerNameFromDifferentIssuer pins the issuer-id
// guard: a stored batch of the same credential type but from another issuer
// must not supply issuer-name translations for this log entry, while the
// credential name (keyed by type) still re-resolves.
func TestLogReadDoesNotBorrowIssuerNameFromDifferentIssuer(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "en")

	const vct = "https://example.com/vct/test"
	newLiveBatch(t, svc, vct, "https://other-issuer.example.com")

	require.NoError(t, svc.AddDisclosureLog(
		clientmodels.TrustedParty{Id: "https://verifier.example.com", Name: "Test Verifier"},
		[]clientmodels.LogCredential{{
			CredentialId: vct,
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc},
			Name:         "Test Credential",
			Issuer:       clientmodels.TrustedParty{Id: "https://example.com/issuer", Name: "Original Issuer"},
			Attributes:   []clientmodels.Attribute{},
		}},
	))

	svc.locale = "nl"
	logs, err := svc.GetNewestLogs(10)
	require.NoError(t, err)

	cred := logs[0].DisclosureLog.Credentials[0]
	require.Equal(t, "Testgegeven", cred.Name, "credential name re-resolves by type")
	require.Equal(t, "Original Issuer", cred.Issuer.Name, "issuer name stays the snapshot when the batch issuer differs")
}

// TestLogReadDecodesLegacyMapFormat pins backward compatibility with log rows
// written before the wallet became locale-aware: every text field — including
// display names and descriptions inside the attributes blob — was stored as a
// TranslatedString map. The credential is deliberately absent from the wallet,
// so live-metadata re-resolution cannot mask a decode failure and the legacy
// maps themselves must resolve.
func TestLogReadDecodesLegacyMapFormat(t *testing.T) {
	svc := newTestLogServiceWithLocale(t, "nl")

	entry := &models.EudiLogEntry{
		ID:            datatypes.NewUUIDv4(),
		Type:          string(clientmodels.LogType_Disclosure),
		Protocol:      string(clientmodels.Protocol_OpenID4VP),
		CreatedAt:     time.Now(),
		RequestorId:   "https://verifier.example.com",
		RequestorName: []byte(`{"en":"Test Verifier","nl":"Test Controleur"}`),
		Credentials: []models.EudiLogCredential{{
			ID:           datatypes.NewUUIDv4(),
			CredentialId: "https://example.com/vct/legacy",
			Formats:      []byte(`["dc+sd-jwt"]`),
			Name:         []byte(`{"en":"Legacy Credential","nl":"Oud Gegeven"}`),
			IssuerName:   []byte(`{"en":"Legacy Issuer","nl":"Oude Uitgever"}`),
			IssuerId:     "https://example.com/issuer",
			Attributes:   []byte(`[{"claim_path":["email"],"display_name":{"en":"Email","nl":"E-mailadres"},"description":{"en":"Your email","nl":"Uw e-mail"},"value":{"type":"string","string":"a@b.com"}}]`),
			IssueURL:     []byte(`{"en":"https://issue.example.com/en","nl":"https://issue.example.com/nl"}`),
		}},
	}
	require.NoError(t, svc.store.AddLog(entry))

	logs, err := svc.GetNewestLogs(10)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	require.Equal(t, "Test Controleur", logs[0].DisclosureLog.Verifier.Name)
	cred := logs[0].DisclosureLog.Credentials[0]
	require.Equal(t, "Oud Gegeven", cred.Name)
	require.Equal(t, "Oude Uitgever", cred.Issuer.Name)
	require.NotNil(t, cred.IssueURL)
	require.Equal(t, "https://issue.example.com/nl", *cred.IssueURL)

	require.Len(t, cred.Attributes, 1)
	attr := cred.Attributes[0]
	require.NotNil(t, attr.DisplayName, "legacy map display names must survive the decode")
	require.Equal(t, "E-mailadres", *attr.DisplayName)
	require.NotNil(t, attr.Description)
	require.Equal(t, "Uw e-mail", *attr.Description)
	require.NotNil(t, attr.Value)
	require.Equal(t, "a@b.com", *attr.Value.String)
}
