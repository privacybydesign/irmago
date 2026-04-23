package services

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/datatypes"
)

// EudiLogService creates and retrieves EUDI activity log entries.
type EudiLogService interface {
	AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []*clientmodels.Credential) error
	AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error
	AddRemovalLog(credentials []*clientmodels.Credential) error
	GetNewestLogs(max int) ([]clientmodels.LogInfo, error)
	GetLogsBefore(before time.Time, max int) ([]clientmodels.LogInfo, error)
}

type eudiLogService struct {
	store               db.EudiLogStore
	credentialStore     db.CredentialStore
	credLogoManager     filesystem.LogoManager
	verifierLogoManager filesystem.LogoManager
}

func NewEudiLogService(s storage.Storage) EudiLogService {
	return &eudiLogService{
		store:               db.NewEudiLogStore(s.Db()),
		credentialStore:     db.NewCredentialStore(s.Db()),
		credLogoManager:     s.FileSystem().Credentials().LogoManager(),
		verifierLogoManager: s.FileSystem().Verifiers().LogoManager(),
	}
}

// resolveLogoFilename looks up the logo filename for a credential by its VCT.
// Returns an empty string if no logo is configured.
func (s *eudiLogService) resolveLogoFilename(credentialId string) string {
	batches, err := s.credentialStore.GetBatchesByVCT(credentialId)
	if err != nil || len(batches) == 0 {
		return ""
	}
	batch := batches[0]
	if batch.CredentialMetadata == nil || len(batch.CredentialMetadata.Display) == 0 {
		return ""
	}
	logoURI := batch.CredentialMetadata.Display[0].LogoURI
	if logoURI == "" {
		return ""
	}
	return s.credLogoManager.GetLogoFilenameWithoutExtensionFromUrl(logoURI)
}

func (s *eudiLogService) AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []*clientmodels.Credential) error {
	entry := &models.EudiLogEntry{
		ID:                    datatypes.NewUUIDv4(),
		Type:                  string(clientmodels.LogType_Issuance),
		Protocol:              string(protocol),
		CreatedAt:             time.Now(),
		RequestorId:           issuer.Id,
		RequestorName:         mustJSON(issuer.Name),
		RequestorLogoFilename: s.saveRequestorLogo(issuer),
		Credentials:           s.credentialsToLogCredentials(credentials),
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error {
	entry := &models.EudiLogEntry{
		ID:                    datatypes.NewUUIDv4(),
		Type:                  string(clientmodels.LogType_Disclosure),
		Protocol:              string(clientmodels.Protocol_OpenID4VP),
		CreatedAt:             time.Now(),
		RequestorId:           verifier.Id,
		RequestorName:         mustJSON(verifier.Name),
		RequestorLogoFilename: s.saveRequestorLogo(verifier),
		Credentials:           s.logCredentialsToModelCredentials(credentials),
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddRemovalLog(credentials []*clientmodels.Credential) error {
	entry := &models.EudiLogEntry{
		ID:          datatypes.NewUUIDv4(),
		Type:        string(clientmodels.LogType_CredentialRemoval),
		CreatedAt:   time.Now(),
		Credentials: s.credentialsToLogCredentials(credentials),
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) GetNewestLogs(max int) ([]clientmodels.LogInfo, error) {
	entries, err := s.store.GetNewestLogs(max)
	if err != nil {
		return nil, err
	}
	return s.entriesToLogInfos(entries)
}

func (s *eudiLogService) GetLogsBefore(before time.Time, max int) ([]clientmodels.LogInfo, error) {
	// Create a dummy entry with the timestamp for the store query.
	entries, err := s.store.GetLogsBefore(&models.EudiLogEntry{CreatedAt: before}, max)
	if err != nil {
		return nil, err
	}
	return s.entriesToLogInfos(entries)
}

// --- conversion helpers ---

func (s *eudiLogService) credentialsToLogCredentials(creds []*clientmodels.Credential) []models.EudiLogCredential {
	result := make([]models.EudiLogCredential, len(creds))
	for i, c := range creds {
		// Derive formats from the credential's instance IDs (one format per key).
		formats := make([]clientmodels.CredentialFormat, 0, len(c.CredentialInstanceIds))
		for f := range c.CredentialInstanceIds {
			formats = append(formats, f)
		}
		// Fall back to BatchInstanceCountsRemaining keys if no instance IDs.
		if len(formats) == 0 {
			for f := range c.BatchInstanceCountsRemaining {
				formats = append(formats, f)
			}
		}
		result[i] = models.EudiLogCredential{
			ID:           datatypes.NewUUIDv4(),
			CredentialId: c.CredentialId,
			Formats:      mustJSON(formats),
			Name:         mustJSON(c.Name),
			IssuerName:   mustJSON(c.Issuer.Name),
			Attributes:   mustJSON(c.Attributes),
			LogoFilename: s.resolveLogoFilename(c.CredentialId),
		}
	}
	return result
}

func (s *eudiLogService) logCredentialsToModelCredentials(creds []clientmodels.LogCredential) []models.EudiLogCredential {
	result := make([]models.EudiLogCredential, len(creds))
	for i, c := range creds {
		result[i] = models.EudiLogCredential{
			ID:           datatypes.NewUUIDv4(),
			CredentialId: c.CredentialId,
			Formats:      mustJSON(c.Formats),
			Name:         mustJSON(c.Name),
			IssuerName:   mustJSON(c.Issuer.Name),
			Attributes:   mustJSON(c.Attributes),
			LogoFilename: s.saveCredentialLogo(c),
		}
	}
	return result
}

func (s *eudiLogService) entriesToLogInfos(entries []*models.EudiLogEntry) ([]clientmodels.LogInfo, error) {
	result := make([]clientmodels.LogInfo, 0, len(entries))
	for _, e := range entries {
		info, err := s.entryToLogInfo(e)
		if err != nil {
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

func (s *eudiLogService) entryToLogInfo(e *models.EudiLogEntry) (clientmodels.LogInfo, error) {
	logCreds, err := modelCredentialsToLogCredentials(e.Credentials, s.credLogoManager)
	if err != nil {
		return clientmodels.LogInfo{}, err
	}

	info := clientmodels.LogInfo{
		Type: clientmodels.LogType(e.Type),
		Time: e.CreatedAt,
	}

	var requestorName clientmodels.TranslatedString
	if e.RequestorName != nil {
		_ = json.Unmarshal(e.RequestorName, &requestorName)
	}
	var requestorImage *clientmodels.Image
	if e.RequestorLogoFilename != "" {
		imageData, err := s.verifierLogoManager.GetLogo(e.RequestorLogoFilename)
		if err == nil && imageData != nil {
			requestorImage = &clientmodels.Image{Base64: *imageData}
		}
	}
	requestor := &clientmodels.TrustedParty{
		Id:    e.RequestorId,
		Name:  requestorName,
		Image: requestorImage,
	}

	switch clientmodels.LogType(e.Type) {
	case clientmodels.LogType_Issuance:
		info.IssuanceLog = &clientmodels.IssuanceLog{
			Protocol:    clientmodels.Protocol(e.Protocol),
			Credentials: logCreds,
			Issuer:      requestor,
		}
	case clientmodels.LogType_Disclosure:
		info.DisclosureLog = &clientmodels.DisclosureLog{
			Protocol:    clientmodels.Protocol(e.Protocol),
			Credentials: logCreds,
			Verifier:    requestor,
		}
	case clientmodels.LogType_CredentialRemoval:
		info.RemovalLog = &clientmodels.RemovalLog{
			Credentials: logCreds,
		}
	}

	return info, nil
}

func modelCredentialsToLogCredentials(creds []models.EudiLogCredential, credLogoManager filesystem.LogoManager) ([]clientmodels.LogCredential, error) {
	result := make([]clientmodels.LogCredential, len(creds))
	for i, c := range creds {
		var name clientmodels.TranslatedString
		if c.Name != nil {
			_ = json.Unmarshal(c.Name, &name)
		}
		var issuerName clientmodels.TranslatedString
		if c.IssuerName != nil {
			_ = json.Unmarshal(c.IssuerName, &issuerName)
		}
		var attrs []clientmodels.Attribute
		if c.Attributes != nil {
			_ = json.Unmarshal(c.Attributes, &attrs)
		}
		if attrs == nil {
			attrs = []clientmodels.Attribute{}
		}
		var formats []clientmodels.CredentialFormat
		if c.Formats != nil {
			_ = json.Unmarshal(c.Formats, &formats)
		}
		if formats == nil {
			formats = []clientmodels.CredentialFormat{}
		}
		var image *clientmodels.Image
		if c.LogoFilename != "" && credLogoManager != nil {
			imageData, err := credLogoManager.GetLogo(c.LogoFilename)
			if err == nil && imageData != nil {
				image = &clientmodels.Image{Base64: *imageData}
			}
		}
		result[i] = clientmodels.LogCredential{
			CredentialId: c.CredentialId,
			Formats:      formats,
			Name:         name,
			Image:        image,
			Issuer:       clientmodels.TrustedParty{Name: issuerName},
			Attributes:   attrs,
		}
	}
	return result, nil
}

// saveCredentialLogo persists a credential's logo image to the credential
// logo storage. It first tries to resolve the filename from the database
// (works for EUDI-issued credentials). If that fails but the LogCredential
// has pre-resolved image data (e.g. from the OpenID4VP handler), it saves
// that image to disk instead.
func (s *eudiLogService) saveCredentialLogo(cred clientmodels.LogCredential) string {
	if filename := s.resolveLogoFilename(cred.CredentialId); filename != "" {
		return filename
	}
	if cred.Image == nil || cred.Image.Base64 == "" {
		return ""
	}
	rawBytes, err := base64.StdEncoding.DecodeString(cred.Image.Base64)
	if err != nil {
		eudi.Logger.Warnf("failed to decode credential logo base64 for %q: %v", cred.CredentialId, err)
		return ""
	}
	filename := cred.CredentialId
	if _, err := s.credLogoManager.SaveLogo(filename, rawBytes); err != nil {
		eudi.Logger.Warnf("failed to save credential logo for %q: %v", cred.CredentialId, err)
		return ""
	}
	return filename
}

// saveRequestorLogo persists the requestor's logo image (if any) to the
// verifier logo storage and returns the filename used for storage.
// Returns "" if the requestor has no image.
func (s *eudiLogService) saveRequestorLogo(tp clientmodels.TrustedParty) string {
	if tp.Image == nil || tp.Image.Base64 == "" || tp.Id == "" {
		return ""
	}
	rawBytes, err := base64.StdEncoding.DecodeString(tp.Image.Base64)
	if err != nil {
		return ""
	}
	filename := tp.Id
	if _, err := s.verifierLogoManager.SaveLogo(filename, rawBytes); err != nil {
		return ""
	}
	return filename
}

func mustJSON(v any) datatypes.JSON {
	b, _ := json.Marshal(v)
	return b
}
