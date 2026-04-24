package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	credLogoManager     filesystem.LogoManager
	issuerLogoManager   filesystem.LogoManager
	verifierLogoManager filesystem.LogoManager
}

func NewEudiLogService(s storage.Storage) EudiLogService {
	return &eudiLogService{
		store:               db.NewEudiLogStore(s.Db()),
		credLogoManager:     s.FileSystem().Credentials().LogoManager(),
		issuerLogoManager:   s.FileSystem().Issuers().LogoManager(),
		verifierLogoManager: s.FileSystem().Verifiers().LogoManager(),
	}
}

func (s *eudiLogService) AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []*clientmodels.Credential) error {
	requestorName, err := json.Marshal(issuer.Name)
	if err != nil {
		return err
	}
	creds, err := s.credentialsToLogCredentials(credentials)
	if err != nil {
		return err
	}
	entry := &models.EudiLogEntry{
		ID:                    datatypes.NewUUIDv4(),
		Type:                  string(clientmodels.LogType_Issuance),
		Protocol:              string(protocol),
		CreatedAt:             time.Now(),
		RequestorId:           issuer.Id,
		RequestorName:         requestorName,
		RequestorLogoFilename: s.saveRequestorLogo(issuer),
		Credentials:           creds,
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error {
	requestorName, err := json.Marshal(verifier.Name)
	if err != nil {
		return err
	}
	creds, err := s.logCredentialsToModelCredentials(credentials)
	if err != nil {
		return err
	}
	entry := &models.EudiLogEntry{
		ID:                    datatypes.NewUUIDv4(),
		Type:                  string(clientmodels.LogType_Disclosure),
		Protocol:              string(clientmodels.Protocol_OpenID4VP),
		CreatedAt:             time.Now(),
		RequestorId:           verifier.Id,
		RequestorName:         requestorName,
		RequestorLogoFilename: s.saveRequestorLogo(verifier),
		Credentials:           creds,
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddRemovalLog(credentials []*clientmodels.Credential) error {
	creds, err := s.credentialsToLogCredentials(credentials)
	if err != nil {
		return err
	}
	entry := &models.EudiLogEntry{
		ID:          datatypes.NewUUIDv4(),
		Type:        string(clientmodels.LogType_CredentialRemoval),
		CreatedAt:   time.Now(),
		Credentials: creds,
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
	entries, err := s.store.GetLogsBefore(before, max)
	if err != nil {
		return nil, err
	}
	return s.entriesToLogInfos(entries)
}

// --- conversion helpers ---

func (s *eudiLogService) credentialsToLogCredentials(creds []*clientmodels.Credential) ([]models.EudiLogCredential, error) {
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
		formatsJSON, err := json.Marshal(formats)
		if err != nil {
			return nil, fmt.Errorf("marshal formats for %q: %w", c.CredentialId, err)
		}
		nameJSON, err := json.Marshal(c.Name)
		if err != nil {
			return nil, fmt.Errorf("marshal name for %q: %w", c.CredentialId, err)
		}
		issuerNameJSON, err := json.Marshal(c.Issuer.Name)
		if err != nil {
			return nil, fmt.Errorf("marshal issuer name for %q: %w", c.CredentialId, err)
		}
		attrsJSON, err := json.Marshal(c.Attributes)
		if err != nil {
			return nil, fmt.Errorf("marshal attributes for %q: %w", c.CredentialId, err)
		}
		issueURLJSON, err := json.Marshal(c.IssueURL)
		if err != nil {
			return nil, fmt.Errorf("marshal issue URL for %q: %w", c.CredentialId, err)
		}
		result[i] = models.EudiLogCredential{
			ID:                  datatypes.NewUUIDv4(),
			CredentialId:        c.CredentialId,
			Formats:             formatsJSON,
			Name:                nameJSON,
			IssuerName:          issuerNameJSON,
			IssuerId:            c.Issuer.Id,
			Attributes:          attrsJSON,
			IssuanceDate:        c.IssuanceDate,
			ExpiryDate:          c.ExpiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURLJSON,
			LogoFilename:        saveLogoFromBase64(s.credLogoManager, c.CredentialId, c.Image),
			IssuerLogoFilename:  saveLogoFromBase64(s.issuerLogoManager, c.Issuer.Id, c.Issuer.Image),
		}
	}
	return result, nil
}

func (s *eudiLogService) logCredentialsToModelCredentials(creds []clientmodels.LogCredential) ([]models.EudiLogCredential, error) {
	result := make([]models.EudiLogCredential, len(creds))
	for i, c := range creds {
		formatsJSON, err := json.Marshal(c.Formats)
		if err != nil {
			return nil, fmt.Errorf("marshal formats for %q: %w", c.CredentialId, err)
		}
		nameJSON, err := json.Marshal(c.Name)
		if err != nil {
			return nil, fmt.Errorf("marshal name for %q: %w", c.CredentialId, err)
		}
		issuerNameJSON, err := json.Marshal(c.Issuer.Name)
		if err != nil {
			return nil, fmt.Errorf("marshal issuer name for %q: %w", c.CredentialId, err)
		}
		attrsJSON, err := json.Marshal(c.Attributes)
		if err != nil {
			return nil, fmt.Errorf("marshal attributes for %q: %w", c.CredentialId, err)
		}
		issueURLJSON, err := json.Marshal(c.IssueURL)
		if err != nil {
			return nil, fmt.Errorf("marshal issue URL for %q: %w", c.CredentialId, err)
		}
		result[i] = models.EudiLogCredential{
			ID:                  datatypes.NewUUIDv4(),
			CredentialId:        c.CredentialId,
			Formats:             formatsJSON,
			Name:                nameJSON,
			IssuerName:          issuerNameJSON,
			IssuerId:            c.Issuer.Id,
			Attributes:          attrsJSON,
			IssuanceDate:        c.IssuanceDate,
			ExpiryDate:          c.ExpiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURLJSON,
			LogoFilename:        saveLogoFromBase64(s.credLogoManager, c.CredentialId, c.Image),
			IssuerLogoFilename:  saveLogoFromBase64(s.issuerLogoManager, c.Issuer.Id, c.Issuer.Image),
		}
	}
	return result, nil
}

func (s *eudiLogService) entriesToLogInfos(entries []*models.EudiLogEntry) ([]clientmodels.LogInfo, error) {
	result := make([]clientmodels.LogInfo, 0, len(entries))
	for _, e := range entries {
		info, err := s.entryToLogInfo(e)
		if err != nil {
			eudi.Logger.Warnf("failed to convert log entry %s: %v", e.ID, err)
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

func (s *eudiLogService) entryToLogInfo(e *models.EudiLogEntry) (clientmodels.LogInfo, error) {
	logCreds, err := modelCredentialsToLogCredentials(e.Credentials, s.credLogoManager, s.issuerLogoManager)
	if err != nil {
		return clientmodels.LogInfo{}, err
	}

	info := clientmodels.LogInfo{
		Type: clientmodels.LogType(e.Type),
		Time: e.CreatedAt,
	}

	var requestorName clientmodels.TranslatedString
	if e.RequestorName != nil {
		if err := json.Unmarshal(e.RequestorName, &requestorName); err != nil {
			eudi.Logger.Warnf("failed to unmarshal requestor name for log %s: %v", e.ID, err)
		}
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

func modelCredentialsToLogCredentials(creds []models.EudiLogCredential, credLogoManager filesystem.LogoManager, issuerLogoManager filesystem.LogoManager) ([]clientmodels.LogCredential, error) {
	result := make([]clientmodels.LogCredential, len(creds))
	for i, c := range creds {
		var name clientmodels.TranslatedString
		if c.Name != nil {
			if err := json.Unmarshal(c.Name, &name); err != nil {
				eudi.Logger.Warnf("failed to unmarshal credential name for %q: %v", c.CredentialId, err)
			}
		}
		var issuerName clientmodels.TranslatedString
		if c.IssuerName != nil {
			if err := json.Unmarshal(c.IssuerName, &issuerName); err != nil {
				eudi.Logger.Warnf("failed to unmarshal issuer name for %q: %v", c.CredentialId, err)
			}
		}
		var attrs []clientmodels.Attribute
		if c.Attributes != nil {
			if err := json.Unmarshal(c.Attributes, &attrs); err != nil {
				eudi.Logger.Warnf("failed to unmarshal attributes for %q: %v", c.CredentialId, err)
			}
		}
		if attrs == nil {
			attrs = []clientmodels.Attribute{}
		}
		var formats []clientmodels.CredentialFormat
		if c.Formats != nil {
			if err := json.Unmarshal(c.Formats, &formats); err != nil {
				eudi.Logger.Warnf("failed to unmarshal formats for %q: %v", c.CredentialId, err)
			}
		}
		if formats == nil {
			formats = []clientmodels.CredentialFormat{}
		}
		var credImage *clientmodels.Image
		if c.LogoFilename != "" && credLogoManager != nil {
			if imageData, err := credLogoManager.GetLogo(c.LogoFilename); err == nil && imageData != nil {
				credImage = &clientmodels.Image{Base64: *imageData}
			}
		}
		var issuerImage *clientmodels.Image
		if c.IssuerLogoFilename != "" && issuerLogoManager != nil {
			if imageData, err := issuerLogoManager.GetLogo(c.IssuerLogoFilename); err == nil && imageData != nil {
				issuerImage = &clientmodels.Image{Base64: *imageData}
			}
		}
		var issueURL *clientmodels.TranslatedString
		if c.IssueURL != nil {
			issueURL = &clientmodels.TranslatedString{}
			if err := json.Unmarshal(c.IssueURL, issueURL); err != nil {
				eudi.Logger.Warnf("failed to unmarshal issue URL for %q: %v", c.CredentialId, err)
				issueURL = nil
			}
		}
		result[i] = clientmodels.LogCredential{
			CredentialId:        c.CredentialId,
			Formats:             formats,
			Name:                name,
			Image:               credImage,
			Issuer:              clientmodels.TrustedParty{Id: c.IssuerId, Name: issuerName, Image: issuerImage},
			Attributes:          attrs,
			IssuanceDate:        c.IssuanceDate,
			ExpiryDate:          c.ExpiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURL,
		}
	}
	return result, nil
}

// saveLogoFromBase64 persists a base64-encoded image to the given logo manager
// under a deterministic filename derived from the provided key (SHA256).
// Returns the filename on success, or "" if no image is available.
func saveLogoFromBase64(manager filesystem.LogoManager, key string, image *clientmodels.Image) string {
	if image == nil || image.Base64 == "" || key == "" {
		return ""
	}
	rawBytes, err := base64.StdEncoding.DecodeString(image.Base64)
	if err != nil {
		return ""
	}
	filename := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
	if _, err := manager.SaveLogo(filename, rawBytes); err != nil {
		return ""
	}
	return filename
}

// saveRequestorLogo persists the requestor's logo image (if any) to the
// verifier logo storage and returns the filename used for storage.
// Returns "" if the requestor has no image.
func (s *eudiLogService) saveRequestorLogo(tp clientmodels.TrustedParty) string {
	return saveLogoFromBase64(s.verifierLogoManager, tp.Id, tp.Image)
}
