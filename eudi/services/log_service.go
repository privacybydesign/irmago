package services

import (
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
	AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error
	AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error
	AddRemovalLog(credentials []clientmodels.LogCredential) error
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

func (s *eudiLogService) AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error {
	creds, err := s.logCredentialsToModelCredentials(credentials)
	if err != nil {
		return err
	}
	return s.addSessionLog(clientmodels.LogType_Issuance, protocol, issuer, creds)
}

func (s *eudiLogService) AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error {
	creds, err := s.logCredentialsToModelCredentials(credentials)
	if err != nil {
		return err
	}
	return s.addSessionLog(clientmodels.LogType_Disclosure, clientmodels.Protocol_OpenID4VP, verifier, creds)
}

func (s *eudiLogService) addSessionLog(logType clientmodels.LogType, protocol clientmodels.Protocol, requestor clientmodels.TrustedParty, creds []models.EudiLogCredential) error {
	requestorName, err := json.Marshal(requestor.Name)
	if err != nil {
		return err
	}
	saveLogoFromBase64(s.verifierLogoManager, requestor.Id, requestor.Image)
	entry := &models.EudiLogEntry{
		ID:            datatypes.NewUUIDv4(),
		Type:          string(logType),
		Protocol:      string(protocol),
		CreatedAt:     time.Now(),
		RequestorId:   requestor.Id,
		RequestorName: requestorName,
		Credentials:   creds,
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddRemovalLog(credentials []clientmodels.LogCredential) error {
	creds, err := s.logCredentialsToModelCredentials(credentials)
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
		var expiryDate datatypes.NullTime
		if c.ExpiryDate != 0 {
			expiryDate = datatypes.NullTime{V: time.Unix(c.ExpiryDate, 0), Valid: true}
		}
		saveLogoFromBase64(s.credLogoManager, c.CredentialId, c.Image)
		saveLogoFromBase64(s.issuerLogoManager, c.Issuer.Id, c.Issuer.Image)
		result[i] = models.EudiLogCredential{
			ID:                  datatypes.NewUUIDv4(),
			CredentialId:        c.CredentialId,
			Formats:             formatsJSON,
			Name:                nameJSON,
			IssuerName:          issuerNameJSON,
			IssuerId:            c.Issuer.Id,
			IssuerVerified:      c.Issuer.Verified,
			Attributes:          attrsJSON,
			IssuanceDate:        time.Unix(c.IssuanceDate, 0),
			ExpiryDate:          expiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURLJSON,
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
	requestorImage := eudi.LoadLogoImage(s.verifierLogoManager, e.RequestorId)
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
		credImage := eudi.LoadLogoImage(credLogoManager, c.CredentialId)
		issuerImage := eudi.LoadLogoImage(issuerLogoManager, c.IssuerId)
		var issueURL *clientmodels.TranslatedString
		if c.IssueURL != nil {
			issueURL = &clientmodels.TranslatedString{}
			if err := json.Unmarshal(c.IssueURL, issueURL); err != nil {
				eudi.Logger.Warnf("failed to unmarshal issue URL for %q: %v", c.CredentialId, err)
				issueURL = nil
			}
		}
		var expiryDate int64
		if c.ExpiryDate.Valid {
			expiryDate = c.ExpiryDate.V.Unix()
		}
		result[i] = clientmodels.LogCredential{
			CredentialId:        c.CredentialId,
			Formats:             formats,
			Name:                name,
			Image:               credImage,
			Issuer:              clientmodels.TrustedParty{Id: c.IssuerId, Name: issuerName, Image: issuerImage, Verified: c.IssuerVerified},
			Attributes:          attrs,
			IssuanceDate:        c.IssuanceDate.Unix(),
			ExpiryDate:          expiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURL,
		}
	}
	return result, nil
}

// saveLogoFromBase64 persists a base64-encoded image to the given logo manager
// under the provided logical key. The manager hashes the key internally; no
// filename is returned because the read path resolves the same key on demand.
func saveLogoFromBase64(manager filesystem.LogoManager, key string, image *clientmodels.Image) {
	if image == nil || image.Base64 == "" || key == "" || manager == nil {
		return
	}
	rawBytes, err := base64.StdEncoding.DecodeString(image.Base64)
	if err != nil {
		return
	}
	if err := manager.Save(key, rawBytes); err != nil {
		eudi.Logger.Warnf("failed to cache logo for key %q: %v", key, err)
	}
}
