package services

import (
	"encoding/json"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
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
	store db.EudiLogStore
}

func NewEudiLogService(s storage.Storage) EudiLogService {
	return &eudiLogService{
		store: db.NewEudiLogStore(s.Db()),
	}
}

func (s *eudiLogService) AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []*clientmodels.Credential) error {
	entry := &models.EudiLogEntry{
		ID:            datatypes.NewUUIDv4(),
		Type:          string(clientmodels.LogType_Issuance),
		Protocol:      string(protocol),
		CreatedAt:     time.Now(),
		RequestorId:   issuer.Id,
		RequestorName: mustJSON(issuer.Name),
		Credentials:   credentialsToLogCredentials(credentials),
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error {
	entry := &models.EudiLogEntry{
		ID:            datatypes.NewUUIDv4(),
		Type:          string(clientmodels.LogType_Disclosure),
		Protocol:      string(clientmodels.Protocol_OpenID4VP),
		CreatedAt:     time.Now(),
		RequestorId:   verifier.Id,
		RequestorName: mustJSON(verifier.Name),
		Credentials:   logCredentialsToModelCredentials(credentials),
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddRemovalLog(credentials []*clientmodels.Credential) error {
	entry := &models.EudiLogEntry{
		ID:            datatypes.NewUUIDv4(),
		Type:          string(clientmodels.LogType_CredentialRemoval),
		CreatedAt:     time.Now(),
		Credentials:   credentialsToLogCredentials(credentials),
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) GetNewestLogs(max int) ([]clientmodels.LogInfo, error) {
	entries, err := s.store.GetNewestLogs(max)
	if err != nil {
		return nil, err
	}
	return entriesToLogInfos(entries)
}

func (s *eudiLogService) GetLogsBefore(before time.Time, max int) ([]clientmodels.LogInfo, error) {
	// Create a dummy entry with the timestamp for the store query.
	entries, err := s.store.GetLogsBefore(&models.EudiLogEntry{CreatedAt: before}, max)
	if err != nil {
		return nil, err
	}
	return entriesToLogInfos(entries)
}

// --- conversion helpers ---

func credentialsToLogCredentials(creds []*clientmodels.Credential) []models.EudiLogCredential {
	result := make([]models.EudiLogCredential, len(creds))
	for i, c := range creds {
		result[i] = models.EudiLogCredential{
			ID:           datatypes.NewUUIDv4(),
			CredentialId: c.CredentialId,
			Name:         mustJSON(c.Name),
			IssuerName:   mustJSON(c.Issuer.Name),
			Attributes:   mustJSON(c.Attributes),
		}
	}
	return result
}

func logCredentialsToModelCredentials(creds []clientmodels.LogCredential) []models.EudiLogCredential {
	result := make([]models.EudiLogCredential, len(creds))
	for i, c := range creds {
		result[i] = models.EudiLogCredential{
			ID:           datatypes.NewUUIDv4(),
			CredentialId: c.CredentialId,
			Name:         mustJSON(c.Name),
			IssuerName:   mustJSON(c.Issuer.Name),
			Attributes:   mustJSON(c.Attributes),
		}
	}
	return result
}

func entriesToLogInfos(entries []*models.EudiLogEntry) ([]clientmodels.LogInfo, error) {
	result := make([]clientmodels.LogInfo, len(entries))
	for i, e := range entries {
		info, err := entryToLogInfo(e)
		if err != nil {
			return nil, err
		}
		result[i] = info
	}
	return result, nil
}

func entryToLogInfo(e *models.EudiLogEntry) (clientmodels.LogInfo, error) {
	logCreds, err := modelCredentialsToLogCredentials(e.Credentials)
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
	requestor := &clientmodels.TrustedParty{
		Id:   e.RequestorId,
		Name: requestorName,
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

func modelCredentialsToLogCredentials(creds []models.EudiLogCredential) ([]clientmodels.LogCredential, error) {
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
		result[i] = clientmodels.LogCredential{
			CredentialId: c.CredentialId,
			Name:         name,
			Issuer:       clientmodels.TrustedParty{Name: issuerName},
			Attributes:   attrs,
		}
	}
	return result, nil
}

func mustJSON(v any) datatypes.JSON {
	b, _ := json.Marshal(v)
	return b
}
