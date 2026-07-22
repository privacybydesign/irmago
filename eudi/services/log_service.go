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
	credentialStore     db.CredentialStore
	credLogoManager     filesystem.LogoManager
	issuerLogoManager   filesystem.LogoManager
	verifierLogoManager filesystem.LogoManager
	locale              string
}

func NewEudiLogService(s storage.Storage, locale string) EudiLogService {
	return &eudiLogService{
		store:               db.NewEudiLogStore(s.Db()),
		credentialStore:     db.NewCredentialStore(s.Db()),
		credLogoManager:     s.FileSystem().Credentials().LogoManager(),
		issuerLogoManager:   s.FileSystem().Issuers().LogoManager(),
		verifierLogoManager: s.FileSystem().Verifiers().LogoManager(),
		locale:              locale,
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
		var issuanceDate, expiryDate datatypes.NullTime
		if c.IssuanceDate != nil {
			issuanceDate = datatypes.NullTime{V: time.Unix(*c.IssuanceDate, 0), Valid: true}
		}
		if c.ExpiryDate != nil {
			expiryDate = datatypes.NullTime{V: time.Unix(*c.ExpiryDate, 0), Valid: true}
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
			IssuanceDate:        issuanceDate,
			ExpiryDate:          expiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURLJSON,
		}
	}
	return result, nil
}

func (s *eudiLogService) entriesToLogInfos(entries []*models.EudiLogEntry) ([]clientmodels.LogInfo, error) {
	batchByVct := s.batchesByVct()
	result := make([]clientmodels.LogInfo, 0, len(entries))
	for _, e := range entries {
		info, err := s.entryToLogInfo(e, batchByVct)
		if err != nil {
			eudi.Logger.Warnf("failed to convert log entry %s: %v", e.ID, err)
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

// batchesByVct indexes the stored credential batches by their VCT so log
// entries can re-resolve display text against live metadata for the current
// locale. Best-effort: on a storage error the index is empty and logs fall
// back to their creation-time snapshots. When multiple batches share a VCT,
// one carrying credential metadata is preferred.
func (s *eudiLogService) batchesByVct() map[string]*models.CredentialBatch {
	result := map[string]*models.CredentialBatch{}
	batches, err := s.credentialStore.GetCredentialBatchList()
	if err != nil {
		eudi.Logger.Warnf("failed to load credential batches for log text re-resolution: %v", err)
		return result
	}
	for _, batch := range batches {
		if existing, ok := result[batch.VerifiableCredentialType]; ok && existing.CredentialMetadata != nil {
			continue
		}
		result[batch.VerifiableCredentialType] = batch
	}
	return result
}

func (s *eudiLogService) entryToLogInfo(e *models.EudiLogEntry, batchByVct map[string]*models.CredentialBatch) (clientmodels.LogInfo, error) {
	logCreds, err := modelCredentialsToLogCredentials(e.Credentials, s.credLogoManager, s.issuerLogoManager, s.locale, batchByVct)
	if err != nil {
		return clientmodels.LogInfo{}, err
	}

	info := clientmodels.LogInfo{
		Type: clientmodels.LogType(e.Type),
		Time: e.CreatedAt,
	}

	requestorName := decodeStoredText(e.RequestorName, s.locale)
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

func modelCredentialsToLogCredentials(creds []models.EudiLogCredential, credLogoManager filesystem.LogoManager, issuerLogoManager filesystem.LogoManager, locale string, batchByVct map[string]*models.CredentialBatch) ([]clientmodels.LogCredential, error) {
	result := make([]clientmodels.LogCredential, len(creds))
	for i, c := range creds {
		name := decodeStoredText(c.Name, locale)
		issuerName := decodeStoredText(c.IssuerName, locale)
		attrs := decodeStoredAttributes(c.CredentialId, c.Attributes, locale)
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
		var issueURL *string
		if s := decodeStoredText(c.IssueURL, locale); s != "" {
			issueURL = &s
		}
		var issuanceDate, expiryDate *int64
		if c.IssuanceDate.Valid {
			x := c.IssuanceDate.V.Unix()
			issuanceDate = &x
		}
		if c.ExpiryDate.Valid {
			y := c.ExpiryDate.V.Unix()
			expiryDate = &y
		}

		// Re-resolve display text against live credential metadata when the
		// credential is still in the wallet, so the activity log follows the
		// active locale. The persisted snapshot remains the fallback for
		// deleted credentials, untranslated fields, and verifier names (which
		// have no stored metadata to consult).
		if batch := batchByVct[c.CredentialId]; batch != nil {
			if batch.CredentialMetadata != nil {
				if n := clientmodels.Resolve(CredentialNamesByLanguage(batch.CredentialMetadata.Display), locale); n != "" {
					name = n
				}
			}
			// Guard on issuer id: the same credential type could later be
			// issued by a different issuer, whose translations must not be
			// borrowed for this log entry's issuer.
			if c.IssuerId == batch.CredentialIssuer {
				if n := clientmodels.Resolve(IssuerNamesByLanguage(batch.IssuerDisplay), locale); n != "" {
					issuerName = n
				}
			}
			reResolveAttributeNames(attrs, batch, locale)
		}

		result[i] = clientmodels.LogCredential{
			CredentialId:        c.CredentialId,
			Formats:             formats,
			Name:                name,
			Image:               credImage,
			Issuer:              clientmodels.TrustedParty{Id: c.IssuerId, Name: issuerName, Image: issuerImage, Verified: c.IssuerVerified},
			Attributes:          attrs,
			IssuanceDate:        issuanceDate,
			ExpiryDate:          expiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURL,
		}
	}
	return result, nil
}

// reResolveAttributeNames overrides attribute display names with the
// translation the batch's live claim metadata resolves for the locale.
// Attributes whose path has no metadata entry (exact or null-wildcard match)
// keep their snapshot.
func reResolveAttributeNames(attrs []clientmodels.Attribute, batch *models.CredentialBatch, locale string) {
	if batch.CredentialMetadata == nil {
		return
	}
	lookup := map[string]string{}
	for _, claim := range batch.CredentialMetadata.Claims {
		if len(claim.Display) == 0 {
			continue
		}
		var path []any
		if err := json.Unmarshal(claim.Path, &path); err != nil {
			continue
		}
		if n := clientmodels.Resolve(ClaimNamesByLanguage(claim.Display), locale); n != "" {
			lookup[clientmodels.ClaimPathKey(path)] = n
		}
	}
	if len(lookup) == 0 {
		return
	}
	for i := range attrs {
		if d, ok := lookupDisplayName(lookup, attrs[i].ClaimPath); ok {
			attrs[i].DisplayName = &d
		}
	}
}

// storedLogAttribute mirrors clientmodels.Attribute but keeps the display
// name and description raw, so both the current string form and the legacy
// TranslatedString-map form (entries written before the wallet became
// locale-aware) decode without data loss.
type storedLogAttribute struct {
	ClaimPath      []any                        `json:"claim_path"`
	DisplayName    json.RawMessage              `json:"display_name,omitempty"`
	Description    json.RawMessage              `json:"description,omitempty"`
	Value          *clientmodels.AttributeValue `json:"value,omitempty"`
	RequestedValue *clientmodels.AttributeValue `json:"requested_value,omitempty"`
}

// decodeStoredAttributes decodes a stored log credential's attribute list,
// resolving legacy map-form display names and descriptions with the given
// locale. Never returns nil.
func decodeStoredAttributes(credentialId string, raw []byte, locale string) []clientmodels.Attribute {
	if len(raw) == 0 {
		return []clientmodels.Attribute{}
	}
	var stored []storedLogAttribute
	if err := json.Unmarshal(raw, &stored); err != nil {
		eudi.Logger.Warnf("failed to unmarshal attributes for %q: %v", credentialId, err)
		return []clientmodels.Attribute{}
	}
	attrs := make([]clientmodels.Attribute, len(stored))
	for i, s := range stored {
		attrs[i] = clientmodels.Attribute{
			ClaimPath:      s.ClaimPath,
			DisplayName:    decodeOptionalStoredText(s.DisplayName, locale),
			Description:    decodeOptionalStoredText(s.Description, locale),
			Value:          s.Value,
			RequestedValue: s.RequestedValue,
		}
	}
	return attrs
}

// decodeOptionalStoredText decodes an optional stored log text field to an
// optional string: absent, null, and unresolvable inputs all yield nil.
func decodeOptionalStoredText(raw json.RawMessage, locale string) *string {
	if len(raw) == 0 {
		return nil
	}
	if s := decodeStoredText(raw, locale); s != "" {
		return &s
	}
	return nil
}

// decodeStoredText decodes a stored log text field. New entries store a plain
// JSON string (the text resolved at log-creation time); entries written before
// the wallet became locale-aware store a TranslatedString map, which is
// resolved with the given locale on read. Returns "" for empty or null input.
func decodeStoredText(raw []byte, locale string) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var ts clientmodels.TranslatedString
	if err := json.Unmarshal(raw, &ts); err == nil {
		return clientmodels.Resolve(ts, locale)
	}
	eudi.Logger.Warnf("failed to decode stored log text %q", string(raw))
	return ""
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
