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

// EudiLogService creates, retrieves and queries activity log entries, for
// every protocol: IRMA sessions are logged here too.
type EudiLogService interface {
	AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error
	AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error
	AddRemovalLog(credentials []clientmodels.LogCredential) error
	// AddLog writes one entry, with everything the specific Add methods
	// cannot express (roles, signed message, multi-language texts).
	AddLog(w LogWrite) error
	// AddLogs writes entries in one transaction, skipping ids that are
	// already stored, and marks migration done with them.
	AddLogs(ws []LogWrite, migration string) error

	// IndexLogs brings the derived columns of older entries up to date. The
	// query methods call it, so it only needs calling to do the work early.
	IndexLogs() error
	QueryLogs(q clientmodels.LogQuery) (clientmodels.LogPage, error)
	// GetLog returns one entry, or nil when there is none with this id.
	GetLog(id string) (*clientmodels.LogInfo, error)
	CredentialActivity(hashes []string) (map[string]clientmodels.CredentialActivity, error)
	ListParties(f clientmodels.LogFilter, limit int) ([]clientmodels.PartySummary, error)
	// UpdateCredentialHash points the log entries of a card at its new hash.
	UpdateCredentialHash(oldHash, newHash string) error
	// DeleteLogsForCredentialTypes deletes the entries with a credential whose
	// type starts with one of the prefixes.
	DeleteLogsForCredentialTypes(prefixes []string) error
	// InferCredentialHashes matches log credentials without a card hash to
	// the given cards, once (see InferLogCredentialHashes).
	InferCredentialHashes(cards []*clientmodels.Credential, migration string) error
}

// LogWrite is one log entry to write.
type LogWrite struct {
	// ID is the entry id; zero for a new random one. Set it to make writing
	// the same entry twice idempotent, as a migration does.
	ID       datatypes.UUID
	Type     clientmodels.LogType
	Protocol clientmodels.Protocol
	// Time is when it happened; zero for now.
	Time      time.Time
	Requestor *clientmodels.TrustedParty
	// RequestorNames, when set, is stored in place of Requestor.Name so the
	// name follows the locale.
	RequestorNames clientmodels.TranslatedString
	Credentials    []LogWriteCredential
	SignedMessage  string
	Hidden         bool
	Source         string
	IrmaRaw        []byte
}

// LogWriteCredential is one credential of a LogWrite.
type LogWriteCredential struct {
	clientmodels.LogCredential
	Role clientmodels.LogRole
	// Texts, when set, are stored in place of the resolved strings, so the
	// entry follows the locale and is found in every language.
	Texts *LogCredentialTexts
}

// LogCredentialTexts are the translations of a log credential's texts.
type LogCredentialTexts struct {
	Name       clientmodels.TranslatedString
	IssuerName clientmodels.TranslatedString
	IssueURL   clientmodels.TranslatedString
	// Attributes holds the name and description per attribute, by
	// clientmodels.ClaimPathKey of its claim path.
	Attributes map[string]LogAttributeTexts
}

type LogAttributeTexts struct {
	Name        clientmodels.TranslatedString
	Description clientmodels.TranslatedString
}

type eudiLogService struct {
	store               db.EudiLogStore
	displaySources      []CredentialDisplaySource
	credLogoManager     filesystem.LogoManager
	issuerLogoManager   filesystem.LogoManager
	verifierLogoManager filesystem.LogoManager
	locale              string
}

func NewEudiLogService(s storage.Storage, locale string) EudiLogService {
	return &eudiLogService{
		store:               db.NewEudiLogStore(s.Db()),
		displaySources:      NewCredentialDisplaySources(s.Db()),
		credLogoManager:     s.FileSystem().Credentials().LogoManager(),
		issuerLogoManager:   s.FileSystem().Issuers().LogoManager(),
		verifierLogoManager: s.FileSystem().Verifiers().LogoManager(),
		locale:              locale,
	}
}

func (s *eudiLogService) AddIssuanceLog(protocol clientmodels.Protocol, issuer clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error {
	return s.AddLog(LogWrite{
		Type:        clientmodels.LogType_Issuance,
		Protocol:    protocol,
		Requestor:   &issuer,
		Credentials: withRole(credentials, clientmodels.LogRole_Issued),
	})
}

func (s *eudiLogService) AddDisclosureLog(verifier clientmodels.TrustedParty, credentials []clientmodels.LogCredential) error {
	return s.AddLog(LogWrite{
		Type:        clientmodels.LogType_Disclosure,
		Protocol:    clientmodels.Protocol_OpenID4VP,
		Requestor:   &verifier,
		Credentials: withRole(credentials, clientmodels.LogRole_Disclosed),
	})
}

func (s *eudiLogService) AddRemovalLog(credentials []clientmodels.LogCredential) error {
	return s.AddLog(LogWrite{
		Type:        clientmodels.LogType_CredentialRemoval,
		Credentials: withRole(credentials, clientmodels.LogRole_Removed),
	})
}

func withRole(creds []clientmodels.LogCredential, role clientmodels.LogRole) []LogWriteCredential {
	result := make([]LogWriteCredential, len(creds))
	for i, c := range creds {
		result[i] = LogWriteCredential{LogCredential: c, Role: role}
	}
	return result
}

func (s *eudiLogService) AddLog(w LogWrite) error {
	entry, err := s.toModelEntry(w)
	if err != nil {
		return err
	}
	return s.store.AddLog(entry)
}

func (s *eudiLogService) AddLogs(ws []LogWrite, migration string) error {
	entries := make([]*models.EudiLogEntry, 0, len(ws))
	for _, w := range ws {
		entry, err := s.toModelEntry(w)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
	}
	return s.store.AddLogs(entries, migration)
}

func (s *eudiLogService) toModelEntry(w LogWrite) (*models.EudiLogEntry, error) {
	creds, err := s.logCredentialsToModelCredentials(w.Credentials)
	if err != nil {
		return nil, err
	}

	id := w.ID
	if id == (datatypes.UUID{}) {
		id = datatypes.NewUUIDv4()
	}
	created := w.Time
	if created.IsZero() {
		created = time.Now()
	}
	entry := &models.EudiLogEntry{
		ID:          id,
		Type:        string(w.Type),
		Protocol:    string(w.Protocol),
		CreatedAt:   created,
		Credentials: creds,
		IrmaRaw:     w.IrmaRaw,
	}
	if w.Hidden {
		entry.Hidden = &w.Hidden
	}
	if w.SignedMessage != "" {
		entry.SignedMessage = &w.SignedMessage
	}
	if w.Source != "" {
		entry.Source = &w.Source
	}

	if r := w.Requestor; r != nil {
		var name any = r.Name
		if len(w.RequestorNames) > 0 {
			name = w.RequestorNames
		}
		if entry.RequestorName, err = json.Marshal(name); err != nil {
			return nil, err
		}
		if entry.RequestorDetails, err = partyDetails(r); err != nil {
			return nil, err
		}
		entry.RequestorId = r.Id
		entry.RequestorVerified = r.Verified
		saveLogoFromBase64(s.verifierLogoManager, r.Id, r.Image)
	}

	indexEntry(entry)
	return entry, nil
}

// partyDetails encodes a party without its name and image, which are stored
// on their own.
func partyDetails(p *clientmodels.TrustedParty) (datatypes.JSON, error) {
	details := *p
	details.Name = ""
	details.Image = nil
	return json.Marshal(details)
}

// --- conversion helpers ---

func (s *eudiLogService) logCredentialsToModelCredentials(creds []LogWriteCredential) ([]models.EudiLogCredential, error) {
	result := make([]models.EudiLogCredential, len(creds))
	for i, c := range creds {
		texts := c.Texts
		if texts == nil {
			texts = &LogCredentialTexts{}
		}
		formatsJSON, err := json.Marshal(c.Formats)
		if err != nil {
			return nil, fmt.Errorf("marshal formats for %q: %w", c.CredentialId, err)
		}
		nameJSON, err := json.Marshal(textOr(texts.Name, c.Name))
		if err != nil {
			return nil, fmt.Errorf("marshal name for %q: %w", c.CredentialId, err)
		}
		issuerNameJSON, err := json.Marshal(textOr(texts.IssuerName, c.Issuer.Name))
		if err != nil {
			return nil, fmt.Errorf("marshal issuer name for %q: %w", c.CredentialId, err)
		}
		attrsJSON, err := json.Marshal(writtenAttributes(c.Attributes, texts.Attributes))
		if err != nil {
			return nil, fmt.Errorf("marshal attributes for %q: %w", c.CredentialId, err)
		}
		var issueURL any = c.IssueURL
		if len(texts.IssueURL) > 0 {
			issueURL = texts.IssueURL
		}
		issueURLJSON, err := json.Marshal(issueURL)
		if err != nil {
			return nil, fmt.Errorf("marshal issue URL for %q: %w", c.CredentialId, err)
		}
		issuerDetails, err := partyDetails(&c.Issuer)
		if err != nil {
			return nil, fmt.Errorf("marshal issuer for %q: %w", c.CredentialId, err)
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
		role := string(c.Role)
		position := i
		result[i] = models.EudiLogCredential{
			ID:                  datatypes.NewUUIDv4(),
			CredentialId:        c.CredentialId,
			Formats:             formatsJSON,
			Name:                nameJSON,
			IssuerName:          issuerNameJSON,
			IssuerId:            c.Issuer.Id,
			IssuerVerified:      c.Issuer.Verified,
			IssuerDetails:       issuerDetails,
			Attributes:          attrsJSON,
			IssuanceDate:        issuanceDate,
			ExpiryDate:          expiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURLJSON,
			Role:                &role,
			Position:            &position,
		}
		if c.Hash != "" {
			hash := c.Hash
			confidence := string(c.HashConfidence)
			if confidence == "" {
				confidence = string(clientmodels.HashConfidence_Exact)
			}
			result[i].CredentialHash = &hash
			result[i].HashConfidence = &confidence
		}
	}
	return result, nil
}

// textOr is the translations when there are any, else the resolved text.
func textOr(texts clientmodels.TranslatedString, resolved string) any {
	if len(texts) > 0 {
		return texts
	}
	return resolved
}

// writtenLogAttribute is an attribute as stored, with its name and
// description either resolved strings or translation maps. storedLogAttribute
// reads both back.
type writtenLogAttribute struct {
	clientmodels.Attribute
	DisplayName any `json:"display_name,omitempty"`
	Description any `json:"description,omitempty"`
}

func writtenAttributes(attrs []clientmodels.Attribute, texts map[string]LogAttributeTexts) []writtenLogAttribute {
	result := make([]writtenLogAttribute, len(attrs))
	for i, a := range attrs {
		result[i] = writtenLogAttribute{Attribute: a}
		if a.DisplayName != nil {
			result[i].DisplayName = *a.DisplayName
		}
		if a.Description != nil {
			result[i].Description = *a.Description
		}
		t, ok := texts[clientmodels.ClaimPathKey(a.ClaimPath)]
		if !ok {
			continue
		}
		if len(t.Name) > 0 {
			result[i].DisplayName = t.Name
		}
		if len(t.Description) > 0 {
			result[i].Description = t.Description
		}
	}
	return result
}

func (s *eudiLogService) entriesToLogInfos(entries []*models.EudiLogEntry) ([]clientmodels.LogInfo, error) {
	if len(entries) == 0 {
		return []clientmodels.LogInfo{}, nil
	}
	displayByVct := s.liveDisplaysByVct()
	result := make([]clientmodels.LogInfo, 0, len(entries))
	for _, e := range entries {
		result = append(result, s.entryToLogInfo(e, displayByVct))
	}
	return result, nil
}

// liveDisplaysByVct resolves, per stored credential type, the display text the
// current locale gives it, so log entries can re-resolve against live metadata
// instead of their creation-time snapshot. Resolving here rather than per log
// credential matters: a page of entries usually covers far fewer credential
// types than it has rows.
//
// Every format contributes its own types (a vct, a docType); the union is keyed
// by that type string. Best-effort: a format whose storage cannot be read
// contributes nothing and its logs fall back to their snapshot.
func (s *eudiLogService) liveDisplaysByVct() map[string]ResolvedBatchDisplay {
	result := map[string]ResolvedBatchDisplay{}
	for _, source := range s.displaySources {
		for typ, display := range source.LiveDisplaysByType(s.locale) {
			if _, taken := result[typ]; !taken {
				result[typ] = display
			}
		}
	}
	return result
}

func (s *eudiLogService) entryToLogInfo(e *models.EudiLogEntry, displayByVct map[string]ResolvedBatchDisplay) clientmodels.LogInfo {
	info := clientmodels.LogInfo{
		ID:   e.ID.String(),
		Type: clientmodels.LogType(e.Type),
		Time: e.CreatedAt,
	}
	if e.CreatedAtNs != nil {
		info.Time = time.Unix(0, *e.CreatedAtNs)
	}

	requestor := s.requestorOf(e)

	// Split the credentials by what happened to them. Entries written before
	// roles were stored have the role their entry type implies.
	issued := []clientmodels.LogCredential{}
	disclosed := []clientmodels.LogCredential{}
	all := s.modelCredentialsToLogCredentials(e.Credentials, displayByVct)
	for i, c := range e.Credentials {
		if roleOf(e.Type, &c) == clientmodels.LogRole_Disclosed && e.Type == string(clientmodels.LogType_Issuance) {
			disclosed = append(disclosed, all[i])
		} else {
			issued = append(issued, all[i])
		}
	}

	switch clientmodels.LogType(e.Type) {
	case clientmodels.LogType_Issuance:
		info.IssuanceLog = &clientmodels.IssuanceLog{
			Protocol:             clientmodels.Protocol(e.Protocol),
			Credentials:          issued,
			DisclosedCredentials: disclosed,
			Issuer:               requestor,
		}
	case clientmodels.LogType_Disclosure:
		info.DisclosureLog = &clientmodels.DisclosureLog{
			Protocol:    clientmodels.Protocol(e.Protocol),
			Credentials: all,
			Verifier:    requestor,
		}
	case clientmodels.LogType_Signature:
		message := ""
		if e.SignedMessage != nil {
			message = *e.SignedMessage
		}
		info.SignedMessageLog = &clientmodels.SignedMessageLog{
			DisclosureLog: clientmodels.DisclosureLog{
				Protocol:    clientmodels.Protocol(e.Protocol),
				Credentials: all,
				Verifier:    requestor,
			},
			Message: message,
		}
	case clientmodels.LogType_CredentialRemoval:
		info.RemovalLog = &clientmodels.RemovalLog{
			Credentials: all,
		}
	}

	return info
}

// requestorOf is the party on the other side of an entry, with the trust
// details stored with it.
func (s *eudiLogService) requestorOf(e *models.EudiLogEntry) *clientmodels.TrustedParty {
	requestor := &clientmodels.TrustedParty{}
	if len(e.RequestorDetails) > 0 {
		if err := json.Unmarshal(e.RequestorDetails, requestor); err != nil {
			eudi.Logger.Warnf("failed to unmarshal requestor details: %v", err)
			requestor = &clientmodels.TrustedParty{}
		}
	}
	requestor.Id = e.RequestorId
	requestor.Name = decodeStoredText(e.RequestorName, s.locale)
	requestor.Image = eudi.LoadLogoImage(s.verifierLogoManager, e.RequestorId)
	requestor.Verified = e.RequestorVerified
	return requestor
}

// roleOf is the stored role of a log credential, or for entries written
// before roles were stored, the role its entry type implies.
func roleOf(entryType string, c *models.EudiLogCredential) clientmodels.LogRole {
	if c.Role != nil && *c.Role != "" {
		return clientmodels.LogRole(*c.Role)
	}
	switch clientmodels.LogType(entryType) {
	case clientmodels.LogType_Issuance:
		return clientmodels.LogRole_Issued
	case clientmodels.LogType_CredentialRemoval:
		return clientmodels.LogRole_Removed
	default:
		return clientmodels.LogRole_Disclosed
	}
}

func (s *eudiLogService) modelCredentialsToLogCredentials(creds []models.EudiLogCredential, displayByVct map[string]ResolvedBatchDisplay) []clientmodels.LogCredential {
	locale := s.locale
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
		credImage := eudi.LoadLogoImage(s.credLogoManager, c.CredentialId)
		issuerImage := eudi.LoadLogoImage(s.issuerLogoManager, c.IssuerId)
		issueURL := decodeOptionalStoredText(json.RawMessage(c.IssueURL), locale)

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
		if live, ok := displayByVct[c.CredentialId]; ok {
			if live.CredentialName != "" {
				name = live.CredentialName
			}
			if live.IssuerName != "" && canReResolveIssuerName(c.IssuerId, issuerName, live) {
				issuerName = live.IssuerName
			}
			reResolveAttributeNames(attrs, live.ClaimNames)
		}

		issuer := clientmodels.TrustedParty{}
		if len(c.IssuerDetails) > 0 {
			if err := json.Unmarshal(c.IssuerDetails, &issuer); err != nil {
				eudi.Logger.Warnf("failed to unmarshal issuer details for %q: %v", c.CredentialId, err)
				issuer = clientmodels.TrustedParty{}
			}
		}
		issuer.Id, issuer.Name, issuer.Image, issuer.Verified = c.IssuerId, issuerName, issuerImage, c.IssuerVerified

		var hash string
		var confidence clientmodels.HashConfidence
		if c.CredentialHash != nil {
			hash = *c.CredentialHash
		}
		if c.HashConfidence != nil {
			confidence = clientmodels.HashConfidence(*c.HashConfidence)
		}

		result[i] = clientmodels.LogCredential{
			CredentialId:        c.CredentialId,
			Formats:             formats,
			Name:                name,
			Image:               credImage,
			Issuer:              issuer,
			Hash:                hash,
			HashConfidence:      confidence,
			Attributes:          attrs,
			IssuanceDate:        issuanceDate,
			ExpiryDate:          expiryDate,
			Revoked:             c.Revoked,
			RevocationSupported: c.RevocationSupported,
			IssueURL:            issueURL,
		}
	}
	return result
}

// canReResolveIssuerName reports whether the stored credential's issuer
// displays belong to this log entry's issuer, guarding against relabeling a
// log with a different issuer's name when the same credential type was later
// issued by someone else. Either the ids match, or the snapshot name is one of
// the issuer's display names — the latter covers the OpenID4VCI issuance flow,
// which records the issuer's well-known URL while the batch stores the JWT's
// iss claim, so the ids may legitimately use different identifier schemes for
// the same issuer.
func canReResolveIssuerName(issuerId, snapshotName string, live ResolvedBatchDisplay) bool {
	if issuerId == live.IssuerId {
		return true
	}
	if snapshotName == "" {
		return false
	}
	for _, name := range live.IssuerNames {
		if name == snapshotName {
			return true
		}
	}
	return false
}

// reResolveAttributeNames overrides attribute display names with the
// translation the stored credential's live claim metadata resolves for the
// locale. Attributes whose path has no metadata entry (exact or null-wildcard
// match), or whose entry has no translation, keep their snapshot.
func reResolveAttributeNames(attrs []clientmodels.Attribute, claimNames map[string]string) {
	if len(claimNames) == 0 {
		return
	}
	for i := range attrs {
		if d, ok := lookupDisplayName(claimNames, attrs[i].ClaimPath); ok && d != "" {
			attrs[i].DisplayName = &d
		}
	}
}

// storedLogAttribute reads back a clientmodels.Attribute that was written with
// json.Marshal, keeping only the display name and description raw so both the
// current string form and the legacy TranslatedString-map form (entries written
// before the wallet became locale-aware) decode without data loss.
//
// Attribute is embedded rather than re-listed field by field: a hand-written
// mirror would silently stop round-tripping any field added to Attribute later,
// with no error — just a value missing from the activity log. The two fields
// below shadow their embedded namesakes, which Go's JSON decoder resolves in
// their favour because they sit at the shallower depth.
type storedLogAttribute struct {
	clientmodels.Attribute
	DisplayName json.RawMessage `json:"display_name,omitempty"`
	Description json.RawMessage `json:"description,omitempty"`
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
		attrs[i] = s.Attribute
		attrs[i].DisplayName = decodeOptionalStoredText(s.DisplayName, locale)
		attrs[i].Description = decodeOptionalStoredText(s.Description, locale)
	}
	return attrs
}

// decodeOptionalStoredText decodes an optional stored log text field to an
// optional string: absent, null, and unresolvable inputs all yield nil.
func decodeOptionalStoredText(raw json.RawMessage, locale string) *string {
	return clientmodels.PtrIfNonEmpty(decodeStoredText(raw, locale))
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
	mimeType := ""
	if image.MimeType != nil {
		mimeType = *image.MimeType
	}
	if err := manager.Save(key, rawBytes, mimeType); err != nil {
		eudi.Logger.Warnf("failed to cache logo for key %q: %v", key, err)
	}
}
