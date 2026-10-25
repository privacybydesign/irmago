package client

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"gorm.io/datatypes"
)

const (
	// irmaLogsMigration moves the IRMA logs from bbolt into the SQL log.
	irmaLogsMigration = "irma-logs-to-sql"
	// logHashBackfill matches the log entries written before card hashes
	// were recorded to the cards in the wallet.
	logHashBackfill = "logs.hash-backfill.v1"
	irmaLogSource   = "irma-bbolt"
)

// irmaLogNamespace makes the ids of migrated IRMA entries deterministic, so a
// migration that is interrupted and run again writes each entry once.
var irmaLogNamespace = uuid.MustParse("5f0e6a3c-3c56-4f6b-9a0e-7d1f4f2b9c11")

// logService is the log service for the current locale.
func (client *Client) logService() services.EudiLogService {
	return services.NewEudiLogService(client.eudiStorage, client.locale())
}

// QueryLogs returns a page of activity log entries, newest first.
func (client *Client) QueryLogs(q clientmodels.LogQuery) (clientmodels.LogPage, error) {
	return client.logService().QueryLogs(q)
}

// GetLog returns one activity log entry by its id, or nil when there is none.
func (client *Client) GetLog(id string) (*clientmodels.LogInfo, error) {
	return client.logService().GetLog(id)
}

// CredentialActivity sums up the activity of the cards with these hashes
// (Credential.Hash). Every hash gets an entry, empty for a card with none.
func (client *Client) CredentialActivity(hashes []string) (map[string]clientmodels.CredentialActivity, error) {
	return client.logService().CredentialActivity(hashes)
}

// ListParties sums up the entries matching f per party, the most recent
// party first. A limit of zero or less returns all.
func (client *Client) ListParties(f clientmodels.LogFilter, limit int) ([]clientmodels.PartySummary, error) {
	return client.logService().ListParties(f, limit)
}

// LoadNewestLogs returns the newest max entries, hidden ones included.
//
// Deprecated: use QueryLogs, which pages without skipping entries that share
// a time.
func (client *Client) LoadNewestLogs(max int) ([]clientmodels.LogInfo, error) {
	page, err := client.QueryLogs(clientmodels.LogQuery{
		Limit:  max,
		Filter: clientmodels.LogFilter{IncludeHidden: true},
	})
	return page.Entries, err
}

// LoadLogsBefore returns the newest max entries strictly before before,
// hidden ones included.
//
// Deprecated: use QueryLogs.
func (client *Client) LoadLogsBefore(before time.Time, max int) ([]clientmodels.LogInfo, error) {
	page, err := client.QueryLogs(clientmodels.LogQuery{
		Limit:  max,
		Filter: clientmodels.LogFilter{IncludeHidden: true, To: &before},
	})
	return page.Entries, err
}

// irmaLogSink writes the logs of IRMA sessions to the SQL log.
type irmaLogSink struct {
	client *Client
}

func (s irmaLogSink) AddLogEntry(entry *irmaclient.LogEntry) error {
	w, err := s.client.irmaLogWrite(entry)
	if err != nil {
		return err
	}
	return s.client.logService().AddLog(w)
}

func (s irmaLogSink) DeleteLogsForSchemes(schemes []irma.SchemeManagerIdentifier) error {
	prefixes := make([]string, len(schemes))
	for i, id := range schemes {
		prefixes[i] = id.String() + "."
	}
	return s.client.logService().DeleteLogsForCredentialTypes(prefixes)
}

// irmaLogWrite converts an IRMA log entry to what the SQL log stores: the
// entry as the activity log shows it, the translations of its texts, the card
// hash of each credential where it can be known, and the entry itself.
func (client *Client) irmaLogWrite(entry *irmaclient.LogEntry) (services.LogWrite, error) {
	raw, err := json.Marshal(entry)
	if err != nil {
		return services.LogWrite{}, err
	}
	w := services.LogWrite{
		Time:    time.Time(entry.Time),
		IrmaRaw: raw,
	}
	if entry.ID != 0 {
		w.ID = datatypes.UUID(uuid.NewSHA1(irmaLogNamespace, fmt.Appendf(nil, "%d", entry.ID)))
		w.Source = irmaLogSource
	}
	if entry.ServerName != nil && len(entry.ServerName.Name) > 0 {
		w.RequestorNames = clientmodels.TranslatedString(entry.ServerName.Name)
	}

	info, err := client.rawLogEntryToLogInfo(entry)
	if err != nil {
		return services.LogWrite{}, err
	}
	w.Type = info.Type

	conf := client.GetIrmaConfiguration()
	add := func(creds []clientmodels.LogCredential, role clientmodels.LogRole) {
		for _, c := range creds {
			w.Credentials = append(w.Credentials, services.LogWriteCredential{
				LogCredential: c,
				Role:          role,
				Texts:         irmaCredentialTexts(conf, c.CredentialId),
			})
		}
	}
	switch {
	case info.IssuanceLog != nil:
		w.Protocol = info.IssuanceLog.Protocol
		w.Requestor = info.IssuanceLog.Issuer
		add(info.IssuanceLog.Credentials, clientmodels.LogRole_Issued)
		add(info.IssuanceLog.DisclosedCredentials, clientmodels.LogRole_Disclosed)
		w.Hidden = issuesKeyshareCredential(conf, info.IssuanceLog.Credentials)
	case info.DisclosureLog != nil:
		w.Protocol = info.DisclosureLog.Protocol
		w.Requestor = info.DisclosureLog.Verifier
		add(info.DisclosureLog.Credentials, clientmodels.LogRole_Disclosed)
	case info.SignedMessageLog != nil:
		w.Protocol = info.SignedMessageLog.Protocol
		w.Requestor = info.SignedMessageLog.Verifier
		w.SignedMessage = info.SignedMessageLog.Message
		add(info.SignedMessageLog.Credentials, clientmodels.LogRole_Disclosed)
	case info.RemovalLog != nil:
		add(info.RemovalLog.Credentials, clientmodels.LogRole_Removed)
	}

	client.setIrmaLogHashes(entry, w.Credentials)
	return w, nil
}

// setIrmaLogHashes fills in the card hash of the credentials of an IRMA log
// entry, where the entry says which card it was:
//   - issued: the request holds every value, and the card hash is over the
//     type and values only, so it is exact even for old entries.
//   - disclosed: the session's disclosure choice names the instance, which
//     the wallet maps to its card while it still holds it.
//   - removed: the entry holds every value, so it is exact too, once the
//     values are paired with their attributes.
func (client *Client) setIrmaLogHashes(entry *irmaclient.LogEntry, creds []services.LogWriteCredential) {
	issued := map[string][]string{}
	if entry.Type == irma.ActionIssuing {
		if request, err := entry.SessionRequest(); err == nil {
			if issuance, ok := request.(*irma.IssuanceRequest); ok {
				for _, cr := range issuance.Credentials {
					if hash, err := requestCardHash(cr); err == nil {
						id := cr.CredentialTypeID.String()
						issued[id] = append(issued[id], hash)
					}
				}
			}
		}
	}

	disclosed := map[string]string{}
	if entry.DisclosureChoice != nil {
		instances := client.getIrmaCredentialInfoList()
		for _, attrs := range entry.DisclosureChoice.Attributes {
			for _, attr := range attrs {
				if attr == nil || attr.CredentialHash == "" {
					continue
				}
				id := attr.Type.CredentialTypeIdentifier().String()
				if _, done := disclosed[id]; done {
					continue
				}
				for _, info := range instances {
					if info.Hash == attr.CredentialHash {
						if hash, err := hashAttributesAndCredType(info); err == nil {
							disclosed[id] = hash
						}
						break
					}
				}
			}
		}
	}

	conf := client.GetIrmaConfiguration()
	for i := range creds {
		c := &creds[i]
		switch c.Role {
		case clientmodels.LogRole_Issued:
			if hashes := issued[c.CredentialId]; len(hashes) > 0 {
				c.Hash, issued[c.CredentialId] = hashes[0], hashes[1:]
			}
		case clientmodels.LogRole_Disclosed:
			c.Hash = disclosed[c.CredentialId]
		case clientmodels.LogRole_Removed:
			id := irma.NewCredentialTypeIdentifier(c.CredentialId)
			credType := conf.CredentialTypes[id]
			if credType == nil || entry.Removed[id] == nil {
				continue
			}
			parts := strings.Split(id.String(), ".")
			if len(parts) != 3 {
				continue
			}
			info := &irma.CredentialInfo{
				SchemeManagerID: parts[0],
				IssuerID:        parts[1],
				ID:              parts[2],
				Attributes:      removedAttributeValues(credType, entry.Removed[id], time.Time(entry.Time)),
			}
			if hash, err := hashAttributesAndCredType(info); err == nil {
				c.Hash = hash
			}
		}
		if c.Hash != "" {
			c.HashConfidence = clientmodels.HashConfidence_Exact
		}
	}
}

// requestCardHash is the card hash of a credential issued over IRMA, from its
// request: what the wallet stores from it hashes to the same.
func requestCardHash(cr *irma.CredentialRequest) (string, error) {
	attrs := map[string]any{}
	for k, v := range cr.Attributes {
		attrs[k] = v
	}
	return irmaclient.CardHash(irmaclient.SdJwtVcBatchMetadata{
		CredentialType: cr.CredentialTypeID.String(),
		Attributes:     attrs,
	}.CredentialInfo())
}

// irmaCredentialTexts are the translations of an IRMA credential type's
// texts, or nil when the type is not in the configuration.
func irmaCredentialTexts(conf *irma.Configuration, credentialId string) *services.LogCredentialTexts {
	credType := conf.CredentialTypes[irma.NewCredentialTypeIdentifier(credentialId)]
	if credType == nil {
		return nil
	}
	texts := &services.LogCredentialTexts{
		Name:       clientmodels.TranslatedString(credType.Name),
		Attributes: map[string]services.LogAttributeTexts{},
	}
	if issuer := conf.Issuers[credType.IssuerIdentifier()]; issuer != nil {
		texts.IssuerName = clientmodels.TranslatedString(issuer.Name)
	}
	if credType.IssueURL != nil {
		texts.IssueURL = credType.IssueURL.ToClientmodels()
	}
	for _, at := range credType.AttributeTypes {
		texts.Attributes[clientmodels.ClaimPathKey([]any{at.ID})] = services.LogAttributeTexts{
			Name:        clientmodels.TranslatedString(at.Name),
			Description: clientmodels.TranslatedString(at.Description),
		}
	}
	return texts
}

// issuesKeyshareCredential reports whether an issuance includes the keyshare
// credential of a scheme, as enrollment does. The activity log hides those.
func issuesKeyshareCredential(conf *irma.Configuration, creds []clientmodels.LogCredential) bool {
	for _, c := range creds {
		for _, manager := range conf.SchemeManagers {
			if manager.KeyshareAttribute != "" && strings.HasPrefix(manager.KeyshareAttribute, c.CredentialId+".") {
				return true
			}
		}
	}
	return false
}

// migrateIrmaLogs moves the IRMA logs from the bbolt store into the SQL log,
// once. The entries are written in one transaction together with the marker
// that the migration is done, and only then deleted from bbolt; an entry that
// cannot be converted any more (its scheme is gone) keeps a reduced row with
// the original entry, rather than being lost. Interrupted anywhere, the next
// start finishes it: the ids are deterministic, so nothing is written twice.
func (client *Client) migrateIrmaLogs() error {
	logs := client.logService()
	done, err := client.logMigrationDone(irmaLogsMigration)
	if err != nil {
		return err
	}
	if !done {
		var writes []services.LogWrite
		err := client.irmaClient.IterateStoredLogs(func(entry *irmaclient.LogEntry) error {
			w, err := client.migratedIrmaLogWrite(entry)
			if err != nil {
				irma.Logger.Warnf("log migration: keeping entry %d without its details: %v", entry.ID, err)
				w, err = reducedIrmaLogWrite(entry)
				if err != nil {
					return err
				}
			}
			writes = append(writes, w)
			return nil
		})
		if err != nil {
			return fmt.Errorf("log migration: failed to read the IRMA logs: %w", err)
		}
		dedupeLogos(writes)
		if err := logs.AddLogs(writes, irmaLogsMigration); err != nil {
			return fmt.Errorf("log migration: failed to write the IRMA logs: %w", err)
		}
	}
	if err := client.irmaClient.DeleteStoredLogs(); err != nil && !isMissingBucket(err) {
		return fmt.Errorf("log migration: failed to delete the migrated IRMA logs: %w", err)
	}
	return nil
}

// migratedIrmaLogWrite is irmaLogWrite for an entry that may predate the
// configuration: converting one whose types the configuration no longer has
// can panic deep in the conversion, which is turned into an error here so the
// entry is kept reduced instead.
func (client *Client) migratedIrmaLogWrite(entry *irmaclient.LogEntry) (w services.LogWrite, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("converting entry panicked: %v", r)
		}
	}()
	return client.irmaLogWrite(entry)
}

// dedupeLogos drops the images after the first of each party and credential
// type: the log stores one logo per key, so the rest would only be written
// again.
func dedupeLogos(writes []services.LogWrite) {
	seen := map[string]bool{}
	first := func(key string) bool {
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	for i := range writes {
		if r := writes[i].Requestor; r != nil && r.Image != nil && !first("r:"+r.Id) {
			r.Image = nil
		}
		for j := range writes[i].Credentials {
			c := &writes[i].Credentials[j]
			if c.Image != nil && !first("c:"+c.CredentialId) {
				c.Image = nil
			}
			if c.Issuer.Image != nil && !first("i:"+c.Issuer.Id) {
				c.Issuer.Image = nil
			}
		}
	}
}

// reducedIrmaLogWrite keeps what can be read from an entry without the
// configuration: its type, time, requestor and credential types.
func reducedIrmaLogWrite(entry *irmaclient.LogEntry) (services.LogWrite, error) {
	raw, err := json.Marshal(entry)
	if err != nil {
		return services.LogWrite{}, err
	}
	w := services.LogWrite{
		ID:       datatypes.UUID(uuid.NewSHA1(irmaLogNamespace, fmt.Appendf(nil, "%d", entry.ID))),
		Time:     time.Time(entry.Time),
		Protocol: clientmodels.Protocol_Irma,
		Source:   irmaLogSource,
		IrmaRaw:  raw,
	}
	switch entry.Type {
	case irma.ActionIssuing:
		w.Type = clientmodels.LogType_Issuance
	case irma.ActionSigning:
		w.Type = clientmodels.LogType_Signature
		w.SignedMessage = string(entry.SignedMessage)
	case irmaclient.ActionRemoval:
		w.Type = clientmodels.LogType_CredentialRemoval
		w.Protocol = ""
	default:
		w.Type = clientmodels.LogType_Disclosure
	}
	if entry.ServerName != nil {
		w.Requestor = &clientmodels.TrustedParty{Id: entry.ServerName.ID.String()}
		w.RequestorNames = clientmodels.TranslatedString(entry.ServerName.Name)
	}

	role := clientmodels.LogRole_Disclosed
	var types []string
	switch entry.Type {
	case irma.ActionIssuing:
		role = clientmodels.LogRole_Issued
		if request, err := entry.SessionRequest(); err == nil {
			for _, cr := range request.(*irma.IssuanceRequest).Credentials {
				types = append(types, cr.CredentialTypeID.String())
			}
		}
	case irmaclient.ActionRemoval:
		role = clientmodels.LogRole_Removed
		for id := range entry.Removed {
			types = append(types, id.String())
		}
	default:
		if request, err := entry.SessionRequest(); err == nil && request != nil {
			for id := range request.Identifiers().CredentialTypes {
				types = append(types, id.String())
			}
		}
	}
	for _, id := range types {
		w.Credentials = append(w.Credentials, services.LogWriteCredential{
			LogCredential: clientmodels.LogCredential{
				CredentialId: id,
				Name:         id,
				Formats:      []clientmodels.CredentialFormat{},
				Attributes:   []clientmodels.Attribute{},
				Issuer:       clientmodels.TrustedParty{Id: irma.NewCredentialTypeIdentifier(id).IssuerIdentifier().String()},
			},
			Role: role,
		})
	}
	return w, nil
}

func isMissingBucket(err error) bool {
	return err != nil && strings.Contains(err.Error(), "bucket not found")
}

func (client *Client) logMigrationDone(name string) (bool, error) {
	return services.LogMigrationDone(client.eudiStorage, name)
}

// backfillLogHashes matches the log credentials that have no card hash to
// the cards in the wallet, once. See EudiLogService.InferCredentialHashes.
func (client *Client) backfillLogHashes() error {
	creds, err := client.getCredentialsIncludingKeyshare()
	if err != nil {
		return err
	}
	return client.logService().InferCredentialHashes(creds, logHashBackfill)
}
