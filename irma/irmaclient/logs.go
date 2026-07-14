package irmaclient

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
)

// CredentialLog is the internal storage format for a credential in a log entry.
type CredentialLog struct {
	Formats        []clientmodels.CredentialFormat
	CredentialType string
	Attributes     map[string]string
}

// LogTime is the timestamp type used for LogEntry.Time. It marshals at
// nanosecond precision so log pagination by time does not collapse entries
// that fall within the same second. UnmarshalJSON also accepts the legacy
// integer-seconds encoding written by older client versions.
type LogTime time.Time

func (t LogTime) MarshalJSON() ([]byte, error) {
	return time.Time(t).MarshalJSON()
}

func (t *LogTime) UnmarshalJSON(b []byte) error {
	var tt time.Time
	if err := tt.UnmarshalJSON(b); err == nil {
		*t = LogTime(tt)
		return nil
	}
	var secs int64
	if err := json.Unmarshal(b, &secs); err != nil {
		return err
	}
	*t = LogTime(time.Unix(secs, 0))
	return nil
}

// ===========================================================================

type LogsStorage interface {
	AddLogEntry(entry *LogEntry) error
	DeleteLogEntry(entryId uint64) error
	LoadNewestLogs(max int) ([]*LogEntry, error)
	LoadLogsBeforeTime(before time.Time, max int) ([]*LogEntry, error)
	DeleteLogs() error
}

type OpenID4VPDisclosureLog struct {
	DisclosedCredentials []CredentialLog
}

// LogEntry is a log entry of a past event.
type LogEntry struct {
	// General info
	ID   uint64
	Type irma.Action
	Time LogTime // Time at which the session was completed

	// Credential removal
	Removed        map[irma.CredentialTypeIdentifier][]irma.TranslatedString
	RemovedFormats []clientmodels.CredentialFormat

	// Signature sessions
	SignedMessage          []byte
	Timestamp              *atum.Timestamp
	SignedMessageLDContext string

	// Issuance sessions
	IssueCommitment *irma.IssueCommitmentMessage

	// All session types
	ServerName *irma.RequestorInfo
	Version    *irma.ProtocolVersion
	Disclosure *irma.Disclosure
	Request    json.RawMessage     // Message that started the session
	request    irma.SessionRequest // cached parsed version of Request; get with LogEntry.SessionRequest()

	// Eudi logs
	OpenID4VP *OpenID4VPDisclosureLog
}

const ActionRemoval = irma.Action("removal")

func (entry *LogEntry) SessionRequest() (irma.SessionRequest, error) {
	if entry.request != nil {
		return entry.request, nil
	}

	switch entry.Type {
	case irma.ActionDisclosing:
		entry.request = &irma.DisclosureRequest{}
	case irma.ActionSigning:
		entry.request = &irma.SignatureRequest{}
	case irma.ActionIssuing:
		entry.request = &irma.IssuanceRequest{}
	default:
		return nil, nil
	}

	err := json.Unmarshal([]byte(entry.Request), entry.request)
	if err != nil {
		return nil, err
	}

	return entry.request, nil
}

func (entry *LogEntry) setSessionRequest() error {
	bts, err := json.Marshal(entry.request)
	if err != nil {
		return err
	}
	entry.Request = json.RawMessage(bts)
	return nil
}

// GetDisclosedCredentials gets the list of disclosed credentials for a log entry
func (entry *LogEntry) GetDisclosedCredentials(conf *irma.Configuration) ([][]*irma.DisclosedAttribute, error) {
	if entry.Type == ActionRemoval {
		return [][]*irma.DisclosedAttribute{}, nil
	}

	request, err := entry.SessionRequest()
	if err != nil {
		return nil, err
	}
	var disclosure *irma.Disclosure
	disjunctions := request.Disclosure()
	if entry.Type == irma.ActionIssuing {
		disclosure = entry.IssueCommitment.Disclosure()
	} else {
		disclosure = entry.Disclosure
	}
	_, attrs, err := disclosure.DisclosedAttributes(conf, disjunctions.Disclose, nil)
	return attrs, err
}

// GetIssuedCredentials gets the list of issued credentials for a log entry
func (entry *LogEntry) GetIssuedCredentials(conf *irma.Configuration) (list irma.CredentialInfoList, err error) {
	if entry.Type != irma.ActionIssuing {
		return irma.CredentialInfoList{}, nil
	}
	request, err := entry.SessionRequest()
	if err != nil {
		return nil, err
	}
	return request.(*irma.IssuanceRequest).GetCredentialInfoList(conf, entry.Version, time.Time(entry.Time))
}

// GetSignedMessage gets the signed for a log entry
func (entry *LogEntry) GetSignedMessage() (abs *irma.SignedMessage, err error) {
	if entry.Type != irma.ActionSigning {
		return nil, nil
	}
	request, err := entry.SessionRequest()
	if err != nil {
		return nil, err
	}
	sigrequest := request.(*irma.SignatureRequest)
	return &irma.SignedMessage{
		LDContext: entry.SignedMessageLDContext,
		Signature: entry.Disclosure.Proofs,
		Nonce:     sigrequest.Nonce,
		Context:   sigrequest.GetContext(),
		Message:   string(entry.SignedMessage),
		Timestamp: entry.Timestamp,
	}, nil
}

func (session *session) createLogEntry(response any) (*LogEntry, error) {
	entry := &LogEntry{
		Type:       session.Action,
		Time:       LogTime(time.Now()),
		ServerName: session.RequestorInfo,
		Version:    session.Version,
		request:    session.request,
	}

	if err := entry.setSessionRequest(); err != nil {
		return nil, err
	}

	switch entry.Type {
	case ActionRemoval:

	case irma.ActionSigning:
		// Get the signed message and timestamp
		entry.SignedMessage = []byte(session.request.(*irma.SignatureRequest).Message)
		entry.Timestamp = session.timestamp
		entry.SignedMessageLDContext = irma.LDContextSignedMessage

		fallthrough
	case irma.ActionDisclosing:
		entry.Disclosure = response.(*irma.Disclosure)
	case irma.ActionIssuing:
		entry.IssueCommitment = response.(*irma.IssueCommitmentMessage)
	default:
		return nil, errors.New("Invalid log type")
	}

	return entry, nil
}

// =====================================================================================

type InMemoryLogsStorage struct {
	logs []*LogEntry
}

func (s *InMemoryLogsStorage) AddLogEntry(entry *LogEntry) error {
	s.logs = append(s.logs, entry)
	return nil
}

func (s *InMemoryLogsStorage) DeleteLogEntry(entryId uint64) error {
	for index, entry := range s.logs {
		if entry.ID == entryId {
			s.logs = append(s.logs[:index], s.logs[index+1:]...)
			return nil
		}
	}
	return fmt.Errorf("log entry with %v not found", entryId)
}

func (s *InMemoryLogsStorage) LoadNewestLogs(max int) ([]*LogEntry, error) {
	return s.logs, nil
}

func (s *InMemoryLogsStorage) LoadLogsBeforeTime(before time.Time, max int) ([]*LogEntry, error) {
	var result []*LogEntry
	for _, e := range s.logs {
		if time.Time(e.Time).Before(before) {
			result = append(result, e)
			if len(result) >= max {
				break
			}
		}
	}
	return result, nil
}

func (s *InMemoryLogsStorage) DeleteLogs() error {
	s.logs = []*LogEntry{}
	return nil
}
