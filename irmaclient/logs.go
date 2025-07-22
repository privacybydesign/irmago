package irmaclient

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
)

// Credential format & protocol agnostic logs
type LogInfo struct {
	Type             irma.Action       // The type of action
	Time             irma.Timestamp    // Time at which the action occured
	RemovalLog       *RemovalLog       // when Type==ActionRemoval
	IssuanceLog      *IssuanceLog      // when Type==ActionIssuing
	DisclosureLog    *DisclosureLog    // when Type==ActionDisclosing
	SignedMessageLog *SignedMessageLog // when Type==ActionSigning
}

type SignedMessageLog struct {
	Protocol string
	Message  string
	Verifier *irma.RequestorInfo
}

type IssuanceLog struct {
	Protocol             string
	Credentials          []CredentialLog
	DisclosedCredentials []CredentialLog
}

type DisclosureLog struct {
	Protocol    string
	Credentials []CredentialLog
	Verifier    *irma.RequestorInfo
}

type RemovalLog struct {
	Credentials []CredentialLog
}

type CredentialLog struct {
	Formats        []string
	CredentialType string
	Attributes     map[string]string
}

// ===========================================================================

type LogsStorage interface {
	AddLogEntry(entry *LogEntry) error
	DeleteLogEntry(entryId uint64) error
	LoadNewestLogs(max int) ([]*LogEntry, error)
	LoadLogsBefore(index uint64, max int) ([]*LogEntry, error)
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
	Time irma.Timestamp // Time at which the session was completed

	// Credential removal
	Removed map[irma.CredentialTypeIdentifier][]irma.TranslatedString `json:",omitempty"`

	// Signature sessions
	SignedMessage          []byte          `json:",omitempty"`
	Timestamp              *atum.Timestamp `json:",omitempty"`
	SignedMessageLDContext string          `json:",omitempty"`

	// Issuance sessions
	IssueCommitment *irma.IssueCommitmentMessage `json:",omitempty"`

	// All session types
	ServerName *irma.RequestorInfo   `json:",omitempty"`
	Version    *irma.ProtocolVersion `json:",omitempty"`
	Disclosure *irma.Disclosure      `json:",omitempty"`
	Request    json.RawMessage       `json:",omitempty"` // Message that started the session
	request    irma.SessionRequest   // cached parsed version of Request; get with LogEntry.SessionRequest()

	// Eudi logs
	OpenID4VP *OpenID4VPDisclosureLog `json:",omitempty"`
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

func (session *session) createLogEntry(response interface{}) (*LogEntry, error) {
	entry := &LogEntry{
		Type:       session.Action,
		Time:       irma.Timestamp(time.Now()),
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

func (s *InMemoryLogsStorage) LoadLogsBefore(index uint64, max int) ([]*LogEntry, error) {
	return s.logs, nil
}

func (s *InMemoryLogsStorage) DeleteLogs() error {
	s.logs = []*LogEntry{}
	return nil
}
