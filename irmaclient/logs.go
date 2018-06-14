package irmaclient

import (
	"encoding/json"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

// LogEntry is a log entry of a past event.
type LogEntry struct {
	// General info
	Type        irma.Action
	Time        irma.Timestamp    // Time at which the session was completed
	SessionInfo *irma.SessionInfo // Message that started the session

	// Session type-specific info
	Removed       map[irma.CredentialTypeIdentifier][]irma.TranslatedString // In case of credential removal
	SignedMessage []byte                                                    // In case of signature sessions

	response    interface{}     // Our response (ProofList or IssueCommitmentMessage)
	rawResponse json.RawMessage // Unparsed []byte version of response
}

const actionRemoval = irma.Action("removal")

func (entry *LogEntry) GetDisclosedCredentials(conf *irma.Configuration) (irma.DisclosedCredentialList, error) {
	var proofs gabi.ProofList
	if entry.Type == irma.ActionIssuing {
		proofs = entry.response.(*gabi.IssueCommitmentMessage).Proofs
	} else {
		proofs = entry.response.(gabi.ProofList)
	}
	return irma.ExtractDisclosedCredentials(conf, proofs)
}

func (entry *LogEntry) GetIssuedCredentials(conf *irma.Configuration) (list irma.CredentialInfoList, err error) {
	if entry.Type != irma.ActionIssuing {
		return nil, nil
	}
	jwt, err := irma.ParseRequestorJwt(irma.ActionIssuing, entry.SessionInfo.Jwt)
	if err != nil {
		return
	}
	ir := jwt.IrmaSession().(*irma.IssuanceRequest)
	return ir.GetCredentialInfoList(conf, ir.GetVersion())
}

func (session *session) createLogEntry(response interface{}) (*LogEntry, error) {
	entry := &LogEntry{
		Type:        session.Action,
		Time:        irma.Timestamp(time.Now()),
		SessionInfo: session.info,
		response:    response,
	}

	if entry.Type == irma.ActionSigning {
		if session.IsInteractive() {
			entry.SignedMessage = []byte(session.jwt.(*irma.SignatureRequestorJwt).Request.Request.Message)
		} else {
			request, ok := session.irmaSession.(*irma.SignatureRequest)
			if !ok {
				return nil, errors.New("Session does not contain a valid Signature Request")
			}
			entry.SignedMessage = []byte(request.Message)
		}
	}

	return entry, nil
}

// Jwt returns the JWT from the requestor that started the IRMA session which the
// current log entry tracks.
func (entry *LogEntry) Jwt() (irma.RequestorJwt, error) {
	return irma.ParseRequestorJwt(entry.Type, entry.SessionInfo.Jwt)
}

// GetResponse returns our response to the requestor from the log entry.
func (entry *LogEntry) GetResponse() (interface{}, error) {
	if entry.response == nil {
		switch entry.Type {
		case actionRemoval:
			return nil, nil
		case irma.ActionSigning:
			fallthrough
		case irma.ActionDisclosing:
			entry.response = []*gabi.ProofD{}
		case irma.ActionIssuing:
			entry.response = &gabi.IssueCommitmentMessage{}
		default:
			return nil, errors.New("Invalid log type")
		}
		err := json.Unmarshal(entry.rawResponse, entry.response)
		if err != nil {
			return nil, err
		}
	}

	return entry.response, nil
}

type jsonLogEntry struct {
	Type        irma.Action
	Time        irma.Timestamp
	SessionInfo *logSessionInfo

	Removed       map[irma.CredentialTypeIdentifier][]irma.TranslatedString `json:",omitempty"`
	SignedMessage []byte                                                    `json:",omitempty"`

	Response json.RawMessage
}

// UnmarshalJSON implements json.Unmarshaler.
func (entry *LogEntry) UnmarshalJSON(bytes []byte) error {
	var err error
	temp := &jsonLogEntry{}
	if err = json.Unmarshal(bytes, temp); err != nil {
		return err
	}

	*entry = LogEntry{
		Type: temp.Type,
		Time: temp.Time,
		SessionInfo: &irma.SessionInfo{
			Jwt:     temp.SessionInfo.Jwt,
			Nonce:   temp.SessionInfo.Nonce,
			Context: temp.SessionInfo.Context,
			Keys:    make(map[irma.IssuerIdentifier]int),
		},
		Removed:       temp.Removed,
		SignedMessage: temp.SignedMessage,
		rawResponse:   temp.Response,
	}

	// TODO remove on protocol upgrade
	for iss, count := range temp.SessionInfo.Keys {
		entry.SessionInfo.Keys[irma.NewIssuerIdentifier(iss)] = count
	}

	return nil
}

// MarshalJSON implements json.Marshaler.
func (entry *LogEntry) MarshalJSON() ([]byte, error) {
	// If the entry was created using createLogEntry(), then entry.rawResponse == nil
	if len(entry.rawResponse) == 0 && entry.response != nil {
		if bytes, err := json.Marshal(entry.response); err == nil {
			entry.rawResponse = json.RawMessage(bytes)
		} else {
			return nil, err
		}
	}

	var si *logSessionInfo
	if entry.SessionInfo != nil {
		si = &logSessionInfo{
			Jwt:     entry.SessionInfo.Jwt,
			Nonce:   entry.SessionInfo.Nonce,
			Context: entry.SessionInfo.Context,
			Keys:    make(map[string]int),
		}
		// TODO remove on protocol upgrade
		for iss, count := range entry.SessionInfo.Keys {
			si.Keys[iss.String()] = count
		}
	}
	temp := &jsonLogEntry{
		Type:          entry.Type,
		Time:          entry.Time,
		Response:      entry.rawResponse,
		SessionInfo:   si,
		Removed:       entry.Removed,
		SignedMessage: entry.SignedMessage,
	}

	return json.Marshal(temp)
}
