package irmaclient

import (
	"encoding/json"
	"time"

	"github.com/credentials/irmago"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// LogEntry is a log entry of a past event.
type LogEntry struct {
	// General info
	Type        irma.Action
	Time        irma.Timestamp    // Time at which the session was completed
	SessionInfo *irma.SessionInfo // Message that started the session

	// Session type-specific info
	Disclosed         map[irma.CredentialTypeIdentifier]map[int]irma.TranslatedString // Any session type
	Received          map[irma.CredentialTypeIdentifier][]irma.TranslatedString       // In case of issuance session
	Removed           map[irma.CredentialTypeIdentifier][]irma.TranslatedString       // In case of credential removal
	SignedMessage     []byte                                                          // In case of signature sessions
	SignedMessageType string                                                          // In case of signature sessions

	response    interface{}     // Our response (ProofList or IssueCommitmentMessage)
	rawResponse json.RawMessage // Unparsed []byte version of response
}

const actionRemoval = irma.Action("removal")

func (session *session) createLogEntry(response interface{}) (*LogEntry, error) {
	entry := &LogEntry{
		Type:        session.Action,
		Time:        irma.Timestamp(time.Now()),
		SessionInfo: session.info,
		response:    response,
	}

	// Populate session type-specific fields of the log entry (except for .Disclosed which is handled below)
	var prooflist gabi.ProofList
	var ok bool
	switch entry.Type {
	case irma.ActionSigning:
		entry.SignedMessage = []byte(session.jwt.(*irma.SignatureRequestorJwt).Request.Request.Message)
		entry.SignedMessageType = session.jwt.(*irma.SignatureRequestorJwt).Request.Request.MessageType
		fallthrough
	case irma.ActionDisclosing:
		if prooflist, ok = response.(gabi.ProofList); !ok {
			return nil, errors.New("Response was not a ProofList")
		}
	case irma.ActionIssuing:
		if entry.Received == nil {
			entry.Received = map[irma.CredentialTypeIdentifier][]irma.TranslatedString{}
		}
		for _, req := range session.jwt.(*irma.IdentityProviderJwt).Request.Request.Credentials {
			list, err := req.AttributeList(session.client.Configuration)
			if err != nil {
				continue // TODO?
			}
			entry.Received[list.CredentialType().Identifier()] = list.Strings()
		}
		var msg *gabi.IssueCommitmentMessage
		if msg, ok = response.(*gabi.IssueCommitmentMessage); ok {
			prooflist = msg.Proofs
		} else {
			return nil, errors.New("Response was not a *IssueCommitmentMessage")
		}
	default:
		return nil, errors.New("Invalid log type")
	}

	// Populate the list of disclosed attributes .Disclosed
	for _, proof := range prooflist {
		if proofd, isproofd := proof.(*gabi.ProofD); isproofd {
			if entry.Disclosed == nil {
				entry.Disclosed = map[irma.CredentialTypeIdentifier]map[int]irma.TranslatedString{}
			}
			meta := irma.MetadataFromInt(proofd.ADisclosed[1], session.client.Configuration)
			id := meta.CredentialType().Identifier()
			entry.Disclosed[id] = map[int]irma.TranslatedString{}
			for i, attr := range proofd.ADisclosed {
				if i == 1 {
					continue
				}
				val := string(attr.Bytes())
				entry.Disclosed[id][i] = irma.TranslatedString{"en": val, "nl": val}
			}
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

	Disclosed         map[irma.CredentialTypeIdentifier]map[int]irma.TranslatedString `json:",omitempty"`
	Received          map[irma.CredentialTypeIdentifier][]irma.TranslatedString       `json:",omitempty"`
	Removed           map[irma.CredentialTypeIdentifier][]irma.TranslatedString       `json:",omitempty"`
	SignedMessage     []byte                                                          `json:",omitempty"`
	SignedMessageType string                                                          `json:",omitempty"`

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
		Removed:           temp.Removed,
		Disclosed:         temp.Disclosed,
		Received:          temp.Received,
		SignedMessage:     temp.SignedMessage,
		SignedMessageType: temp.SignedMessageType,
		rawResponse:       temp.Response,
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
		Type:              entry.Type,
		Time:              entry.Time,
		Response:          entry.rawResponse,
		SessionInfo:       si,
		Removed:           entry.Removed,
		Disclosed:         entry.Disclosed,
		Received:          entry.Received,
		SignedMessage:     entry.SignedMessage,
		SignedMessageType: entry.SignedMessageType,
	}

	return json.Marshal(temp)
}
