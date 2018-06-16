package irmaclient

import (
	"encoding/json"
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

// LogEntry is a log entry of a past event.
type LogEntry struct {
	// General info
	Type        irma.Action
	Time        irma.Timestamp        // Time at which the session was completed
	SessionInfo *irma.SessionInfo     // Message that started the session
	Version     *irma.ProtocolVersion // Protocol version that was used in the session

	// Session type-specific info
	Removed       map[irma.CredentialTypeIdentifier][]irma.TranslatedString // In case of credential removal
	SignedMessage []byte                                                    // In case of signature sessions
	Timestamp     *atum.Timestamp                                           // In case of signature sessions

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
	return ir.GetCredentialInfoList(conf, entry.Version)
}

func (session *session) createLogEntry(response interface{}) (*LogEntry, error) {
	entry := &LogEntry{
		Type:        session.Action,
		Time:        irma.Timestamp(time.Now()),
		Version:     session.Version,
		SessionInfo: session.info,
		response:    response,
	}

	if entry.Type == irma.ActionSigning {
		request := session.irmaSession.(*irma.SignatureRequest)
		entry.SignedMessage = []byte(request.Message)
		entry.Timestamp = request.Timestamp
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

func (entry *LogEntry) GetSignature() (abs *irma.IrmaSignedMessage, err error) {
	if entry.Type != irma.ActionSigning {
		return nil, nil
	}
	response, err := entry.GetResponse()
	if err != nil {
		return
	}
	proofds := response.([]*gabi.ProofD)
	signature := make(gabi.ProofList, len(proofds))
	for i, proof := range proofds {
		signature[i] = proof
	}
	return &irma.IrmaSignedMessage{
		Signature: signature,
		Nonce:     entry.SessionInfo.Nonce,
		Context:   entry.SessionInfo.Context,
		Message:   string(entry.SignedMessage),
		Timestamp: entry.Timestamp,
	}, nil
}

type jsonLogEntry struct {
	Type        irma.Action
	Time        irma.Timestamp
	SessionInfo *logSessionInfo       `json:",omitempty"`
	Version     *irma.ProtocolVersion `json:",omitempty"`

	Removed       map[irma.CredentialTypeIdentifier][]irma.TranslatedString `json:",omitempty"`
	SignedMessage []byte                                                    `json:",omitempty"`
	Timestamp     *atum.Timestamp                                           `json:",omitempty"`

	Response json.RawMessage `json:",omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (entry *LogEntry) UnmarshalJSON(bytes []byte) error {
	var err error
	temp := &jsonLogEntry{}
	if err = json.Unmarshal(bytes, temp); err != nil {
		return err
	}

	*entry = LogEntry{
		Type:    temp.Type,
		Time:    temp.Time,
		Version: temp.Version,
		SessionInfo: &irma.SessionInfo{
			Jwt:     temp.SessionInfo.Jwt,
			Nonce:   temp.SessionInfo.Nonce,
			Context: temp.SessionInfo.Context,
			Keys:    make(map[irma.IssuerIdentifier]int),
		},
		Removed:       temp.Removed,
		SignedMessage: temp.SignedMessage,
		Timestamp:     temp.Timestamp,
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
		Version:       entry.Version,
		Response:      entry.rawResponse,
		SessionInfo:   si,
		Removed:       entry.Removed,
		SignedMessage: entry.SignedMessage,
		Timestamp:     entry.Timestamp,
	}

	return json.Marshal(temp)
}
