package irmago

import (
	"encoding/json"

	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

type LogEntry struct {
	Type        Action
	Time        Timestamp    // Time at which the session was completed
	SessionInfo *SessionInfo // Message that started the session
	Response    interface{}  // Session-type specific info, parsed on-demand, use .GetResponse()

	raw json.RawMessage
}

type RemovalLog struct {
	Credential CredentialTypeIdentifier
}

type VerificationLog struct {
	Proofs []*gabi.ProofD
}

type IssuanceLog struct {
	Proofs        []*gabi.ProofD
	AttributeList []*AttributeList
}

type SigningLog struct {
	Proofs      []*gabi.ProofD
	Message     []byte
	MessageType string
}

func (session *session) createLogEntry(response gabi.ProofList) (*LogEntry, error) {
	entry := &LogEntry{
		Type:        session.Action,
		Time:        Timestamp(time.Now()),
		SessionInfo: session.info,
	}

	proofs := []*gabi.ProofD{}
	for _, proof := range response {
		if proofd, isproofd := proof.(*gabi.ProofD); isproofd {
			proofs = append(proofs, proofd)
		}
	}

	switch entry.Type {
	case ActionDisclosing:
		item := &VerificationLog{Proofs: proofs}
		entry.Response = item
	case ActionIssuing:
		item := &IssuanceLog{Proofs: proofs}
		for _, req := range session.jwt.(*IdentityProviderJwt).Request.Request.Credentials {
			list, err := req.AttributeList(session.credManager.ConfigurationStore)
			if err != nil {
				continue // TODO?
			}
			item.AttributeList = append(item.AttributeList, list)
		}
		entry.Response = item
	case ActionSigning:
		item := SigningLog{Proofs: proofs}
		item.Message = []byte(session.jwt.(*SignatureRequestorJwt).Request.Request.Message)
		item.MessageType = session.jwt.(*SignatureRequestorJwt).Request.Request.MessageType
		entry.Response = item
	default:
		return nil, errors.New("Invalid log type")
	}

	return entry, nil
}

func (entry *LogEntry) Jwt() (RequestorJwt, string, error) {
	return parseRequestorJwt(entry.Type, entry.SessionInfo.Jwt)
}

func (entry *LogEntry) GetResponse() (interface{}, error) {
	if entry.Response == nil {
		switch entry.Type {
		case ActionDisclosing:
			entry.Response = &VerificationLog{}
		case ActionIssuing:
			entry.Response = &IssuanceLog{}
		case ActionSigning:
			entry.Response = &SigningLog{}
		case Action("removal"):
			entry.Response = &RemovalLog{}
		default:
			return nil, errors.New("Invalid log type")
		}
		err := json.Unmarshal(entry.raw, entry.Response)
		if err != nil {
			return nil, err
		}
	}

	return entry.Response, nil
}

type jsonLogEntry struct {
	Type        Action
	Time        Timestamp
	SessionInfo *logSessionInfo
	Response    json.RawMessage
}

func (entry *LogEntry) UnmarshalJSON(bytes []byte) error {
	var err error
	temp := &jsonLogEntry{}
	if err = json.Unmarshal(bytes, temp); err != nil {
		return err
	}

	*entry = LogEntry{
		Type: temp.Type,
		Time: temp.Time,
		SessionInfo: &SessionInfo{
			Jwt:     temp.SessionInfo.Jwt,
			Nonce:   temp.SessionInfo.Nonce,
			Context: temp.SessionInfo.Context,
			Keys:    make(map[IssuerIdentifier]int),
		},
		raw: temp.Response,
	}

	// TODO remove on protocol upgrade
	for iss, count := range temp.SessionInfo.Keys {
		entry.SessionInfo.Keys[NewIssuerIdentifier(iss)] = count
	}

	return nil
}
