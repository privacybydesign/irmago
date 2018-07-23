package irmaclient

import (
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

// LogSessionInfo is a SessionInfo alias to bypass the custom JSON marshaler
type LogSessionInfo irma.SessionInfo

// LogEntry is a log entry of a past event.
type LogEntry struct {
	// General info
	Type        irma.Action
	Time        irma.Timestamp        // Time at which the session was completed
	SessionInfo *LogSessionInfo       `json:",omitempty"` // Message that started the session
	Version     *irma.ProtocolVersion `json:",omitempty"` // Protocol version that was used in the session

	// Session type-specific info
	Removed       map[irma.CredentialTypeIdentifier][]irma.TranslatedString `json:",omitempty"` // In case of credential removal
	SignedMessage []byte                                                    `json:",omitempty"` // In case of signature sessions
	Timestamp     *atum.Timestamp                                           `json:",omitempty"` // In case of signature sessions

	IssueCommitment *gabi.IssueCommitmentMessage `json:",omitempty"`
	ProofList       gabi.ProofList               `json:",omitempty"`
}

const actionRemoval = irma.Action("removal")

// GetDisclosedCredentials gets the list of disclosed credentials for a log entry
func (entry *LogEntry) GetDisclosedCredentials(conf *irma.Configuration) (irma.DisclosedCredentialList, error) {
	if entry.Type == actionRemoval {
		return irma.DisclosedCredentialList{}, nil
	}
	var proofs gabi.ProofList
	if entry.Type == irma.ActionIssuing {
		proofs = entry.IssueCommitment.Proofs
	} else {
		proofs = entry.ProofList
	}
	return irma.ExtractDisclosedCredentials(conf, proofs)
}

// GetIssuedCredentials gets the list of issued credentials for a log entry
func (entry *LogEntry) GetIssuedCredentials(conf *irma.Configuration) (list irma.CredentialInfoList, err error) {
	if entry.Type != irma.ActionIssuing {
		return irma.CredentialInfoList{}, nil
	}
	jwt, err := irma.ParseRequestorJwt(irma.ActionIssuing, entry.SessionInfo.Jwt)
	if err != nil {
		return
	}
	ir := jwt.IrmaSession().(*irma.IssuanceRequest)
	return ir.GetCredentialInfoList(conf, entry.Version)
}

// GetSignedMessage gets the signed for a log entry
func (entry *LogEntry) GetSignedMessage() (abs *irma.IrmaSignedMessage, err error) {
	if entry.Type != irma.ActionSigning {
		return nil, nil
	}
	return &irma.IrmaSignedMessage{
		Signature: entry.ProofList,
		Nonce:     entry.SessionInfo.Nonce,
		Context:   entry.SessionInfo.Context,
		Message:   string(entry.SignedMessage),
		Timestamp: entry.Timestamp,
	}, nil
}

func (session *session) createLogEntry(response interface{}) (*LogEntry, error) {
	entry := &LogEntry{
		Type:        session.Action,
		Time:        irma.Timestamp(time.Now()),
		Version:     session.Version,
		SessionInfo: (*LogSessionInfo)(session.info),
	}

	switch entry.Type {
	case actionRemoval:

	case irma.ActionSigning:
		// Get the signed message and timestamp
		request := session.irmaSession.(*irma.SignatureRequest)
		entry.SignedMessage = []byte(request.Message)
		entry.Timestamp = request.Timestamp

		fallthrough
	case irma.ActionDisclosing:
		entry.ProofList = response.(gabi.ProofList)
	case irma.ActionIssuing:
		entry.IssueCommitment = response.(*gabi.IssueCommitmentMessage)
	default:
		return nil, errors.New("Invalid log type")
	}

	return entry, nil
}

// Jwt returns the JWT from the requestor that started the IRMA session which the
// current log entry tracks.
func (entry *LogEntry) Jwt() (irma.RequestorJwt, error) {
	return irma.ParseRequestorJwt(entry.Type, entry.SessionInfo.Jwt)
}
