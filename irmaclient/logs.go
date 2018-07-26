package irmaclient

import (
	"time"

	"github.com/bwesterb/go-atum"
	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

// LogEntry is a log entry of a past event.
type LogEntry struct {
	// General info
	Type    irma.Action
	Time    irma.Timestamp        // Time at which the session was completed
	Version *irma.ProtocolVersion `json:",omitempty"` // Protocol version that was used in the session
	Request irma.SessionRequest   `json:",omitempty"` // Message that started the session

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
	return entry.Request.(*irma.IssuanceRequest).GetCredentialInfoList(conf, entry.Version)
}

// GetSignedMessage gets the signed for a log entry
func (entry *LogEntry) GetSignedMessage() (abs *irma.SignedMessage, err error) {
	if entry.Type != irma.ActionSigning {
		return nil, nil
	}
	request := entry.Request.(*irma.SignatureRequest)
	return &irma.SignedMessage{
		Signature: entry.ProofList,
		Nonce:     request.Nonce,
		Context:   request.Context,
		Message:   string(entry.SignedMessage),
		Timestamp: entry.Timestamp,
	}, nil
}

func (session *session) createLogEntry(response interface{}) (*LogEntry, error) {
	entry := &LogEntry{
		Type:    session.Action,
		Time:    irma.Timestamp(time.Now()),
		Version: session.Version,
		Request: session.request,
	}

	switch entry.Type {
	case actionRemoval:

	case irma.ActionSigning:
		// Get the signed message and timestamp
		request := session.request.(*irma.SignatureRequest)
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
