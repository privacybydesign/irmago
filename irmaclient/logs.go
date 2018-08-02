package irmaclient

import (
	"github.com/bwesterb/go-atum"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

// LogEntry is a log entry of a past event.
type LogEntry struct {
	// General info
	Type    irma.Action
	Time    irma.Timestamp        // Time at which the session was completed
	Version *irma.ProtocolVersion `json:",omitempty"` // Protocol version that was used in the session
	//Request irma.SessionRequest   `json:",omitempty"` // Message that started the session

	// Session type-specific info
	Removed       map[irma.CredentialTypeIdentifier][]irma.TranslatedString `json:",omitempty"` // In case of credential removal
	SignedMessage []byte                                                    `json:",omitempty"` // In case of signature sessions
	Timestamp     *atum.Timestamp                                           `json:",omitempty"` // In case of signature sessions

	IssueCommitment *gabi.IssueCommitmentMessage `json:",omitempty"`
	ProofList       gabi.ProofList               `json:",omitempty"`
}

const actionRemoval = irma.Action("removal")

// GetDisclosedCredentials gets the list of disclosed credentials for a log entry
func (entry *LogEntry) GetDisclosedCredentials(conf *irma.Configuration) ([]*irma.DisclosedAttribute, error) {
	return nil, nil
}

// GetIssuedCredentials gets the list of issued credentials for a log entry
func (entry *LogEntry) GetIssuedCredentials(conf *irma.Configuration) (list irma.CredentialInfoList, err error) {
	return nil, nil
}

// GetSignedMessage gets the signed for a log entry
func (entry *LogEntry) GetSignedMessage() (abs *irma.SignedMessage, err error) {
	return nil, nil
}

func (session *session) createLogEntry(response interface{}) (*LogEntry, error) {
	return nil, nil
}
