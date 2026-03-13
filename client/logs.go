package client

import (
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// LogCredential is a credential entry in a log, containing full credential metadata.
// It mirrors client.Credential but omits wallet-specific fields (hash, instance IDs, batch counts)
// and adds Formats to indicate which credential formats this log entry covers.
type LogCredential struct {
	CredentialId        string             `json:"credential_id"`
	Formats             []CredentialFormat `json:"formats"`
	ImagePath           string             `json:"image_path"`
	Name                TranslatedString   `json:"name"`
	Issuer              TrustedParty       `json:"issuer"`
	Attributes          []Attribute        `json:"attributes"`
	IssuanceDate        int64              `json:"issuance_date"`
	ExpiryDate          int64              `json:"expiry_date"`
	Revoked             bool               `json:"revoked"`
	RevocationSupported bool               `json:"revocation_supported"`
	IssueURL            *TranslatedString  `json:"issue_url,omitempty"`
}

type DisclosureLog struct {
	Protocol    irmaclient.Protocol `json:"protocol"`
	Credentials []LogCredential     `json:"credentials"`
	Verifier    *irma.RequestorInfo `json:"verifier"`
}

type IssuanceLog struct {
	Protocol             irmaclient.Protocol `json:"protocol"`
	Credentials          []LogCredential     `json:"credentials"`
	DisclosedCredentials []LogCredential     `json:"disclosed_credentials"`
	Issuer               *irma.RequestorInfo `json:"issuer"`
}

type RemovalLog struct {
	Credentials []LogCredential `json:"credentials"`
}

type SignedMessageLog struct {
	DisclosureLog
	Message string `json:"message"`
}

// LogInfo is a credential format & protocol agnostic log entry with full credential metadata.
type LogInfo struct {
	ID               uint64             `json:"id"`
	Type             irmaclient.LogType `json:"type"`
	Time             irma.Timestamp     `json:"time"`
	RemovalLog       *RemovalLog        `json:"removal_log,omitempty"`
	IssuanceLog      *IssuanceLog       `json:"issuance_log,omitempty"`
	DisclosureLog    *DisclosureLog     `json:"disclosure_log,omitempty"`
	SignedMessageLog *SignedMessageLog  `json:"signed_message_log,omitempty"`
}
