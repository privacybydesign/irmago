package client

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
)

// LogCredential is a credential entry in a log, containing full credential metadata.
// It mirrors client.Credential but omits wallet-specific fields (hash, instance IDs, batch counts)
// and adds Formats to indicate which credential formats this log entry covers.
type LogCredential struct {
	CredentialId        string                          `json:"credential_id"`
	Formats             []clientmodels.CredentialFormat `json:"formats"`
	ImagePath           string                          `json:"image_path"`
	Name                clientmodels.TranslatedString   `json:"name"`
	Issuer              clientmodels.TrustedParty       `json:"issuer"`
	Attributes          []clientmodels.Attribute        `json:"attributes"`
	IssuanceDate        int64                           `json:"issuance_date"`
	ExpiryDate          int64                           `json:"expiry_date"`
	Revoked             bool                            `json:"revoked"`
	RevocationSupported bool                            `json:"revocation_supported"`
	IssueURL            *clientmodels.TranslatedString  `json:"issue_url,omitempty"`
}

type DisclosureLog struct {
	Protocol    clientmodels.Protocol      `json:"protocol"`
	Credentials []LogCredential            `json:"credentials"`
	Verifier    *clientmodels.TrustedParty `json:"verifier"`
}

type IssuanceLog struct {
	Protocol             clientmodels.Protocol      `json:"protocol"`
	Credentials          []LogCredential            `json:"credentials"`
	DisclosedCredentials []LogCredential            `json:"disclosed_credentials"`
	Issuer               *clientmodels.TrustedParty `json:"issuer"`
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
	ID               uint64               `json:"id"`
	Type             clientmodels.LogType `json:"type"`
	Time             irma.Timestamp       `json:"time"`
	RemovalLog       *RemovalLog          `json:"removal_log,omitempty"`
	IssuanceLog      *IssuanceLog         `json:"issuance_log,omitempty"`
	DisclosureLog    *DisclosureLog       `json:"disclosure_log,omitempty"`
	SignedMessageLog *SignedMessageLog    `json:"signed_message_log,omitempty"`
}
