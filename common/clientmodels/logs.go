package clientmodels

import "time"

// LogCredential is a credential entry in a log, containing full credential metadata.
type LogCredential struct {
	CredentialId        string             `json:"credential_id"`
	Formats             []CredentialFormat `json:"formats"`
	Image               *Image             `json:"image,omitempty"`
	Name                TranslatedString   `json:"name"`
	Issuer              TrustedParty       `json:"issuer"`
	Attributes          []Attribute        `json:"attributes"`
	IssuanceDate        int64              `json:"issuance_date"`
	ExpiryDate          int64              `json:"expiry_date"`
	Revoked             bool               `json:"revoked"`
	RevocationSupported bool               `json:"revocation_supported"`
	IssueURL            *TranslatedString  `json:"issue_url,omitempty"`
}

// DisclosureLog is a log of a disclosure session.
type DisclosureLog struct {
	Protocol    Protocol        `json:"protocol"`
	Credentials []LogCredential `json:"credentials"`
	Verifier    *TrustedParty   `json:"verifier"`
}

// IssuanceLog is a log of an issuance session.
type IssuanceLog struct {
	Protocol             Protocol        `json:"protocol"`
	Credentials          []LogCredential `json:"credentials"`
	DisclosedCredentials []LogCredential `json:"disclosed_credentials"`
	Issuer               *TrustedParty   `json:"issuer"`
}

// RemovalLog is a log of a credential removal.
type RemovalLog struct {
	Credentials []LogCredential `json:"credentials"`
}

// SignedMessageLog is a log of a signature session.
type SignedMessageLog struct {
	DisclosureLog
	Message string `json:"message"`
}

// LogInfo is a credential format & protocol agnostic log entry with full credential metadata.
type LogInfo struct {
	ID               uint64            `json:"id"`
	Type             LogType           `json:"type"`
	Time             time.Time         `json:"time"`
	RemovalLog       *RemovalLog       `json:"removal_log,omitempty"`
	IssuanceLog      *IssuanceLog      `json:"issuance_log,omitempty"`
	DisclosureLog    *DisclosureLog    `json:"disclosure_log,omitempty"`
	SignedMessageLog *SignedMessageLog `json:"signed_message_log,omitempty"`
}
