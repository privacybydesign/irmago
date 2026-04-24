package models

import (
	"time"

	"gorm.io/datatypes"
)

// EudiLogEntry is a single activity log entry for EUDI protocol sessions
// (OpenID4VCI issuance, OpenID4VP disclosure, or credential removal).
type EudiLogEntry struct {
	ID        datatypes.UUID `gorm:"type:uuid;primaryKey"`
	Type      string         // "issuance", "disclosure", "removal"
	Protocol  string         // "openid4vci", "openid4vp", or empty for removal
	CreatedAt time.Time `gorm:"index"`

	// Requestor/verifier/issuer info (JSON-encoded TranslatedString for name).
	RequestorId           string
	RequestorName         datatypes.JSON `gorm:"type:json"`
	RequestorLogoFilename string         // Logo filename managed by the verifier logo manager. Empty when no logo is available.

	// Logged credentials.
	Credentials []EudiLogCredential `gorm:"foreignKey:EudiLogEntryID;constraint:OnDelete:CASCADE"`
}

// EudiLogCredential is a credential entry within an activity log.
type EudiLogCredential struct {
	ID             datatypes.UUID `gorm:"type:uuid;primaryKey"`
	EudiLogEntryID datatypes.UUID `gorm:"index"`

	// VCT URL or IRMA credential type identifier.
	CredentialId string

	// JSON-encoded []string of credential formats (e.g. ["dc+sd-jwt"]).
	Formats datatypes.JSON `gorm:"type:json"`

	// JSON-encoded TranslatedString for display name and issuer name.
	Name       datatypes.JSON `gorm:"type:json"`
	IssuerName datatypes.JSON `gorm:"type:json"`
	IssuerId   string

	// JSON-encoded []clientmodels.Attribute — full attribute list with paths,
	// display names, and values. Stored as a blob since logs are write-once.
	Attributes datatypes.JSON `gorm:"type:json"`

	// Credential timing and status metadata.
	IssuanceDate        int64
	ExpiryDate          int64
	Revoked             bool
	RevocationSupported bool
	IssueURL            datatypes.JSON `gorm:"type:json"` // JSON-encoded *TranslatedString, nil when not set.

	// Filename (without extension) of the credential logo stored by the
	// credential logo manager. Empty when no logo is available.
	LogoFilename string

	// Filename (without extension) of the issuer logo stored by the
	// issuer logo manager. Empty when no logo is available.
	IssuerLogoFilename string
}
