package models

import (
	"time"

	"gorm.io/datatypes"
)

// EudiLogEntry is a single activity log entry for EUDI protocol sessions
// (OpenID4VCI issuance, OpenID4VP disclosure, or credential removal).
//
// The verifier logo, when available, is stored in the verifier logo manager
// keyed by RequestorId. The read path resolves it via Exists+Get on demand.
type EudiLogEntry struct {
	ID        datatypes.UUID `gorm:"type:uuid;primaryKey"`
	Type      string         // "issuance", "disclosure", "removal"
	Protocol  string         // "openid4vci", "openid4vp", or empty for removal
	CreatedAt time.Time      `gorm:"index"`

	// Requestor/verifier/issuer info (JSON-encoded TranslatedString for name).
	RequestorId   string
	RequestorName datatypes.JSON `gorm:"type:json"`

	// RequestorTrustLevel is the requestor's trust level at session time: the
	// verifier's on a disclosure entry, the issuer's on an issuance entry. Written
	// once and never re-resolved. Empty on rows written before the levels existed,
	// which renders levelless — an absence, not the verdict
	// clientmodels.TrustLevel_Low.
	RequestorTrustLevel string

	// Logged credentials.
	Credentials []EudiLogCredential `gorm:"foreignKey:EudiLogEntryID;constraint:OnDelete:CASCADE"`
}

// EudiLogCredential is a credential entry within an activity log.
//
// Credential and issuer logos, when available, are stored in the credential
// and issuer logo managers respectively, keyed by CredentialId / IssuerId.
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

	// IssuerTrustLevel is this credential's issuer's level at session time, on the
	// same terms as EudiLogEntry.RequestorTrustLevel.
	IssuerTrustLevel string

	// IssuerVerified is the boolean IssuerTrustLevel replaced. Read-only: nothing
	// writes it any more, and it is how pre-feature rows still render a vouched-for
	// issuer.
	IssuerVerified bool

	// JSON-encoded []clientmodels.Attribute — full attribute list with paths,
	// display names, and values. Stored as a blob since logs are write-once.
	Attributes datatypes.JSON `gorm:"type:json"`

	// Credential timing and status metadata.
	IssuanceDate        datatypes.NullTime
	ExpiryDate          datatypes.NullTime
	Revoked             bool
	RevocationSupported bool
	IssueURL            datatypes.JSON `gorm:"type:json"` // JSON-encoded *TranslatedString, nil when not set.
}
