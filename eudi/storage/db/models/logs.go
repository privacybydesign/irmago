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

	// RequestorVerified records whether the requestor was authenticated at the
	// time of the session — for a verifier, that its request was signed by a
	// trusted end-entity certificate. It is stored rather than re-derived,
	// because the certificate that authenticated a past session is not
	// something the wallet keeps: the log says what was true then, the same way
	// IssuerVerified does per credential. Entries written before this column
	// existed read back false, which is the pre-existing behaviour.
	RequestorVerified bool

	// RequestorAnonymous records that nothing identified itself: the session had
	// an address the platform vouched for and no name at all. Stored separately
	// from RequestorVerified because the two answer different questions -- one
	// asks whether a name was authenticated, the other whether there was a name
	// -- and collapsing them would make a stranger indistinguishable in the log
	// from an issuer whose real metadata merely was not signed.
	RequestorAnonymous bool

	// RequestorOrigin is the web origin the platform authenticated, when the
	// session arrived through the Digital Credentials API. For an anonymous
	// requestor it is the only identity there is, so an entry without it is an
	// entry the user cannot act on.
	RequestorOrigin string

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
	Name           datatypes.JSON `gorm:"type:json"`
	IssuerName     datatypes.JSON `gorm:"type:json"`
	IssuerId       string
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
