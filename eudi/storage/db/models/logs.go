package models

import (
	"time"

	"gorm.io/datatypes"
)

// EudiLogEntry is a single activity log entry: an IRMA, OpenID4VCI or
// OpenID4VP session, or a credential removal. IRMA entries used to live in the
// IRMA bbolt store; they are moved here once, so the activity log is one table
// that can be queried.
//
// The verifier logo, when available, is stored in the verifier logo manager
// keyed by RequestorId. The read path resolves it via Exists+Get on demand.
type EudiLogEntry struct {
	ID        datatypes.UUID `gorm:"type:uuid;primaryKey"`
	Type      string         // "issuance", "disclosure", "signature", "removal"
	Protocol  string         // "irma", "openid4vci", "openid4vp", or empty for removal
	CreatedAt time.Time      `gorm:"index"`

	// The columns below were added after entries already existed, so all are
	// nullable: AutoMigrate cannot add a NOT NULL column to a table with rows.
	// Rows written before them are filled in by the log index pass
	// (services.IndexLogs), which also sets IndexVersion.

	// CreatedAtNs is CreatedAt as UTC unix nanoseconds. Queries order and page
	// on it rather than on CreatedAt, which the sqlcipher driver stores as text
	// with the local UTC offset, so it does not sort across a DST change.
	CreatedAtNs *int64 `gorm:"index"`

	// Hidden marks entries the activity log leaves out by default: the
	// issuance of the keyshare credential during enrollment.
	Hidden *bool

	// SignedMessage is the message of a signature session.
	SignedMessage *string

	// RequestorDetails is the JSON-encoded clientmodels.TrustedParty of the
	// requestor without its name and image (those are RequestorName and the
	// verifier logo manager), keeping the trust details IRMA sessions have.
	RequestorDetails datatypes.JSON `gorm:"type:json"`

	// PartyKey groups entries by the party on the other side: the requestor
	// id. Empty for removals.
	PartyKey *string `gorm:"index"`

	// SearchText is the normalised text a search matches against: names in
	// every stored language, attribute values and the signed message.
	SearchText *string

	// IndexVersion is the version of the log index pass that last filled the
	// derived columns (PartyKey, SearchText, roles, positions, attribute rows).
	IndexVersion *int

	// Source is "irma-bbolt" for entries moved over from the IRMA store.
	Source *string

	// IrmaRaw is the original IRMA log entry as JSON, for IRMA sessions. It
	// keeps what the columns do not: the proofs, the issue commitments and the
	// signature timestamp.
	IrmaRaw []byte

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

	// IssuerDetails is the JSON-encoded clientmodels.TrustedParty of the
	// issuer without its name and image, keeping the trust details IRMA has.
	IssuerDetails datatypes.JSON `gorm:"type:json"`

	// Role is what happened to this credential in the entry: "issued",
	// "disclosed" (also during an issuance session) or "removed".
	Role *string

	// Position is the credential's place in the entry, so it reads back in
	// the order it was written.
	Position *int

	// CredentialHash is the Credential.Hash of the card this credential was,
	// so a card's activity can be looked up. Captured when the entry is
	// written; for older entries the hash backfill guesses it.
	CredentialHash *string `gorm:"index"`

	// HashConfidence is "exact" when the hash was known when writing, and
	// "inferred" when it was matched afterwards from type and values.
	HashConfidence *string

	// One row per attribute, to find which entries included a given
	// attribute without decoding Attributes.
	AttributeRows []EudiLogAttribute `gorm:"foreignKey:EudiLogCredentialID;constraint:OnDelete:CASCADE"`
}

// EudiLogAttribute records that a log credential included an attribute. It
// keeps the claim path only, never the value, so no personal data is copied.
type EudiLogAttribute struct {
	ID                  datatypes.UUID `gorm:"type:uuid;primaryKey"`
	EudiLogCredentialID datatypes.UUID `gorm:"index"`
	EudiLogEntryID      datatypes.UUID `gorm:"index"`
	ClaimPathKey        string         `gorm:"index"`
}

// AppMigration marks a one-off data migration as done.
type AppMigration struct {
	Name   string `gorm:"primaryKey"`
	DoneAt time.Time
}
