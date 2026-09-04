package models

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// CredentialFormat represents the credential format identifier as defined in the OID4VCI spec.
type CredentialFormat string

const (
	CredentialFormatSdJwtVc CredentialFormat = "dc+sd-jwt"
	CredentialFormatMsoMdoc CredentialFormat = "mso_mdoc"
)

// SdJwtVcBatch is one logical SD-JWT VC credential: every credential issued from
// a single credential_configuration_id within one OID4VCI issuance session. When
// the issuer supports batch issuance, BatchSize > 1 and multiple
// SdJwtVcBatchInstance rows belong to this batch. Single-use wallets decrement
// RemainingCount on each presentation; the batch is exhausted when it reaches 0.
//
// SD-JWT VC only. mso_mdoc has its own tables (MdocBatch); the
// Format column stays because it is deployed, and always reads dc+sd-jwt. The
// table is named credential_batches, from before the split — see TableName.
type SdJwtVcBatch struct {
	ID datatypes.UUID

	// IssuerIdentifier is the credential's issuer identity as resolved during
	// verification: the `iss` claim, or the subject of the x5c end-entity
	// certificate when `iss` is absent (SD-JWT VC §2.2.2.3).
	// This is the value used for DCQL TrustedAuthority resolution in OID4VP.
	// The column has been renamed from a previously called `IssuerURL` column and is now more in line with the specification naming conventions.
	IssuerIdentifier string `gorm:"column:issuer_url;not null"`

	// CredentialIssuerIdentifier is the credential's issuer identity as resolved
	// from the Credential Offer (OID4VCI §12.2.1).
	// The column has been renamed from a previously called `CredentialIssuer` column and is now more in line with the specification naming conventions.
	CredentialIssuerIdentifier string `gorm:"column:credential_issuer;not null"`

	// VerifiableCredentialType is the vct claim from the issued SD-JWT VC.
	VerifiableCredentialType string

	// Format is the credential format identifier. Always CredentialFormatSdJwtVc
	// for a row in this table; validate enforces it.
	Format CredentialFormat

	// Hash is a deterministic hash over the credential type, the issuer that
	// asserted it, and its sorted disclosed attributes — the three things that make
	// two credentials the same credential. Computed by services.credentialHash.
	//
	// Not the same algorithm as irmaclient.CreateHashForSdJwtVc, which serves
	// IRMA-issued SD-JWTs: that one is a URL-encoded hash over concatenated sorted
	// key/value pairs, this one a hex SHA-256 over length-prefixed fields. An
	// earlier version of this comment claimed the two were the same for
	// compatibility, which was never true and had been contradicted by
	// hashForSdJwtVc's own doc comment for as long as both existed. The two are
	// independent, and no table holds both.
	Hash string `gorm:"uniqueIndex"`

	// ProcessedSdJwtPayload is the JSON-encoded payload of the SD-JWT after
	// processing/verifying the issuer-signed JWT, cached at issuance time so
	// matching a DCQL query doesn't require re-parsing the raw credential. The
	// field name is also the column name and must stay: AutoMigrate (the only
	// schema mechanism here, see storage.autoMigrateHolderModels) cannot rename a
	// column, and would ADD a NOT NULL one instead, which SQLite rejects once the
	// table has rows. See credentials_schema_test.go, which pins this.
	ProcessedSdJwtPayload datatypes.JSON `gorm:"type:JSON;not null"`

	// IssuedAt is the iat claim of the issuer-signed JWT.
	IssuedAt datatypes.NullTime

	// ExpiresAt is the exp claim of the issuer-signed JWT. Nil if the credential does not expire.
	ExpiresAt datatypes.NullTime

	// NotBefore is the nbf claim of the issuer-signed JWT. Nil if the credential has no such
	// restriction. OID4VP wallets must not present a credential before this time.
	NotBefore datatypes.NullTime

	// BatchSize is the number of instances that were issued in this batch.
	BatchSize uint

	// RemainingCount tracks how many instances have not yet been used for a presentation.
	// Decremented on each use; the batch is exhausted when it reaches 0.
	RemainingCount uint

	// IssuerVerified records that the issuer's signature and certificate chain
	// were verified against a trust anchor before this batch was stored.
	//
	// It is stored rather than re-derived. The check happens once, inside
	// CredentialFormatParser.ParseAndVerify, and its result is not something the
	// wallet otherwise keeps: re-deriving it at read time would mean walking the
	// chain and fetching CRLs on every credential list, and would answer "is this
	// issuer trusted now" rather than "was it trusted at issuance" — two claims
	// that part company as soon as a document signer expires or is revoked. The
	// same reasoning, and the same wording, as EudiLogEntry.RequestorVerified.
	//
	// Batches written before this column existed read back false. That understates
	// them, since they went through the same verifying parser, but a stored false
	// is the conservative direction and matches the log table's precedent.
	IssuerVerified bool

	CredentialMetadata *CredentialMetadata     `gorm:"foreignKey:CredentialBatchID;constraint:OnDelete:CASCADE"`
	Instances          []SdJwtVcBatchInstance  `gorm:"foreignKey:CredentialBatchID;constraint:OnDelete:CASCADE"`
	IssuerDisplay      []IssuerMetadataDisplay `gorm:"foreignKey:CredentialBatchID;constraint:OnDelete:CASCADE"`
}

// TableName pins the deployed table name. GORM would otherwise derive
// sd_jwt_vc_batches from the type name, and AutoMigrate would create an empty
// second table next to the one every installed wallet already holds its
// credentials in.
func (SdJwtVcBatch) TableName() string { return "credential_batches" }

func (b *SdJwtVcBatch) BeforeCreate(tx *gorm.DB) error {
	if b.ID.IsNil() {
		b.ID = datatypes.NewUUIDv4()
	}
	b.normalizeChildren()
	return b.validate()
}

func (b *SdJwtVcBatch) normalizeChildren() {
	if b.CredentialMetadata != nil {
		b.CredentialMetadata.CredentialBatchID = b.ID
	}
	for i := range b.Instances {
		b.Instances[i].CredentialBatchID = b.ID
	}
	for i := range b.IssuerDisplay {
		b.IssuerDisplay[i].CredentialBatchID = b.ID
	}
}

func (b *SdJwtVcBatch) validate() error {
	if b.VerifiableCredentialType == "" {
		return fmt.Errorf("verifiable_credential_type is required")
	}
	if b.IssuerIdentifier == "" {
		return fmt.Errorf("issuer_identifier is required")
	}
	if b.CredentialIssuerIdentifier == "" {
		return fmt.Errorf("credential_issuer_identifier is required")
	}
	if b.Format != CredentialFormatSdJwtVc {
		return fmt.Errorf("format must be %q for an SD-JWT VC batch, got %q", CredentialFormatSdJwtVc, b.Format)
	}
	if b.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	if !b.IssuedAt.Valid {
		return fmt.Errorf("issued_at is required")
	}
	if b.BatchSize == 0 {
		return fmt.Errorf("batch_size must be at least 1")
	}
	if b.RemainingCount > b.BatchSize {
		return fmt.Errorf("remaining_count cannot exceed batch_size")
	}
	return nil
}

// SdJwtVcBatchInstance is a single raw SD-JWT VC within an SdJwtVcBatch. Each
// instance carries its own holder binding key, because the OID4VCI session
// creates one key pair per proof JWT in the batch credential request. The table
// is named issued_credential_instances, from before the split — see TableName.
type SdJwtVcBatchInstance struct {
	ID datatypes.UUID

	CredentialBatchID datatypes.UUID

	// HolderBindingKey is the key pair bound to this credential instance during issuance.
	// Nil if the credential configuration did not require cryptographic key binding.
	HolderBindingKey *HolderBindingKey `gorm:"foreignKey:IssuedCredentialInstanceID;constraint:OnDelete:CASCADE"`

	// RawCredential is the SD-JWT VC token as issued, without its key binding JWT
	// (the holder creates that per presentation). The surrounding SQLCipher layer
	// encrypts this at rest.
	RawCredential []byte `gorm:"type:bytea;not null"`

	// Used marks this instance as consumed after it has been presented.
	// Single-use batch wallets must not reuse an instance once Used is true.
	Used bool `gorm:"default:false"`

	// StatusListURI is the canonical URI from the credential's
	// `status.status_list.uri` claim, when present. Nil for credentials
	// that don't carry a Token Status List reference.
	StatusListURI *string

	// StatusListIdx is the bit-position into the referenced status
	// list. Nil iff StatusListURI is nil.
	StatusListIdx *uint64

	// LastKnownStatus is the most recently observed
	// statuslist.Status for this instance. 0 (StatusUnknown) is the
	// default for credentials that have not yet been checked, and
	// for credentials without a status_list reference.
	LastKnownStatus uint8 `gorm:"default:0"`

	// LastStatusCheckAt records the wall-clock time of the most
	// recent successful status check. Nil iff the instance has
	// never been checked.
	LastStatusCheckAt *time.Time
}

// TableName pins the deployed table name; see SdJwtVcBatch.TableName.
func (SdJwtVcBatchInstance) TableName() string { return "issued_credential_instances" }

func (i *SdJwtVcBatchInstance) BeforeCreate(tx *gorm.DB) error {
	if i.ID.IsNil() {
		i.ID = datatypes.NewUUIDv4()
	}
	if i.HolderBindingKey != nil {
		if i.HolderBindingKey.IssuedCredentialInstanceID != nil && !i.HolderBindingKey.IssuedCredentialInstanceID.IsNil() {
			return fmt.Errorf("holder binding key %s is already bound to credential instance %s",
				i.HolderBindingKey.ID, *i.HolderBindingKey.IssuedCredentialInstanceID)
		}
		i.HolderBindingKey.IssuedCredentialInstanceID = &i.ID
	}
	return i.validate()
}

func (i *SdJwtVcBatchInstance) validate() error {
	if i.CredentialBatchID.IsNil() {
		return fmt.Errorf("batch_id is required")
	}
	if len(i.RawCredential) == 0 {
		return fmt.Errorf("raw_credential is required")
	}
	return nil
}

// IssuerMetadataDisplay holds a single locale's display entry for an issuer,
// corresponding to one element of the top-level display[] array in issuer metadata.
type IssuerMetadataDisplay struct {
	ID datatypes.UUID

	// Foreign key
	CredentialBatchID datatypes.UUID

	Name   string
	Locale datatypes.NullString

	// Logo fields are flattened from the logo sub-object.
	LogoURI     datatypes.NullString
	LogoAltText datatypes.NullString
}

func (d *IssuerMetadataDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID.IsNil() {
		d.ID = datatypes.NewUUIDv4()
	}
	return nil
}

// CredentialMetadata represents one entry in the credential_configurations_supported map
// of the issuer metadata, keyed by credential_configuration_id.
type CredentialMetadata struct {
	ID datatypes.UUID

	CredentialBatchID datatypes.UUID

	Display []CredentialDisplay `gorm:"constraint:OnDelete:CASCADE"`
	Claims  []CredentialClaim   `gorm:"constraint:OnDelete:CASCADE"`
}

func (m *CredentialMetadata) BeforeCreate(tx *gorm.DB) error {
	if m.ID.IsNil() {
		m.ID = datatypes.NewUUIDv4()
	}
	return m.normalizeChildren()
}

func (m *CredentialMetadata) normalizeChildren() error {
	for i := range m.Display {
		m.Display[i].CredentialMetadataID = m.ID
	}
	for i := range m.Claims {
		m.Claims[i].CredentialMetadataID = m.ID
		if err := m.Claims[i].normalizeChildren(); err != nil {
			return fmt.Errorf("failed to normalize claim display children: %w", err)
		}
	}
	return nil
}

// CredentialDisplay holds a single locale's display entry for a credential type,
// corresponding to one element of the credential_metadata.display[] array.
type CredentialDisplay struct {
	ID datatypes.UUID

	// Foreign key
	CredentialMetadataID datatypes.UUID

	Name   string
	Locale datatypes.NullString

	// Logo fields are flattened from the logo sub-object.
	// TODO: should be nullable fields
	LogoURI     string
	LogoAltText string

	Description     string
	BackgroundColor string

	// BackgroundImageURI is flattened from the background_image sub-object.
	BackgroundImageURI     string
	BackgroundImageAltText string

	TextColor string
}

func (d *CredentialDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID.IsNil() {
		d.ID = datatypes.NewUUIDv4()
	}
	return nil
}

// CredentialClaim represents one entry in the credential_metadata.claims[] array,
// describing a single claim path within the credential.
type CredentialClaim struct {
	ID datatypes.UUID

	// Foreign key
	CredentialMetadataID datatypes.UUID

	// Path is the dot-separated or JSON Pointer path to the claim within the credential.
	Path      datatypes.JSON `gorm:"type:JSON;not null"`
	Mandatory bool           `gorm:"default:false"`

	Display []ClaimDisplay `gorm:"constraint:OnDelete:CASCADE"`
}

func (c *CredentialClaim) BeforeCreate(tx *gorm.DB) error {
	if c.ID.IsNil() {
		c.ID = datatypes.NewUUIDv4()
	}
	if len(c.Path) == 0 {
		return fmt.Errorf("path is required")
	}
	return c.normalizeChildren()
}

func (c *CredentialClaim) normalizeChildren() error {
	for i := range c.Display {
		c.Display[i].CredentialClaimID = c.ID
	}
	return nil
}

// ClaimDisplay holds a single locale's display label for a credential claim.
type ClaimDisplay struct {
	ID datatypes.UUID

	// Foreign key
	CredentialClaimID datatypes.UUID

	Name   string
	Locale datatypes.NullString
}

func (d *ClaimDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID.IsNil() {
		d.ID = datatypes.NewUUIDv4()
	}
	return nil
}
