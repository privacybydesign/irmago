package models

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// TODO: we need to add polymorphic associations to support multiple credential formats in the future, but for now we only support SD-JWT VCs, so we can keep all fields in one table and use the Format field to distinguish them. See https://gorm.io/docs/polymorphism.html for reference on how to implement this when we need it.

// CredentialFormat represents the credential format identifier as defined in the OID4VCI spec.
type CredentialFormat string

const (
	CredentialFormatSdJwtVc CredentialFormat = "dc+sd-jwt"
)

// CredentialBatch groups all credential instances issued from a single credential_configuration_id
// request within one OID4VCI issuance session. When the issuer supports batch issuance,
// BatchSize > 1 and multiple IssuedCredentialInstance rows belong to this batch. Single-use
// wallets decrement RemainingCount on each presentation; the batch is exhausted when it reaches 0.
type CredentialBatch struct {
	ID datatypes.UUID

	// IssuerURL is the iss claim from the issuer-signed JWT, equal to the credential_issuer
	// in the credential offer (OID4VCI §7.1.1 requires iss == credential_issuer).
	// This is the value used for DCQL TrustedAuthority resolution in OID4VP.
	IssuerURL string

	// VerifiableCredentialType is the vct claim from the issued SD-JWT VC.
	VerifiableCredentialType string

	// Format is the credential format identifier (e.g. "dc+sd-jwt").
	Format CredentialFormat

	// Hash is a deterministic hash over the credential type and its sorted disclosed attributes.
	// Computed with the same algorithm as irmaclient.CreateHashForSdJwtVc so that the EUDI
	// storage remains compatible with the IRMA client's deduplication logic.
	Hash string `gorm:"uniqueIndex"`

	// ProcessedSdJwtPayload is the JSON-encoded payload of the SD-JWT after processing/verifying the issuer-signed JWT.
	ProcessedSdJwtPayload datatypes.JSON `gorm:"type:JSON;not null"`

	// IssuedAt is taken from the iat claim of the issuer-signed JWT.
	IssuedAt time.Time

	// ExpiresAt is taken from the exp claim of the issuer-signed JWT. Nil if the credential does not expire.
	ExpiresAt datatypes.NullTime

	// NotBefore is taken from the nbf claim of the issuer-signed JWT. Nil if the credential has no nbf restriction.
	// OID4VP wallets must not present a credential before this time.
	NotBefore datatypes.NullTime

	// BatchSize is the number of instances that were issued in this batch.
	BatchSize uint

	// RemainingCount tracks how many instances have not yet been used for a presentation.
	// Decremented on each use; the batch is exhausted when it reaches 0.
	RemainingCount uint

	// CredentialIssuer is the canonical URL of the credential issuer (credential_issuer claim).
	CredentialIssuer string
	IssuerDisplay    []IssuerMetadataDisplay `gorm:"constraint:OnDelete:CASCADE"`

	CredentialMetadata *CredentialMetadata `gorm:"constraint:OnDelete:CASCADE"`

	Instances []IssuedCredentialInstance `gorm:"constraint:OnDelete:CASCADE"`
}

func (b *CredentialBatch) BeforeCreate(tx *gorm.DB) error {
	if b.ID.IsNil() {
		b.ID = datatypes.NewUUIDv4()
	}
	b.normalizeChildren()
	return b.validate()
}

func (b *CredentialBatch) normalizeChildren() {
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

func (b *CredentialBatch) validate() error {
	if b.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	if b.VerifiableCredentialType == "" {
		return fmt.Errorf("verifiable_credential_type is required")
	}
	if b.Format == "" {
		return fmt.Errorf("format is required")
	}
	if b.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	if b.IssuedAt.IsZero() {
		return fmt.Errorf("issued_at is required")
	}
	if b.BatchSize == 0 {
		return fmt.Errorf("batch_size must be at least 1")
	}
	if b.RemainingCount > b.BatchSize {
		return fmt.Errorf("remaining_count cannot exceed batch_size")
	}
	if b.CredentialIssuer == "" {
		return fmt.Errorf("credential_issuer is required")
	}
	return nil
}

// IssuedCredentialInstance is a single raw SD-JWT VC token within a CredentialBatch.
// Each instance carries its own holder binding key, because the OID4VCI session creates
// one key pair per proof JWT in the batch credential request.
type IssuedCredentialInstance struct {
	ID datatypes.UUID

	CredentialBatchID datatypes.UUID

	// HolderBindingKey is the key pair bound to this credential instance during issuance.
	// Nil if the credential configuration did not require cryptographic key binding.
	HolderBindingKey *HolderBindingKey `gorm:"constraint:OnDelete:CASCADE"`

	// RawCredential is the raw SD-JWT VC token (without key binding JWT).
	// The surrounding SQLCipher layer encrypts this at rest.
	RawCredential []byte `gorm:"type:bytea;not null"`

	// Used marks this instance as consumed after it has been presented.
	// Single-use batch wallets must not reuse an instance once Used is true.
	Used bool `gorm:"default:false"`
}

func (i *IssuedCredentialInstance) BeforeCreate(tx *gorm.DB) error {
	if i.ID.IsNil() {
		i.ID = datatypes.NewUUIDv4()
	}
	if i.HolderBindingKey != nil {
		i.HolderBindingKey.IssuedCredentialInstanceID = &i.ID
	}
	return i.validate()
}

func (i *IssuedCredentialInstance) validate() error {
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
	// TODO: should be nullable fields
	LogoURI     string
	LogoAltText string
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
