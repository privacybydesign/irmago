package models

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IssuerMetadata is the root record for an OpenID4VCI credential issuer's metadata,
// corresponding to the object returned from the issuer's /.well-known/openid-credential-issuer endpoint.
type IssuerMetadata struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	// CredentialIssuer is the canonical URL of the credential issuer (credential_issuer claim).
	CredentialIssuer string `gorm:"type:text;not null" json:"credential_issuer"`

	Display            []IssuerMetadataDisplay `gorm:"foreignKey:IssuerMetadataID;constraint:OnDelete:CASCADE" json:"display,omitempty"`
	CredentialMetadata *CredentialMetadata     `gorm:"foreignKey:IssuerMetadataID;constraint:OnDelete:CASCADE" json:"credential_configuration,omitempty"`
}

func (m *IssuerMetadata) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return m.validate()
}

func (IssuerMetadata) TableName() string {
	return "issuer_metadata"
}

func (m *IssuerMetadata) validate() error {
	if m.CredentialIssuer == "" {
		return fmt.Errorf("credential_issuer is required")
	}
	return nil
}

// IssuerMetadataDisplay holds a single locale's display entry for an issuer,
// corresponding to one element of the top-level display[] array in issuer metadata.
type IssuerMetadataDisplay struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey"        json:"id"`
	IssuerMetadataID uuid.UUID `gorm:"type:uuid;not null;index"    json:"issuer_metadata_id"`

	Name   string  `gorm:"type:text;not null" json:"name"`
	Locale *string `gorm:"type:text"          json:"locale,omitempty"`

	// Logo fields are flattened from the logo sub-object.
	LogoURI     string `gorm:"type:text" json:"logo_uri,omitempty"`
	LogoAltText string `gorm:"type:text" json:"logo_alt_text,omitempty"`
}

func (d *IssuerMetadataDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return nil
}

func (IssuerMetadataDisplay) TableName() string {
	return "issuer_metadata_displays"
}

// CredentialMetadata represents one entry in the credential_configurations_supported map
// of the issuer metadata, keyed by credential_configuration_id.
type CredentialMetadata struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey"     json:"id"`
	IssuerMetadataID uuid.UUID `gorm:"type:uuid;not null;index" json:"issuer_metadata_id"`

	Display []CredentialDisplay `gorm:"foreignKey:CredentialMetadataID;constraint:OnDelete:CASCADE" json:"display,omitempty"`
	Claims  []CredentialClaim   `gorm:"foreignKey:CredentialMetadataID;constraint:OnDelete:CASCADE" json:"claims,omitempty"`
}

func (c *CredentialMetadata) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return c.validate()
}

func (CredentialMetadata) TableName() string {
	return "credential_configurations"
}

func (c *CredentialMetadata) validate() error {
	if c.IssuerMetadataID == uuid.Nil {
		return fmt.Errorf("issuer_metadata_id is required")
	}
	return nil
}

// CredentialDisplay holds a single locale's display entry for a credential type,
// corresponding to one element of the credential_metadata.display[] array.
type CredentialDisplay struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey"     json:"id"`
	CredentialMetadataID uuid.UUID `gorm:"type:uuid;not null;index" json:"credential_metadata_id"`

	Name   string  `gorm:"type:text;not null" json:"name"`
	Locale *string `gorm:"type:text"          json:"locale,omitempty"`

	// Logo fields are flattened from the logo sub-object.
	LogoURI     string `gorm:"type:text" json:"logo_uri,omitempty"`
	LogoAltText string `gorm:"type:text" json:"logo_alt_text,omitempty"`

	Description     string `gorm:"type:text" json:"description,omitempty"`
	BackgroundColor string `gorm:"type:text" json:"background_color,omitempty"`

	// BackgroundImageURI is flattened from the background_image sub-object.
	BackgroundImageURI     string `gorm:"type:text" json:"background_image_uri,omitempty"`
	BackgroundImageAltText string `gorm:"type:text" json:"background_image_alt_text,omitempty"`

	TextColor string `gorm:"type:text" json:"text_color,omitempty"`
}

func (d *CredentialDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return nil
}

func (CredentialDisplay) TableName() string {
	return "credential_displays"
}

// CredentialClaim represents one entry in the credential_metadata.claims[] array,
// describing a single claim path within the credential.
type CredentialClaim struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey"     json:"id"`
	CredentialMetadataID uuid.UUID `gorm:"type:uuid;not null;index" json:"credential_metadata_id"`

	// Path is the dot-separated or JSON Pointer path to the claim within the credential.
	Path      string `gorm:"type:text;not null" json:"path"`
	Mandatory bool   `gorm:"not null;default:false" json:"mandatory"`

	Display []ClaimDisplay `gorm:"foreignKey:ClaimID;constraint:OnDelete:CASCADE" json:"display,omitempty"`
}

func (c *CredentialClaim) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}

func (CredentialClaim) TableName() string {
	return "credential_claims"
}

// ClaimDisplay holds a single locale's display label for a credential claim.
type ClaimDisplay struct {
	ID      uuid.UUID `gorm:"type:uuid;primaryKey"     json:"id"`
	ClaimID uuid.UUID `gorm:"type:uuid;not null;index" json:"claim_id"`

	Name   string  `gorm:"type:text;not null" json:"name"`
	Locale *string `gorm:"type:text"          json:"locale,omitempty"`
}

func (d *ClaimDisplay) BeforeCreate(tx *gorm.DB) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	return nil
}

func (ClaimDisplay) TableName() string {
	return "claim_displays"
}
