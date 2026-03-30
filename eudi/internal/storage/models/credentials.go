package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CredentialFormat represents the credential format identifier as defined in the OID4VCI spec.
type CredentialFormat string

const (
	CredentialFormatSdJwtVc CredentialFormat = "dc+sd-jwt"
)

// IssuerDisplay holds display metadata for a credential issuer for a single locale,
// derived from CredentialIssuerMetadata.Display.
type IssuerDisplay struct {
	Name        string `json:"name"`
	Locale      string `json:"locale,omitempty"`
	LogoURI     string `json:"logo_uri,omitempty"`
	LogoAltText string `json:"logo_alt_text,omitempty"`
}

// CredentialDisplay holds display metadata for a credential type for a single locale,
// derived from CredentialConfiguration.CredentialMetadata.
type CredentialDisplay struct {
	Name        string `json:"name"`
	Locale      string `json:"locale,omitempty"`
	Description string `json:"description,omitempty"`
}

// CredentialBatch groups all credential instances issued from a single credential_configuration_id
// request within one OID4VCI issuance session. When the issuer supports batch issuance,
// BatchSize > 1 and multiple IssuedCredentialInstance rows belong to this batch. Single-use
// wallets decrement RemainingCount on each presentation; the batch is exhausted when it reaches 0.
type CredentialBatch struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	// IssuerURL is the iss claim from the issuer-signed JWT, equal to the credential_issuer
	// in the credential offer (OID4VCI §7.1.1 requires iss == credential_issuer).
	// This is the value used for DCQL TrustedAuthority resolution in OID4VP.
	IssuerURL string `gorm:"type:text;not null;index" json:"issuer_url"`

	// CredentialConfigurationID is the credential_configuration_id from the credential offer.
	CredentialConfigurationID string `gorm:"type:text;not null" json:"credential_configuration_id"`

	// VerifiableCredentialType is the vct claim from the issued SD-JWT VC.
	VerifiableCredentialType string `gorm:"type:text;not null;index" json:"verifiable_credential_type"`

	// Format is the credential format identifier (e.g. "dc+sd-jwt").
	Format CredentialFormat `gorm:"type:text;not null" json:"format"`

	// Hash is a deterministic hash over the credential type and its sorted disclosed attributes.
	// Computed with the same algorithm as irmaclient.CreateHashForSdJwtVc so that the EUDI
	// storage remains compatible with the IRMA client's deduplication logic.
	Hash string `gorm:"type:text;not null;uniqueIndex" json:"hash"`

	// AttributesJSON is a JSON-encoded map[string]any of disclosed claim values, used for display.
	AttributesJSON []byte `gorm:"type:bytea;not null" json:"attributes_json"`

	// IssuerDisplayJSON is a JSON-encoded []IssuerDisplay derived from CredentialIssuerMetadata.Display.
	IssuerDisplayJSON []byte `gorm:"type:bytea" json:"issuer_display_json"`

	// CredentialDisplayJSON is a JSON-encoded []CredentialDisplay derived from CredentialConfiguration.CredentialMetadata.
	CredentialDisplayJSON []byte `gorm:"type:bytea" json:"credential_display_json"`

	// ProcessedSdJwtPayload is the JSON-encoded payload of the SD-JWT after processing/verifying the issuer-signed JWT.
	ProcessedSdJwtPayload string `gorm:"type:JSON;not null" json:"processed_sd_jwt_payload"`

	// IssuedAt is taken from the iat claim of the issuer-signed JWT.
	IssuedAt time.Time `gorm:"not null" json:"issued_at"`

	// ExpiresAt is taken from the exp claim of the issuer-signed JWT. Nil if the credential does not expire.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// NotBefore is taken from the nbf claim of the issuer-signed JWT. Nil if the credential has no nbf restriction.
	// OID4VP wallets must not present a credential before this time.
	NotBefore *time.Time `json:"not_before,omitempty"`

	// Status holds the raw JSON of the status claim from the issuer-signed JWT, used for revocation checks.
	// The value is a JSON object (e.g. {"status_list": {"idx": N, "uri": "…"}}) as defined by the Token
	// Status List spec (RFC 9596). Nil if the issuer did not include a status claim.
	Status []byte `gorm:"type:bytea" json:"status,omitempty"`

	// BatchSize is the number of instances that were issued in this batch.
	BatchSize uint `gorm:"not null" json:"batch_size"`

	// RemainingCount tracks how many instances have not yet been used for a presentation.
	// Decremented on each use; the batch is exhausted when it reaches 0.
	RemainingCount uint `gorm:"not null" json:"remaining_count"`

	Instances []IssuedCredentialInstance `gorm:"foreignKey:BatchID;constraint:OnDelete:CASCADE" json:"instances,omitempty"`
}

func (b *CredentialBatch) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return b.validate()
}

func (CredentialBatch) TableName() string {
	return "credential_batches"
}

func (b *CredentialBatch) validate() error {
	if b.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	if b.CredentialConfigurationID == "" {
		return fmt.Errorf("credential_configuration_id is required")
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
	if len(b.AttributesJSON) == 0 {
		return fmt.Errorf("attributes_json is required")
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
	return nil
}

// IssuedCredentialInstance is a single raw SD-JWT VC token within a CredentialBatch.
// Each instance carries its own holder binding key, because the OID4VCI session creates
// one key pair per proof JWT in the batch credential request.
type IssuedCredentialInstance struct {
	ID      uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	BatchID uuid.UUID `gorm:"type:uuid;not null;index" json:"batch_id"`

	// HolderBindingKeyID is the FK to the key pair bound to this credential instance during issuance.
	// Nil if the credential configuration did not require cryptographic key binding.
	HolderBindingKeyID *uuid.UUID        `gorm:"type:uuid;index"                                                         json:"holder_binding_key_id,omitempty"`
	HolderBindingKey   *HolderBindingKey `gorm:"foreignKey:HolderBindingKeyID;references:ID;constraint:OnDelete:CASCADE" json:"holder_binding_key,omitempty"`

	// RawCredential is the raw SD-JWT VC token (without key binding JWT).
	// The surrounding SQLCipher layer encrypts this at rest.
	RawCredential []byte `gorm:"type:bytea;not null" json:"raw_credential"`

	// Used marks this instance as consumed after it has been presented.
	// Single-use batch wallets must not reuse an instance once Used is true.
	Used bool `gorm:"not null;default:false" json:"used"`
}

func (i *IssuedCredentialInstance) BeforeCreate(tx *gorm.DB) error {
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	return i.validate()
}

func (IssuedCredentialInstance) TableName() string {
	return "issued_credential_instances"
}

func (i *IssuedCredentialInstance) validate() error {
	if i.BatchID == uuid.Nil {
		return fmt.Errorf("batch_id is required")
	}
	if len(i.RawCredential) == 0 {
		return fmt.Errorf("raw_credential is required")
	}
	return nil
}
