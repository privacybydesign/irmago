package models

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// The SD-JWT-secured W3C VCDM 2.0 storage models. Like mso_mdoc, VCDM has its
// own tables and shares only the database file with the SD-JWT VC models, plus
// one thing: the holder binding key table. Both SD-JWT-secured data models bind
// a credential to its holder the same way, through the `cnf` claim, so the keys
// are minted, matched and used for key binding JWTs by the same code; only the
// link back to the owning instance differs (HolderBindingKey.VcdmBatchInstanceID).
//
// The two SD-JWT data models deliberately do not share a batch table. They
// differ in type identity (`vct` versus `@context`+`type`), in where the
// attributes live (top level versus `credentialSubject`), in their validity
// fields, and in their status mechanism (IETF Token Status List versus W3C
// Bitstring Status List). One table would make each of those a column the
// other model has to remember to ignore.

// VcdmBatch is one logical SD-JWT-secured VCDM credential: every credential
// issued from a single credential_configuration_id within one OpenID4VCI
// issuance session. When the issuer supports batch issuance, BatchSize > 1 and
// one VcdmBatchInstance row exists per copy, each bound to its own holder key.
type VcdmBatch struct {
	ID datatypes.UUID `gorm:"primaryKey"`

	// TypeIdentity is the credential's type identity: its `@context` values and
	// `type` values, space-joined (vcdm.Document.TypeIdentity), e.g.
	// "https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential".
	TypeIdentity string `gorm:"not null;index"`

	// IssuerIdentifier is the VCDM document's `issuer`, which verification
	// cross-checked against the JWT `iss` when that was present.
	IssuerIdentifier string `gorm:"not null"`

	// CredentialIssuer is the OpenID4VCI credential_issuer the credential was
	// obtained from — where the wallet went, not who signed what it got back.
	CredentialIssuer string `gorm:"not null"`

	// Format is the securing format. Always CredentialFormatSdJwtVcdm today; it
	// is part of the uniqueness key so that the same logical credential secured
	// another way (e.g. a future vc+jwt) can be held next to it, sharing a hash.
	Format CredentialFormat `gorm:"not null;uniqueIndex:idx_vcdm_batches_hash_format,priority:2"`

	// Hash is the deterministic content identity over the type identity and the
	// credential's content (see services.hashForVcdmCredential). Securing-agnostic,
	// hence unique only together with Format.
	Hash string `gorm:"not null;uniqueIndex:idx_vcdm_batches_hash_format,priority:1"`

	// ProcessedPayload is the processed SD-JWT payload, i.e. the VCDM document
	// with every disclosure resolved, cached at issuance so DCQL matching and
	// display do not re-parse the raw credential.
	ProcessedPayload datatypes.JSON `gorm:"type:JSON;not null"`

	// IssuedAt is the JWT iat, or the document's validFrom when iat is absent,
	// or the receipt time when neither is present.
	IssuedAt time.Time `gorm:"not null"`

	// ExpiresAt is the document's validUntil, or the JWT exp. Nil when the
	// credential does not expire.
	ExpiresAt datatypes.NullTime

	// NotBefore is the JWT nbf, or the document's validFrom.
	NotBefore datatypes.NullTime

	BatchSize      uint `gorm:"not null"`
	RemainingCount uint `gorm:"not null"`

	// IssuerVerified records that the issuer's signature verified before the
	// batch was stored. Stored rather than re-derived, for the reasons
	// SdJwtVcBatch.IssuerVerified gives.
	IssuerVerified bool

	// IssuerDisplay is the issuer metadata's top-level display[] array as
	// published, JSON. May be empty.
	IssuerDisplay datatypes.JSON `gorm:"type:JSON"`

	// CredentialMetadata is the credential configuration's credential_metadata
	// (display and claims) as published, JSON. Empty when the issuer advertised
	// none.
	CredentialMetadata datatypes.JSON `gorm:"type:JSON"`

	Instances []VcdmBatchInstance `gorm:"foreignKey:VcdmBatchID;constraint:OnDelete:CASCADE"`
}

func (VcdmBatch) TableName() string { return "vcdm_batches" }

func (b *VcdmBatch) BeforeCreate(tx *gorm.DB) error {
	if b.ID.IsNil() {
		b.ID = datatypes.NewUUIDv4()
	}
	for i := range b.Instances {
		b.Instances[i].VcdmBatchID = b.ID
	}
	return b.validate()
}

func (b *VcdmBatch) validate() error {
	if b.TypeIdentity == "" {
		return fmt.Errorf("type_identity is required")
	}
	if b.IssuerIdentifier == "" {
		return fmt.Errorf("issuer_identifier is required")
	}
	if b.CredentialIssuer == "" {
		return fmt.Errorf("credential_issuer is required")
	}
	if b.Format != CredentialFormatSdJwtVcdm {
		return fmt.Errorf("format must be %q for a VCDM batch, got %q", CredentialFormatSdJwtVcdm, b.Format)
	}
	if b.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	if len(b.ProcessedPayload) == 0 {
		return fmt.Errorf("processed_payload is required")
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

// VcdmBatchInstance is one raw SD-JWT-secured VCDM credential within a
// VcdmBatch.
//
// Its status columns mirror SdJwtVcBatchInstance's. A VCDM credential can name
// its status two ways, the W3C `credentialStatus` (Bitstring Status List) and the
// IETF `status.status_list` claim, so both references are kept; LastKnownStatus
// is their combined result, in statuslist.Status values.
type VcdmBatchInstance struct {
	ID datatypes.UUID `gorm:"primaryKey"`

	VcdmBatchID datatypes.UUID `gorm:"not null;index"`

	// HolderBindingKey is the key pair bound to this instance during issuance.
	// Nil if the credential configuration did not require cryptographic key
	// binding.
	HolderBindingKey *HolderBindingKey `gorm:"foreignKey:VcdmBatchInstanceID;constraint:OnDelete:CASCADE"`

	// RawCredential is the SD-JWT as issued, without a key binding JWT (the
	// holder creates that per presentation). The SQLCipher layer encrypts it at
	// rest.
	RawCredential []byte `gorm:"type:bytea;not null"`

	// Used marks this instance as consumed after it has been presented.
	Used bool `gorm:"not null;default:false"`

	// StatusListURI and StatusListIdx are the IETF `status.status_list`
	// reference, when present. Both nil or both set.
	StatusListURI *string
	StatusListIdx *uint64

	// BitstringStatusEntries are the revocation and suspension
	// BitstringStatusListEntries from `credentialStatus`, as JSON
	// ([]bitstringstatus.Entry). Empty when there are none.
	BitstringStatusEntries datatypes.JSON `gorm:"type:JSON"`

	// LastKnownStatus is the most recently observed status, a
	// statuslist.Status; 0 (StatusUnknown) until checked.
	LastKnownStatus uint8 `gorm:"default:0"`

	// LastStatusCheckAt is the time of the most recent successful check. Nil
	// iff the instance has never been checked.
	LastStatusCheckAt *time.Time
}

func (VcdmBatchInstance) TableName() string { return "vcdm_batch_instances" }

// HasStatusReference reports whether the instance names its status in either
// way, so the wallet can check whether it is revoked.
func (i *VcdmBatchInstance) HasStatusReference() bool {
	return i.StatusListURI != nil || len(i.BitstringStatusEntries) > 0
}

func (i *VcdmBatchInstance) BeforeCreate(tx *gorm.DB) error {
	if i.ID.IsNil() {
		i.ID = datatypes.NewUUIDv4()
	}
	if i.HolderBindingKey != nil {
		if i.HolderBindingKey.IsBound() {
			return fmt.Errorf("holder binding key %s is already bound to a credential instance", i.HolderBindingKey.ID)
		}
		i.HolderBindingKey.VcdmBatchInstanceID = &i.ID
	}
	return i.validate()
}

func (i *VcdmBatchInstance) validate() error {
	if i.VcdmBatchID.IsNil() {
		return fmt.Errorf("vcdm_batch_id is required")
	}
	if len(i.RawCredential) == 0 {
		return fmt.Errorf("raw_credential is required")
	}
	return nil
}
