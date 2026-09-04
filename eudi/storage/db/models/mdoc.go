package models

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// The mso_mdoc storage models. They share nothing with the SD-JWT VC models
// but the database file: their own tables, their own key table, their own
// names. Everything here follows ISO/IEC 18013-5, not SD-JWT VC.
//
// The two formats deliberately do not share a table. They evolve on different
// specifications, on different timelines, and towards different hardware seams,
// so one table would make every schema change to one format a migration of the
// other's rows, and every format-specific column a nullable one the other
// format has to remember to ignore.

// MdocNamespaces is an mdoc's element values, namespace → elementIdentifier →
// value, as cached at issuance after services.NormalizeMdocClaimValues turned
// CBOR-only types (byte strings, tagged dates) into JSON-safe shapes. Stored as
// one JSON column. The values are always JSON-shaped — numbers float64, arrays
// []any, maps map[string]any — both in memory and when read back, so no reader
// has to care which side of the database it is on (see
// services.JSONShapedMdocNamespaces).
type MdocNamespaces map[string]map[string]any

// MdocBatch is one logical mso_mdoc credential: every document issued from a
// single credential_configuration_id within one OpenID4VCI issuance session.
// When the issuer supports batch issuance, BatchSize > 1 and one
// MdocBatchInstance row exists per document, each bound to its own device key.
// Single-use wallets decrement RemainingCount on each presentation; the batch
// is exhausted when it reaches 0.
type MdocBatch struct {
	ID datatypes.UUID `gorm:"primaryKey"`

	// DocType is the ISO 18013-5 document type from the signed MSO (e.g.
	// "eu.europa.ec.av.1", "org.iso.18013.5.1.mDL"). It is the credential type
	// DCQL doctype_value matches against and relying-party authorization keys on.
	DocType string `gorm:"not null"`

	// CredentialIssuer is the OpenID4VCI credential_issuer the document was
	// obtained from, per the issuer metadata used at issuance. It is the only
	// issuer identity an mdoc issuance yields: an mdoc has no `iss` claim, and the
	// document signer certificate is not lifted into a column. That certificate,
	// with its IACA, travels inside every instance's IssuerSigned bytes
	// (IssuerAuth unprotected header 33, x5chain), so a certificate-derived
	// identity can be backfilled from stored data if something comes to read it.
	CredentialIssuer string `gorm:"not null"`

	// Hash is the deterministic content identity over docType, credential issuer
	// and the sorted element values — the three things that make two credentials
	// the same credential. Computed by services.hashGeneric. Unique within this
	// table; the SD-JWT table has its own.
	Hash string `gorm:"uniqueIndex;not null"`

	// Namespaces caches the element values so DCQL matching and display do not
	// re-decode CBOR. Always non-empty: an mdoc with no elements is not a
	// credential.
	Namespaces MdocNamespaces `gorm:"serializer:json;type:JSON;not null"`

	// SignedAt, ValidFrom and ValidUntil are the MSO's validityInfo. ISO 18013-5
	// makes all three mandatory, so none of them is nullable here.
	SignedAt   time.Time `gorm:"not null"`
	ValidFrom  time.Time `gorm:"not null"`
	ValidUntil time.Time `gorm:"not null"`

	// BatchSize is the number of documents issued in this batch; RemainingCount
	// how many have not yet been presented.
	BatchSize      uint `gorm:"not null"`
	RemainingCount uint `gorm:"not null"`

	// IssuerVerified records that issuerAuth verified against an IACA trust
	// anchor before the batch was stored. Stored rather than re-derived, for the
	// reasons SdJwtVcBatch.IssuerVerified gives.
	IssuerVerified bool

	// IssuerDisplay is the issuer metadata's top-level display[] array as
	// published, JSON, decoded by services when rendering. May be empty.
	IssuerDisplay datatypes.JSON `gorm:"type:JSON"`

	// CredentialMetadata is the credential configuration's credential_metadata
	// (display and claims) as published, JSON. Empty when the issuer advertised
	// none; the credential then renders as its docType and element identifiers.
	CredentialMetadata datatypes.JSON `gorm:"type:JSON"`

	Instances []MdocBatchInstance `gorm:"foreignKey:MdocBatchID;constraint:OnDelete:CASCADE"`
}

func (MdocBatch) TableName() string { return "mdoc_batches" }

func (b *MdocBatch) BeforeCreate(tx *gorm.DB) error {
	if b.ID.IsNil() {
		b.ID = datatypes.NewUUIDv4()
	}
	for i := range b.Instances {
		b.Instances[i].MdocBatchID = b.ID
	}
	return b.validate()
}

func (b *MdocBatch) validate() error {
	if b.DocType == "" {
		return fmt.Errorf("doc_type is required")
	}
	if b.CredentialIssuer == "" {
		return fmt.Errorf("credential_issuer is required")
	}
	if b.Hash == "" {
		return fmt.Errorf("hash is required")
	}
	if len(b.Namespaces) == 0 {
		return fmt.Errorf("namespaces are required")
	}
	if b.SignedAt.IsZero() || b.ValidFrom.IsZero() || b.ValidUntil.IsZero() {
		return fmt.Errorf("signed_at, valid_from and valid_until are required")
	}
	if b.BatchSize == 0 {
		return fmt.Errorf("batch_size must be at least 1")
	}
	if b.RemainingCount > b.BatchSize {
		return fmt.Errorf("remaining_count cannot exceed batch_size")
	}
	return nil
}

// MdocBatchInstance is one issued document within an MdocBatch: the
// issuer-signed half of an ISO 18013-5 Document, bound to one device key.
type MdocBatchInstance struct {
	ID datatypes.UUID `gorm:"primaryKey"`

	MdocBatchID datatypes.UUID `gorm:"not null;index"`

	// IssuerSigned is the CBOR of docType plus IssuerSigned as issued, without
	// DeviceSigned: the holder attaches a fresh DeviceSigned at every
	// presentation. The SQLCipher layer encrypts it at rest.
	IssuerSigned []byte `gorm:"type:bytea;not null"`

	// Used marks the document as presented. Single-use batch wallets never
	// present a used document again.
	Used bool `gorm:"not null;default:false"`

	// DeviceKey is the key pair bound into this document's MSO. Nil while the
	// batch is being assembled; linked once the credential has been verified
	// against the key. Presentation does not read this association — it resolves
	// the key by the thumbprint of the device public key in the MSO — but the
	// association is what carries the cascade.
	DeviceKey *MdocDeviceKey `gorm:"foreignKey:MdocBatchInstanceID;constraint:OnDelete:CASCADE"`
}

func (MdocBatchInstance) TableName() string { return "mdoc_batch_instances" }

func (i *MdocBatchInstance) BeforeCreate(tx *gorm.DB) error {
	if i.ID.IsNil() {
		i.ID = datatypes.NewUUIDv4()
	}
	if i.DeviceKey != nil {
		if i.DeviceKey.MdocBatchInstanceID != nil && !i.DeviceKey.MdocBatchInstanceID.IsNil() {
			return fmt.Errorf("device key %s is already bound to mdoc batch instance %s",
				i.DeviceKey.ID, *i.DeviceKey.MdocBatchInstanceID)
		}
		i.DeviceKey.MdocBatchInstanceID = &i.ID
	}
	return i.validate()
}

func (i *MdocBatchInstance) validate() error {
	if i.MdocBatchID.IsNil() {
		return fmt.Errorf("mdoc_batch_id is required")
	}
	if len(i.IssuerSigned) == 0 {
		return fmt.Errorf("issuer_signed is required")
	}
	return nil
}

// MdocDeviceKey is the key pair one document is bound to (ISO 18013-5
// deviceKeyInfo): the issuer signs the public half into the MSO, the holder
// signs DeviceAuth with the private half at presentation.
//
// A key is created before the document exists, to prove possession in the
// OpenID4VCI credential request, so MdocBatchInstanceID is nil until issuance
// has matched the key to the document the issuer bound it into. Deleting the
// instance cascades to the key.
//
// Identity is always the JWK thumbprint of the public key. That is what the
// MSO's COSE_Key yields at issuance and at presentation, whichever binding
// method the proof used, so there is no DID URL column and no need to derive
// one.
type MdocDeviceKey struct {
	ID datatypes.UUID `gorm:"primaryKey"`

	MdocBatchInstanceID *datatypes.UUID `gorm:"index"`

	// PublicKeyThumbprint is the hex SHA-256 JWK thumbprint (RFC 7638) of the
	// public key.
	PublicKeyThumbprint string `gorm:"uniqueIndex;not null"`

	// PrivateKey is the PKCS#8-encoded private key. The SQLCipher layer encrypts
	// it at rest. A hardware-backed device key would store a handle here instead;
	// see mdoc_dcql.DeviceKeyBinder.
	PrivateKey []byte `gorm:"type:bytea;not null"`

	// Curve names the elliptic curve, e.g. P-256 (the one ISO 18013-5 profiles
	// for ES256).
	Curve string `gorm:"not null"`

	CreatedAt time.Time
}

func (MdocDeviceKey) TableName() string { return "mdoc_device_keys" }

func (k *MdocDeviceKey) BeforeCreate(tx *gorm.DB) error {
	if k.ID.IsNil() {
		k.ID = datatypes.NewUUIDv4()
	}
	k.CreatedAt = time.Now().UTC()
	return k.validate()
}

func (k *MdocDeviceKey) validate() error {
	if k.PublicKeyThumbprint == "" {
		return fmt.Errorf("public_key_thumbprint is required")
	}
	if len(k.PrivateKey) == 0 {
		return fmt.Errorf("private_key is required")
	}
	if k.Curve == "" {
		return fmt.Errorf("curve is required")
	}
	return nil
}
