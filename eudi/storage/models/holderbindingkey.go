package models

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type PublicHolderBindingKey struct {
	ID                  datatypes.UUID
	DidUrl              *string
	PublicKeyThumbprint *string
}

type KeyAlgorithm string

const (
	KeyAlgorithmECDSA KeyAlgorithm = "ecdsa"
	KeyAlgorithmRSA   KeyAlgorithm = "rsa"
)

// HolderBindingKey is the base/common record used for all key types.
type HolderBindingKey struct {
	ID datatypes.UUID `gorm:"primaryKey"`

	Algorithm KeyAlgorithm `gorm:"type:text;not null;index"`

	// Secondary lookup, either by PublicKeyThumbprint or DidUrl, not primary identity. Mutually exclusive with each other, but this is not enforced by the database.
	// According to the docs, null values do not count towards uniqueness in SQLite, but this might be different in other databases
	// In the future, we might want to add conditional indexing (where clause), but we need custom migrations in order to get that working with GORM.
	PublicKeyThumbprint datatypes.NullString `gorm:"uniqueIndex"`
	DidUrl              datatypes.NullString `gorm:"uniqueIndex"`

	// Private key bytes, preferably PKCS#8.
	PrivateKey []byte `gorm:"type:bytea;not null"`

	// One-to-one algorithm-specific metadata.
	ECDSA *ECDSAKeyMetadata `gorm:"constraint:OnDelete:CASCADE"`
	RSA   *RSAKeyMetadata   `gorm:"constraint:OnDelete:CASCADE"`

	// Date/time of creation (UTC)
	CreatedAt time.Time
}

func (k *HolderBindingKey) BeforeCreate(tx *gorm.DB) error {
	if k.ID.IsNil() {
		k.ID = datatypes.NewUUIDv4()
	}

	k.CreatedAt = time.Now().UTC()
	k.NormalizeChildren()

	return k.validate()
}

// ECDSAKeyMetadata stores EC-specific metadata.
// KeyID is both the PK and FK to holderbindingkeys.id.
type ECDSAKeyMetadata struct {
	HolderBindingKeyID datatypes.UUID `gorm:"uniqueIndex"`

	// e.g. P-256, P-384, secp256k1
	CurveName string
}

// RSAKeyMetadata stores RSA-specific metadata.
// KeyID is both the PK and FK to holderbindingkeys.id.
type RSAKeyMetadata struct {
	HolderBindingKeyID datatypes.UUID `gorm:"uniqueIndex"`

	// e.g. 2048, 3072, 4096
	ModulusBits int

	// usually 65537
	PublicExponent int
}

func (k *HolderBindingKey) NormalizeChildren() {
	if k.ECDSA != nil {
		k.ECDSA.HolderBindingKeyID = k.ID
	}
	if k.RSA != nil {
		k.RSA.HolderBindingKeyID = k.ID
	}
}

func (k *HolderBindingKey) validate() error {
	if k.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if !k.PublicKeyThumbprint.Valid && !k.DidUrl.Valid {
		return fmt.Errorf("either public_key_thumbprint or did_url is required")
	}
	if k.PublicKeyThumbprint.Valid && k.DidUrl.Valid {
		return fmt.Errorf("public_key_thumbprint and did_url are mutually exclusive")
	}
	if len(k.PrivateKey) == 0 {
		return fmt.Errorf("private_key is required")
	}

	switch k.Algorithm {
	case KeyAlgorithmECDSA:
		if k.ECDSA == nil {
			return fmt.Errorf("ecdsa metadata is required for ecdsa keys")
		}
		if k.RSA != nil {
			return fmt.Errorf("rsa metadata must be nil for ecdsa keys")
		}
		if k.ECDSA.CurveName == "" {
			return fmt.Errorf("curve_name is required for ecdsa keys")
		}

	case KeyAlgorithmRSA:
		if k.RSA == nil {
			return fmt.Errorf("rsa metadata is required for rsa keys")
		}
		if k.ECDSA != nil {
			return fmt.Errorf("ecdsa metadata must be nil for rsa keys")
		}
		if k.RSA.ModulusBits <= 0 {
			return fmt.Errorf("modulus_bits is required for rsa keys")
		}
		if k.RSA.PublicExponent <= 0 {
			return fmt.Errorf("public_exponent is required for rsa keys")
		}

	default:
		return fmt.Errorf("unsupported algorithm: %q", k.Algorithm)
	}

	return nil
}
