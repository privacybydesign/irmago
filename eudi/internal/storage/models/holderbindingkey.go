package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type KeyAlgorithm string

const (
	KeyAlgorithmECDSA KeyAlgorithm = "ecdsa"
	KeyAlgorithmRSA   KeyAlgorithm = "rsa"
)

// HolderBindingKey is the base/common record used for all key types.
type HolderBindingKey struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`

	Algorithm KeyAlgorithm `gorm:"type:text;not null;index" json:"algorithm"`

	// Secondary lookup, not primary identity.
	PublicKeyThumbprint string `gorm:"type:text;not null;uniqueIndex" json:"public_key_thumbprint"`

	// Encrypted private key bytes, preferably encrypted PKCS#8.
	PrivateKeyEncrypted []byte `gorm:"type:bytea;not null" json:"private_key_encrypted"`

	// One-to-one algorithm-specific metadata.
	ECDSA *ECDSAKeyMetadata `gorm:"constraint:OnDelete:CASCADE;foreignKey:KeyID;references:ID" json:"ecdsa,omitempty"`
	RSA   *RSAKeyMetadata   `gorm:"constraint:OnDelete:CASCADE;foreignKey:KeyID;references:ID" json:"rsa,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

func (k *HolderBindingKey) BeforeCreate(tx *gorm.DB) error {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	k.NormalizeChildren()

	return k.validate()
}

func (HolderBindingKey) TableName() string {
	return "holderbindingkeys"
}

// ECDSAKeyMetadata stores EC-specific metadata.
// KeyID is both the PK and FK to holderbindingkeys.id.
type ECDSAKeyMetadata struct {
	KeyID uuid.UUID `gorm:"type:uuid;primaryKey" json:"key_id"`

	// e.g. P-256, P-384, secp256k1
	CurveName string `gorm:"type:text;not null" json:"curve_name"`

	CreatedAt time.Time `json:"created_at"`
}

func (ECDSAKeyMetadata) TableName() string {
	return "ecdsa_holderbindingkey_metadata"
}

// RSAKeyMetadata stores RSA-specific metadata.
// KeyID is both the PK and FK to holderbindingkeys.id.
type RSAKeyMetadata struct {
	KeyID uuid.UUID `gorm:"type:uuid;primaryKey" json:"key_id"`

	// e.g. 2048, 3072, 4096
	ModulusBits int `gorm:"not null" json:"modulus_bits"`

	// usually 65537
	PublicExponent int `gorm:"not null" json:"public_exponent"`

	CreatedAt time.Time `json:"created_at"`
}

func (RSAKeyMetadata) TableName() string {
	return "rsa_holderbindingkey_metadata"
}

func (k *HolderBindingKey) NormalizeChildren() {
	if k.ECDSA != nil {
		k.ECDSA.KeyID = k.ID
	}
	if k.RSA != nil {
		k.RSA.KeyID = k.ID
	}
}

func (k *HolderBindingKey) validate() error {
	if k.Algorithm == "" {
		return fmt.Errorf("algorithm is required")
	}
	if k.PublicKeyThumbprint == "" {
		return fmt.Errorf("public_key_thumbprint is required")
	}
	if len(k.PrivateKeyEncrypted) == 0 {
		return fmt.Errorf("private_key_encrypted is required")
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
