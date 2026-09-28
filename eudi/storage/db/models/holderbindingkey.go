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

// KeyBackend is where a holder key's private half lives (CONTEXT.md, "Key
// backend").
type KeyBackend string

const (
	// KeyBackendSoftware: generated on the device and kept in this database.
	KeyBackendSoftware KeyBackend = "software"
	// KeyBackendWalletProvider: in the wallet provider's HSM; this database
	// keeps only the provider's reference to it.
	KeyBackendWalletProvider KeyBackend = "wallet-provider"
)

// providerKeyRef is what a key row with the given backend and private key
// bytes holds as the wallet provider's reference: its PrivateKey for a
// provider key, "" for a software key.
func providerKeyRef(backend KeyBackend, privateKey []byte) string {
	if backend != KeyBackendWalletProvider {
		return ""
	}
	return string(privateKey)
}

type KeyAlgorithm string

const (
	KeyAlgorithmECDSA KeyAlgorithm = "ecdsa"
	KeyAlgorithmRSA   KeyAlgorithm = "rsa"
)

// HolderBindingKey is an SD-JWT VC holder binding key: the key pair a
// credential's cnf claim binds it to.
type HolderBindingKey struct {
	ID datatypes.UUID `gorm:"primaryKey"`

	// FK back to the owning SdJwtVcBatchInstance (Has One from there). Nil when
	// the key has not yet been bound to a credential instance. SD-JWT VC only:
	// mdoc device keys live in MdocDeviceKey.
	IssuedCredentialInstanceID *datatypes.UUID

	Algorithm KeyAlgorithm `gorm:"type:text;not null;index"`

	// Secondary lookup, either by PublicKeyThumbprint or DidUrl, not primary identity. Mutually exclusive with each other, but this is not enforced by the database.
	// According to the docs, null values do not count towards uniqueness in SQLite, but this might be different in other databases
	// In the future, we might want to add conditional indexing (where clause), but we need custom migrations in order to get that working with GORM.
	PublicKeyThumbprint datatypes.NullString `gorm:"uniqueIndex"`
	DidUrl              datatypes.NullString `gorm:"uniqueIndex"`

	// KeyBackend says where the private key lives, and so what PrivateKey
	// holds: PKCS#8 bytes for a software key, the wallet provider's key
	// reference for a key in its HSM. Fixed when the key is created.
	KeyBackend KeyBackend `gorm:"type:text;not null;default:'software'"`

	// Private key bytes, preferably PKCS#8, or the wallet provider's reference
	// to the key; see KeyBackend.
	PrivateKey []byte `gorm:"type:bytea;not null"`

	// One-to-one algorithm-specific metadata.
	ECDSA *ECDSAKeyMetadata `gorm:"constraint:OnDelete:CASCADE"`
	RSA   *RSAKeyMetadata   `gorm:"constraint:OnDelete:CASCADE"`

	// Date/time of creation (UTC)
	CreatedAt time.Time
}

// ProviderKeyRef returns the wallet provider's reference to the key, or ""
// for a software key.
func (k *HolderBindingKey) ProviderKeyRef() string {
	return providerKeyRef(k.KeyBackend, k.PrivateKey)
}

func (k *HolderBindingKey) BeforeCreate(tx *gorm.DB) error {
	if k.ID.IsNil() {
		k.ID = datatypes.NewUUIDv4()
	}

	k.CreatedAt = time.Now().UTC()
	if k.KeyBackend == "" {
		k.KeyBackend = KeyBackendSoftware
	}
	k.NormalizeChildren()

	return k.validate()
}

// ECDSAKeyMetadata stores EC-specific metadata.
// KeyID is both the PK and FK to holderbindingkeys.id.
type ECDSAKeyMetadata struct {
	HolderBindingKeyID datatypes.UUID `gorm:"primaryKey"`

	// e.g. P-256, P-384, secp256k1
	CurveName string
}

// RSAKeyMetadata stores RSA-specific metadata.
// KeyID is both the PK and FK to holderbindingkeys.id.
type RSAKeyMetadata struct {
	HolderBindingKeyID datatypes.UUID `gorm:"primaryKey"`

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
