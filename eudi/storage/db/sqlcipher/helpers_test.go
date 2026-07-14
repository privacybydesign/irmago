package sqlcipher

import (
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
)

func newECDSAKey() *models.HolderBindingKey {
	thumbprintEcdsa := "test-thumbprint-ecdsa"
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmECDSA,
		PublicKeyThumbprint: datatypes.NullString{V: thumbprintEcdsa, Valid: true},
		PrivateKey:          []byte("encrypted-private-key"),
		ECDSA: &models.ECDSAKeyMetadata{
			CurveName: "P-256",
		},
	}
}

func newRSAKey() *models.HolderBindingKey {
	thumbprintRsa := "test-thumbprint-rsa"
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmRSA,
		PublicKeyThumbprint: datatypes.NullString{V: thumbprintRsa, Valid: true},
		PrivateKey:          []byte("encrypted-private-key"),
		RSA: &models.RSAKeyMetadata{
			ModulusBits:    2048,
			PublicExponent: 65537,
		},
	}
}
