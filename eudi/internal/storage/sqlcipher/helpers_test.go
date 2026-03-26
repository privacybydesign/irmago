package sqlcipher

import "github.com/privacybydesign/irmago/eudi/internal/storage/models"

func newECDSAKey() *models.HolderBindingKey {
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmECDSA,
		PublicKeyThumbprint: "test-thumbprint-ecdsa",
		PrivateKey:          []byte("encrypted-private-key"),
		ECDSA: &models.ECDSAKeyMetadata{
			CurveName: "P-256",
		},
	}
}

func newRSAKey() *models.HolderBindingKey {
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmRSA,
		PublicKeyThumbprint: "test-thumbprint-rsa",
		PrivateKey:          []byte("encrypted-private-key"),
		RSA: &models.RSAKeyMetadata{
			ModulusBits:    2048,
			PublicExponent: 65537,
		},
	}
}
