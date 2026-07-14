package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type AESEncryptionMiddleware struct {
	aesKey [32]byte
}

func NewAESEncryptionMiddleware(aesKey [32]byte) EncryptionMiddleware {
	return &AESEncryptionMiddleware{
		aesKey: aesKey,
	}
}

func (e *AESEncryptionMiddleware) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.aesKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("unable to decrypt data: ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (e *AESEncryptionMiddleware) Encrypt(bytes []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.aesKey[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, bytes, nil), nil
}
