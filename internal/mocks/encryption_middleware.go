package mocks

import "github.com/privacybydesign/irmago/internal/crypto/encryption"

type MockEncryptionMiddleware struct{}

func (m *MockEncryptionMiddleware) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (m *MockEncryptionMiddleware) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

var _ encryption.EncryptionMiddleware = (*MockEncryptionMiddleware)(nil)
