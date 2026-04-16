package encryption

type EncryptionMiddleware interface {
	Encrypt(bytes []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}
