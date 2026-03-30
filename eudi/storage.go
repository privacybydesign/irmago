package eudi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/internal/storage/models"
	"github.com/privacybydesign/irmago/eudi/internal/storage/sqlcipher"
	"github.com/privacybydesign/irmago/internal/common"
	"gorm.io/gorm"
)

// Storage manages the gorm database connection and owns the migration lifecycle.
type Storage struct {
	db     *gorm.DB
	aesKey [32]byte
}

// NewStorage opens (or creates) a SQLite database at path, then auto-migrates all registered models.
// Note: the default transaction has been DISABLED, which means, any Create or Update operation should be wrapped in a transaction (either directly or using the UnitOfWork) to ensure data integrity.
func NewStorage(aesKey [32]byte, storagePath string) (*Storage, error) {
	// Ensure the database file exists before opening the connection (file does not always create automatically,
	// depending on the SQLite version and OS)
	if err := common.EnsureFileExists(storagePath); err != nil {
		return nil, fmt.Errorf("failed to ensure database file exists: %w", err)
	}

	passphrase := string(aesKey[:])
	dsn := sqlcipher.DSN(storagePath, passphrase)
	db, err := gorm.Open(sqlcipher.Dialector{DSN: dsn}, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// TODO: separate the migration logic from the storage initialization logic, so that we can run migrations without needing to initialize the whole storage
	// This will also save us from executing migrations every time we're creating UnitOfWork instances (which will create new repositories, which will otherwise auto-migrate their models if needed)

	db.AutoMigrate(
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
	)

	// Initialize the repositories, which will auto-migrate their models if needed
	return &Storage{
		db:     db,
		aesKey: aesKey,
	}, nil
}

// Db returns the underlying gorm.DB, for use by repositories in this package.
func (s *Storage) Db() *gorm.DB {
	return s.db
}

// Close closes the underlying database connection.
func (s *Storage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *Storage) Decrypt(ciphertext []byte) ([]byte, error) {
	return decrypt(ciphertext, s.aesKey[:])
}

func (s *Storage) Encrypt(plaintext []byte) ([]byte, error) {
	return encrypt(plaintext, s.aesKey[:])
}

// decrypt is an improved version of internal/clientstorage/storage.go's decrypt
func decrypt(ciphertext []byte, aesKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// encrypt is an improved version of internal/clientstorage/storage.go's encrypt
func encrypt(bytes []byte, aesKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, bytes, nil), nil
}
