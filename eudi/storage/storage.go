package storage

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage/models"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipher"
	"github.com/privacybydesign/irmago/internal/common"
	"gorm.io/gorm"
)

// Common errors for storage operations.
var (
	ErrNotFound = errors.New("not found")
)

type Storage interface {
	Close() error
	Db() *gorm.DB

	RemoveAll() error
}

// Storage manages the gorm database connection and owns the migration lifecycle.
type storage struct {
	db *gorm.DB
}

// NewStorage opens (or creates) a SQLite database at path, then auto-migrates all registered models.
// Note: the default transaction has been DISABLED, which means, any Create or Update operation should be wrapped in a transaction (either directly or using the UnitOfWork) to ensure data integrity.
func NewStorage(aesKey [32]byte, storagePath string) (Storage, error) {
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

	err = db.AutoMigrate(
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
		&models.CredentialBatch{},
		&models.IssuedCredentialInstance{},
	)

	if err != nil {
		return nil, fmt.Errorf("auto-migrate database failed: %w", err)
	}

	// Initialize the repositories, which will auto-migrate their models if needed
	return &storage{
		db: db,
	}, nil
}

// Db returns the underlying gorm.DB, for use by repositories in this package.
func (s *storage) Db() *gorm.DB {
	return s.db
}

// Close closes the underlying database connection.
func (s *storage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *storage) RemoveAll() error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).
			Delete(&models.HolderBindingKey{}). // CASCADE should take care of deleting related metadata
			Delete(&models.CredentialBatch{})   // CASCADE should take care of deleting related instances and metadata

		return result.Error
	})
}
