package storage

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const DbFilename = "yivi-eudi.db"

type Storage interface {
	Close() error

	Db() *gorm.DB
	FileSystem() filesystem.FileSystemStorage

	RemoveAll() error
}

// Storage manages the gorm database connection and owns the migration lifecycle.
type storage struct {
	db *gorm.DB
	fs filesystem.FileSystemStorage
}

// NewStorageWithDialector opens the holder database on any GORM dialector and
// auto-migrates the credential-holder models, pairing it with the given file
// storage. The models are dialector-agnostic GORM structs, so a caller can back
// the holder engine with its own database — e.g. sqlcipher (encrypted SQLite,
// one wallet per file) via NewStorage, or gorm.io/driver/postgres for a
// server-side, multi-tenant deployment. The caller owns the encryption posture
// of the chosen dialector (sqlcipher encrypts at rest; a plain database does not).
func NewStorageWithDialector(dialector gorm.Dialector, fs filesystem.FileSystemStorage) (Storage, error) {
	db, err := gorm.Open(dialector, &gorm.Config{Logger: newDBLogger()})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// TODO: separate the migration logic from the storage initialization logic, so that we can run migrations without needing to initialize the whole storage
	// This will also save us from executing migrations every time we're creating UnitOfWork instances (which will create new repositories, which will otherwise auto-migrate their models if needed)
	if err := autoMigrateHolderModels(db); err != nil {
		return nil, err
	}

	return &storage{db: db, fs: fs}, nil
}

func newDBLogger() logger.Interface {
	return logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
}

func autoMigrateHolderModels(db *gorm.DB) error {
	// Dependency order (parents before children): a referenced table must exist
	// before the table whose foreign key points at it. SQLite tolerates any order,
	// but Postgres (and any FK-enforcing driver) rejects a CREATE TABLE whose
	// inline REFERENCES target does not exist yet, so the order matters here.
	if err := db.AutoMigrate(
		&models.CredentialBatch{},
		&models.IssuedCredentialInstance{},
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
		&models.EudiLogEntry{},
		&models.EudiLogCredential{},
	); err != nil {
		return fmt.Errorf("auto-migrate database failed: %w", err)
	}
	return nil
}

// Db returns the underlying gorm.DB, for use by repositories in this package.
func (s *storage) Db() *gorm.DB {
	return s.db
}

func (s *storage) FileSystem() filesystem.FileSystemStorage {
	return s.fs
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
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		session := tx.Session(&gorm.Session{AllowGlobalUpdate: true})
		if err := session.Delete(&models.CredentialBatch{}).Error; err != nil {
			return err
		}
		return session.Delete(&models.EudiLogEntry{}).Error
	}); err != nil {
		return err
	}

	return s.fs.RemoveAllFiles()
}
