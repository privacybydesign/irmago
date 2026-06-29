package storage

import (
	"fmt"
	"log"
	"os"
	"time"

	eudidb "github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/common"
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

// NewStorage opens (or creates) a SQLite database at path and runs any pending schema migrations.
// The dbPath can be ":memory:" to use an in-memory database (useful for testing) or a path to a file.
// Note: the default transaction has been DISABLED, which means, any Create or Update operation should be wrapped in a transaction (either directly or using the UnitOfWork) to ensure data integrity.
func NewStorage(aesKey [32]byte, dbPath string, storagePath string) (Storage, error) {
	// Ensure the database file exists before opening the connection (file does not always create automatically,
	// depending on the SQLite version and OS)
	if dbPath != ":memory:" {
		if err := common.EnsureFileExists(dbPath); err != nil {
			return nil, fmt.Errorf("failed to ensure database file exists: %w", err)
		}
	}

	connector := &sqlcipher.Connector{Path: dbPath}
	dbLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
	db, err := gorm.Open(sqlcipher.Dialector{Connector: connector}, &gorm.Config{Logger: dbLogger})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}
	if err := eudidb.RunMigrations(sqlDB); err != nil {
		return nil, fmt.Errorf("run database migrations: %w", err)
	}

	return &storage{
		db: db,
		fs: filesystem.NewFileSystemStorage(aesKey, storagePath),
	}, nil
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
