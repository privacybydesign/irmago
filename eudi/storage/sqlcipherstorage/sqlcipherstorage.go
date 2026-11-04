// Package sqlcipherstorage constructs the EUDI holder storage backed by an
// sqlcipher-encrypted SQLite database (the wallet-on-a-device deployment).
//
// It is split out of the parent eudi/storage package on purpose: sqlcipher is a
// cgo package (it links libsqlcipher), and Go compiles every imported package.
// Keeping the sqlcipher constructor here means a consumer of
// storage.NewStorageWithDialector — e.g. a gorm.io/driver/postgres, server-side
// deployment — can import eudi/storage without compiling sqlcipher, and so build
// with CGO_ENABLED=0 (and without libsqlcipher on the build host). Consumers that
// want the sqlcipher database import this package explicitly.
package sqlcipherstorage

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/common"
)

// New opens (or creates) an sqlcipher-encrypted SQLite database at dbPath, then
// delegates to storage.NewStorageWithDialector to auto-migrate all registered
// models. dbPath can be ":memory:" for an in-memory database (useful for
// testing) or a path to a file.
//
// Note: the default transaction has been DISABLED, which means any Create or
// Update operation should be wrapped in a transaction (either directly or using
// the UnitOfWork) to ensure data integrity.
func New(aesKey [32]byte, dbPath string, storagePath string) (storage.Storage, error) {
	// Ensure the database file exists before opening the connection (file does not always create automatically,
	// depending on the SQLite version and OS)
	if dbPath != ":memory:" {
		if err := common.EnsureFileExists(dbPath); err != nil {
			return nil, fmt.Errorf("failed to ensure database file exists: %w", err)
		}

		// Migrate legacy plaintext databases (written by v1.0.0/v1.1.0, which opened
		// the database without its key) to an encrypted database before opening with
		// the key. This is a no-op for already-encrypted and freshly-created files.
		plaintext, err := sqlcipher.IsPlaintext(dbPath)
		if err != nil {
			return nil, fmt.Errorf("inspect database file: %w", err)
		}
		if plaintext {
			if err := sqlcipher.EncryptInPlace(dbPath, aesKey[:]); err != nil {
				return nil, fmt.Errorf("encrypt legacy plaintext database: %w", err)
			}
		}
	}

	connector := sqlcipher.NewConnector(dbPath, aesKey[:])
	return storage.NewStorageWithDialector(sqlcipher.Dialector{Connector: connector}, filesystem.NewFileSystemStorage(aesKey, storagePath))
}
