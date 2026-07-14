package sqlcipher

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
)

// sqliteMagic is the 16-byte header a plaintext SQLite database starts with.
// A SQLCipher-encrypted database begins with a random salt instead, so this
// cleanly distinguishes the two.
var sqliteMagic = []byte("SQLite format 3\x00")

// IsPlaintext reports whether the file at path is an unencrypted SQLite database
// (i.e. one written before the AES key was passed to the connection). A missing,
// empty or too-short file is not considered plaintext.
func IsPlaintext(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	header := make([]byte, len(sqliteMagic))
	if _, err := io.ReadFull(f, header); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	return bytes.Equal(header, sqliteMagic), nil
}

// EncryptInPlace converts the plaintext SQLite database at path into a
// SQLCipher-encrypted database keyed with key, atomically replacing the original.
//
// This is a one-off migration for databases written by v1.0.0/v1.1.0, which
// opened the database without its key and therefore left it unencrypted on disk.
// Callers must only invoke it on a file already known to be plaintext (guard with
// IsPlaintext), and never concurrently with an open handle to the same file.
//
// The plaintext original is left untouched until the encrypted copy has been
// written and verified, so an interrupted run simply retries on the next launch.
// No plaintext copy is retained afterwards.
//
// This migration can be removed once no installs predate v1.1.1 (the release that
// keys the database).
func EncryptInPlace(path string, key []byte) error {
	tmp := path + ".migrating"
	// Discard any temp left by an interrupted run, and the one we create below on
	// any early return; after a successful rename the remove is a harmless no-op.
	_ = os.Remove(tmp)
	defer func() { _ = os.Remove(tmp) }()

	if err := exportEncrypted(path, tmp, key); err != nil {
		return err
	}

	// Prove the encrypted copy opens with the key and is readable before we
	// destroy the plaintext original.
	if err := verifyEncrypted(tmp, key); err != nil {
		return fmt.Errorf("verify re-encrypted database: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace database: %w", err)
	}

	// The old plaintext WAL/SHM sidecars do not belong to the new encrypted file
	// and would corrupt the next open if left in place.
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
	return nil
}

// exportEncrypted copies the full schema and data of the plaintext database at
// srcPath into a new SQLCipher-encrypted database at dstPath, using the standard
// ATTACH + sqlcipher_export mechanism. It reuses the registered driver, so no new
// cgo is needed; SetMaxOpenConns(1) keeps ATTACH and the export on one connection.
func exportEncrypted(srcPath, dstPath string, key []byte) error {
	src := sql.OpenDB(&Connector{Path: srcPath}) // no key: the source is plaintext
	src.SetMaxOpenConns(1)
	defer src.Close()

	// Bulk-copy should not enforce foreign-key ordering across tables.
	if _, err := src.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("disable foreign keys: %w", err)
	}

	attach := fmt.Sprintf(`ATTACH DATABASE '%s' AS encrypted KEY "x'%x'"`, strings.ReplaceAll(dstPath, "'", "''"), key)
	if _, err := src.Exec(attach); err != nil {
		return fmt.Errorf("attach encrypted database: %w", err)
	}
	if _, err := src.Exec("SELECT sqlcipher_export('encrypted')"); err != nil {
		return fmt.Errorf("sqlcipher_export: %w", err)
	}
	// src.Close() detaches the encrypted database, so no explicit DETACH is needed.
	return nil
}

// verifyEncrypted opens path with the key; Connect runs PRAGMA key and a read of
// sqlite_master, so a successful ping proves the file decrypts with this key.
func verifyEncrypted(path string, key []byte) error {
	db := sql.OpenDB(NewConnector(path, key))
	db.SetMaxOpenConns(1)
	defer db.Close()
	return db.Ping()
}
