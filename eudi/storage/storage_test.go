package storage

import (
	"bytes"
	"os"
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
)

// TestNewStorageWithDialector_MigratesViaSeam checks the dialector seam runs the
// holder-model AutoMigrate independently of the concrete driver (here sqlcipher
// in-memory), so callers can supply their own dialector (e.g. Postgres).
func TestNewStorageWithDialector_MigratesViaSeam(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	connector := sqlcipher.NewConnector(":memory:", aesKey[:])
	s, err := NewStorageWithDialector(
		sqlcipher.Dialector{Connector: connector},
		filesystem.NewFileSystemStorage(aesKey, t.TempDir()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	assert.True(t, s.Db().Migrator().HasTable(&models.CredentialMetadata{}),
		"the seam must auto-migrate the holder models")
}

// TestNewStorageWithDialector_Postgres proves the holder models migrate onto a
// Postgres dialector — the server-side, multi-tenant deployment path. Skipped
// unless EUDI_TEST_POSTGRES_DSN points at a (throwaway) database.
func TestNewStorageWithDialector_Postgres(t *testing.T) {
	dsn := os.Getenv("EUDI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set EUDI_TEST_POSTGRES_DSN to run the Postgres-backed holder storage test")
	}

	s, err := NewStorageWithDialector(postgres.Open(dsn), filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	assert.True(t, s.Db().Migrator().HasTable(&models.CredentialMetadata{}),
		"the Postgres seam must auto-migrate the holder models")
}

// TestDBLogger_LogsStatementsWithoutBoundValues is the regression guard for the
// holder database writing the wallet's contents to the platform log. GORM
// renders a slow or failing statement with its arguments inlined by default, and
// the arguments here are raw SD-JWT VC tokens, attribute JSON and holder binding
// keys; on mobile the output went to stdout, which gomobile redirects to logcat
// and the iOS console regardless of the log level the app set. The statement
// must still be identifiable, so the placeholders have to survive.
func TestDBLogger_LogsStatementsWithoutBoundValues(t *testing.T) {
	var logged bytes.Buffer
	captureLogger := logrus.New()
	captureLogger.SetOutput(&logged)
	captureLogger.SetLevel(logrus.WarnLevel)

	previous := common.Logger
	common.Logger = captureLogger
	t.Cleanup(func() { common.Logger = previous })

	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	connector := sqlcipher.NewConnector(":memory:", aesKey[:])
	s, err := NewStorageWithDialector(
		sqlcipher.Dialector{Connector: connector},
		filesystem.NewFileSystemStorage(aesKey, t.TempDir()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// A statement that fails while carrying a credential-shaped value, which is
	// what makes GORM log it in the first place.
	const credential = "eyJhbGciOiJFUzI1NiJ9.a-credential-that-must-not-be-logged"
	require.Error(t, s.Db().Exec(
		"INSERT INTO no_such_table (raw_credential) VALUES (?)", credential,
	).Error)

	out := logged.String()
	require.NotEmpty(t, out, "a failing statement must still be logged")
	assert.NotContains(t, out, credential, "bound values must never reach the log")
	assert.Contains(t, out, "no_such_table", "the statement itself must stay identifiable")
}
