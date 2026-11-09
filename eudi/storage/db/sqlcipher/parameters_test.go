package sqlcipher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fixtureKey is the raw 32-byte key testdata/before-parameter-pinning.db is encrypted with:
// the bytes 0x00 to 0x1f.
func fixtureKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// The parameters an encrypted database is opened with are the pinned SQLCipher 4 ones, whatever
// the defaults of the linked library.
func TestSQLCipher_PinsCipherParameters(t *testing.T) {
	key := make([]byte, 32)
	db := openGormDB(t, NewConnector(filepath.Join(t.TempDir(), "test.db"), key))
	defer closeGormDB(t, db)

	for pragma, expected := range map[string]string{
		"cipher_hmac_algorithm": "HMAC_SHA512",
		"cipher_kdf_algorithm":  "PBKDF2_HMAC_SHA512",
		"cipher_page_size":      "4096",
		"kdf_iter":              "256000",
	} {
		var value string
		require.NoError(t, db.Raw("PRAGMA "+pragma).Scan(&value).Error, pragma)
		require.Equal(t, expected, value, pragma)
	}
}

// testdata/before-parameter-pinning.db was written by this driver before it pinned the
// parameters, when it relied on the linked SQLCipher 4's defaults, as every wallet database
// written until then. Pinning must not make such a database unreadable.
func TestSQLCipher_OpensDatabaseWrittenBeforeParameterPinning(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "before-parameter-pinning.db"))
	require.NoError(t, err)
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	require.NoError(t, os.WriteFile(dbPath, fixture, 0o600))

	db := openGormDB(t, NewConnector(dbPath, fixtureKey()))
	defer closeGormDB(t, db)

	var value string
	require.NoError(t, db.Raw("SELECT value FROM fixture").Scan(&value).Error)
	require.Equal(t, "written before the SQLCipher parameters were pinned", value)
}

// The fixture is encrypted with other parameters than SQLCipher 3's defaults, so opening it with
// those fails: the pinned parameters are what make it readable, not a lenient driver.
func TestSQLCipher_FixtureIsNotReadableWithSQLCipher3Parameters(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "before-parameter-pinning.db"))
	require.NoError(t, err)
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	require.NoError(t, os.WriteFile(dbPath, fixture, 0o600))

	saved := cipherParameterPragmas
	cipherParameterPragmas = []string{"PRAGMA cipher_compatibility = 3"}
	defer func() { cipherParameterPragmas = saved }()

	_, err = NewConnector(dbPath, fixtureKey()).Connect(t.Context())
	require.ErrorContains(t, err, "key verification failed")
}
