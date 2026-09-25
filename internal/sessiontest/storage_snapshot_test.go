package sessiontest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/irma/server/keyshare/keyshareserver"
	"github.com/stretchr/testify/require"
)

// A storage snapshot is a copy of a wallet's storage, saved by
// TestGenerateClientStorageForRegressionTests and loaded again by the
// TestClientStorageRegression* tests, one folder per version under
// testdata/storage_regression/v<version>/.

const storageRegressionFixtureDir = "storage_regression"

// snapshotPaths lists what a snapshot holds: each path in the snapshot folder,
// and where it lives in the wallet's storage folder. Saving copies from the
// wallet to the snapshot, loading copies back. Older snapshots lack some paths
// (v0.19.2 predates the EUDI database; logos are there from v1.4.0), and a
// missing path is skipped.
var snapshotPaths = []struct{ snapshot, wallet string }{
	{"bbolt_client_db", "db2"},
	{"eudi_client_db", filepath.Join("eudi", storage.DbFilename)},
	{"ecdsa_sk.pem", "ecdsa_sk.pem"},
	// The databases store only a logo's key. The bytes are these encrypted
	// files, named by an HMAC of the key.
	{"eudi_logos/credentials", "eudi/credentials/logos"},
	{"eudi_logos/issuers", "eudi/issuers/logos"},
	{"eudi_logos/verifiers", "eudi/verifiers/logos"},
}

// keyshareUsersFile holds the test keyshare server's users, so that a loaded
// wallet's keyshare enrollment is recognised. It is not part of the wallet.
const keyshareUsersFile = "keyshare_users.json"

func snapshotDir(t *testing.T, version string) string {
	return filepath.Join(test.FindTestdataFolder(t), storageRegressionFixtureDir, version)
}

// newSnapshotWallet creates an empty wallet storage folder with the trust
// anchors every snapshot session needs: the staging issuer for the veramo
// credentials and the Python PID issuer for the mdoc.
func newSnapshotWallet(t *testing.T) string {
	return newTestStorageFolder(t, stagingIssuerAnchor, pidIssuerAnchor(t))
}

// openSnapshotWallet opens the wallet in storagePath, with the signer key
// stored there (a new one is made and stored when there is none).
func openSnapshotWallet(t *testing.T, storagePath string) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	t.Helper()
	signer := loadOrCreateSigner(t, filepath.Join(storagePath, "ecdsa_sk.pem"))
	c, clientHandler, sessionHandler := createClientWithStorageAndSigner(t, storagePath,
		filepath.Join(storagePath, "irma_configuration"), filepath.Join(storagePath, "eudi"), signer)
	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	return c, clientHandler, sessionHandler
}

func loadOrCreateSigner(t *testing.T, pemPath string) irmaclient.Signer {
	t.Helper()
	bts, err := os.ReadFile(pemPath)
	if os.IsNotExist(err) {
		sk, err := signed.GenerateKey()
		require.NoError(t, err)
		bts, err = signed.MarshalPemPrivateKey(sk)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(pemPath, bts, 0644))
		return test.LoadSigner(t, sk)
	}
	require.NoError(t, err)
	sk, err := signed.UnmarshalPemPrivateKey(bts)
	require.NoError(t, err)
	return test.LoadSigner(t, sk)
}

// saveSnapshot copies a closed wallet's storage, and the keyshare server's
// users, into the snapshot folder dir.
func saveSnapshot(t *testing.T, storagePath, dir string, keyshareDB *keyshareserver.MemoryDB) {
	t.Helper()
	require.NoError(t, common.EnsureDirectoryExists(dir))
	for _, p := range snapshotPaths {
		copyIfExists(t, filepath.Join(storagePath, p.wallet), filepath.Join(dir, p.snapshot))
	}

	users, err := json.Marshal(keyshareDB.DumpUsers())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, keyshareUsersFile), users, 0644))
}

// setupStorageRegressionClient starts the test servers and opens a wallet
// loaded from the given version's snapshot. Skips when the snapshot is absent.
func setupStorageRegressionClient(t *testing.T, version string) (*client.Client, *MockSessionHandler, *IrmaServer) {
	t.Helper()
	dir := snapshotDir(t, version)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skipf("snapshot %s not found; run TestGenerateClientStorageForRegressionTests first", dir)
	}

	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	t.Cleanup(func() { irmaServer.Stop() })

	keyshareServer := testkeyshare.StartKeyshareServerWithDB(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	t.Cleanup(func() { keyshareServer.Stop() })
	loadKeyshareUsers(t, keyshareServer.DB, dir)

	storagePath := newSnapshotWallet(t)
	for _, p := range snapshotPaths {
		copyIfExists(t, filepath.Join(dir, p.snapshot), filepath.Join(storagePath, p.wallet))
	}
	c, _, sessionHandler := openSnapshotWallet(t, storagePath)
	t.Cleanup(func() { _ = c.Close() })

	// Opening the wallet encrypts a plaintext EUDI database (v1.0.0) in place,
	// and creates an encrypted one when the snapshot has none (v0.19.2). Either
	// way it must be encrypted at rest afterwards.
	plaintext, err := sqlcipher.IsPlaintext(filepath.Join(storagePath, "eudi", storage.DbFilename))
	require.NoError(t, err)
	require.False(t, plaintext, "EUDI database must be encrypted at rest after loading")

	return c, sessionHandler, irmaServer
}

func loadKeyshareUsers(t *testing.T, db *keyshareserver.MemoryDB, dir string) {
	t.Helper()
	bts, err := os.ReadFile(filepath.Join(dir, keyshareUsersFile))
	if os.IsNotExist(err) {
		return
	}
	require.NoError(t, err)

	var users []keyshareserver.User
	require.NoError(t, json.Unmarshal(bts, &users))
	for i := range users {
		_ = db.AddUser(context.Background(), &users[i])
	}
}

// copyIfExists copies the file or directory src to dst, and does nothing when
// src does not exist.
func copyIfExists(t *testing.T, src, dst string) {
	t.Helper()
	info, err := os.Stat(src)
	if os.IsNotExist(err) {
		return
	}
	require.NoError(t, err)
	if info.IsDir() {
		require.NoError(t, common.CopyDirectory(src, dst))
		return
	}
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, common.EnsureDirectoryExists(filepath.Dir(dst)))
	require.NoError(t, os.WriteFile(dst, data, 0644))
}
