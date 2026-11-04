package irma

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

// copyPrivateKeysFolder copies the test private keys to a temporary folder, so that tests
// can modify the files on disk without affecting other tests.
func copyPrivateKeysFolder(t *testing.T, files ...string) string {
	src := filepath.Join(test.FindTestdataFolder(t), "privatekeys")
	dst := t.TempDir()
	if len(files) == 0 {
		entries, err := os.ReadDir(src)
		require.NoError(t, err)
		for _, e := range entries {
			files = append(files, e.Name())
		}
	}
	for _, f := range files {
		copyPrivateKeyFile(t, src, dst, f)
	}
	return dst
}

func copyPrivateKeyFile(t *testing.T, srcDir, dstDir, filename string) {
	bts, err := os.ReadFile(filepath.Join(srcDir, filename))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, filename), bts, 0600))
}

// touch sets the modification time of the file, so that the key ring sees it as changed.
func touch(t *testing.T, path string, mtime time.Time) {
	require.NoError(t, os.Chtimes(path, mtime, mtime))
}

// Parsing and validating a private key is expensive (for non-demo schemes it includes safe prime
// checks), and the IRMA server looks up the private key once per credential in an issuance
// request. The folder ring must therefore not re-parse a key file that did not change.
func TestPrivateKeyRingFolderReusesParsedKeys(t *testing.T) {
	conf := parseConfiguration(t)
	tst := NewIssuerIdentifier("test.test")
	ru := NewIssuerIdentifier("irma-demo.RU")

	ring, err := NewPrivateKeyRingFolder(copyPrivateKeysFolder(t), conf)
	require.NoError(t, err)

	latest1, err := ring.Latest(tst)
	require.NoError(t, err)
	latest2, err := ring.Latest(tst)
	require.NoError(t, err)
	require.Equal(t, uint(4), latest1.Counter)
	require.Same(t, latest1, latest2)

	// Get and Latest read the same file, so they should return the same parsed key.
	get4, err := ring.Get(tst, 4)
	require.NoError(t, err)
	require.Same(t, latest1, get4)

	// Key without counter in its filename (test.test.xml has counter 3).
	get3a, err := ring.Get(tst, 3)
	require.NoError(t, err)
	get3b, err := ring.Get(tst, 3)
	require.NoError(t, err)
	require.Equal(t, uint(3), get3a.Counter)
	require.Same(t, get3a, get3b)

	ru1, err := ring.Get(ru, 2)
	require.NoError(t, err)
	ru2, err := ring.Get(ru, 2)
	require.NoError(t, err)
	require.Same(t, ru1, ru2)
}

func TestPrivateKeyRingFolderReloadsModifiedKey(t *testing.T) {
	conf := parseConfiguration(t)
	ru := NewIssuerIdentifier("irma-demo.RU")
	dir := copyPrivateKeysFolder(t)

	ring, err := NewPrivateKeyRingFolder(dir, conf)
	require.NoError(t, err)

	sk1, err := ring.Get(ru, 2)
	require.NoError(t, err)

	touch(t, filepath.Join(dir, "irma-demo.RU.2.xml"), time.Now().Add(time.Hour))

	sk2, err := ring.Get(ru, 2)
	require.NoError(t, err)
	require.NotSame(t, sk1, sk2, "modified key file should be parsed again")
	require.Equal(t, 0, sk1.P.Cmp(sk2.P))
}

func TestPrivateKeyRingFolderRejectsKeyReplacedByInvalidFile(t *testing.T) {
	conf := parseConfiguration(t)
	ru := NewIssuerIdentifier("irma-demo.RU")
	dir := copyPrivateKeysFolder(t)

	ring, err := NewPrivateKeyRingFolder(dir, conf)
	require.NoError(t, err)
	_, err = ring.Get(ru, 2)
	require.NoError(t, err)

	file := filepath.Join(dir, "irma-demo.RU.2.xml")
	require.NoError(t, os.WriteFile(file, []byte("not a private key"), 0600))
	touch(t, file, time.Now().Add(time.Hour))

	_, err = ring.Get(ru, 2)
	require.Error(t, err, "a cached key must not hide that the file on disk became invalid")
}

func TestPrivateKeyRingFolderRemovedKey(t *testing.T) {
	conf := parseConfiguration(t)
	ru := NewIssuerIdentifier("irma-demo.RU")
	dir := copyPrivateKeysFolder(t)

	ring, err := NewPrivateKeyRingFolder(dir, conf)
	require.NoError(t, err)
	_, err = ring.Get(ru, 2)
	require.NoError(t, err)

	require.NoError(t, os.Remove(filepath.Join(dir, "irma-demo.RU.2.xml")))

	_, err = ring.Get(ru, 2)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = ring.Latest(ru)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestPrivateKeyRingFolderPicksUpAddedKey(t *testing.T) {
	conf := parseConfiguration(t)
	tst := NewIssuerIdentifier("test.test")
	dir := copyPrivateKeysFolder(t, "test.test.xml")

	ring, err := NewPrivateKeyRingFolder(dir, conf)
	require.NoError(t, err)

	sk, err := ring.Latest(tst)
	require.NoError(t, err)
	require.Equal(t, uint(3), sk.Counter)

	copyPrivateKeyFile(t, filepath.Join(test.FindTestdataFolder(t), "privatekeys"), dir, "test.test.4.xml")

	sk, err = ring.Latest(tst)
	require.NoError(t, err)
	require.Equal(t, uint(4), sk.Counter)
}

func TestPrivateKeyRingFolderConcurrentAccess(t *testing.T) {
	conf := parseConfiguration(t)
	tst := NewIssuerIdentifier("test.test")

	ring, err := NewPrivateKeyRingFolder(copyPrivateKeysFolder(t), conf)
	require.NoError(t, err)
	expected, err := ring.Latest(tst)
	require.NoError(t, err)

	const n = 50
	results := make([]*gabikeys.PrivateKey, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				results[i], errs[i] = ring.Latest(tst)
			} else {
				results[i], errs[i] = ring.Get(tst, 4)
			}
		}(i)
	}
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i])
		require.Same(t, expected, results[i])
	}
}
