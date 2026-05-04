package filesystem

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// frozenAESKey is the fixed AES storage key the frozen-vector tests below pin
// against. Changing this value invalidates every expected hex string in this
// file; do not change it without intentionally regenerating the vectors.
var frozenAESKey = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// frozenFSStorage returns a FileSystemStorage built with the frozen AES key.
func frozenFSStorage(t *testing.T) FileSystemStorage {
	t.Helper()
	return NewFileSystemStorage(frozenAESKey, t.TempDir())
}

// frozenLogoScope returns the scopedFS bound to the credentials/logos
// directory of a freshly-built FileSystemStorage with the frozen AES key.
// It exists so the tests below share one wiring.
func frozenLogoScope(t *testing.T) *scopedFS {
	t.Helper()
	fs := frozenFSStorage(t).(*fileSystemStorage)
	return fs.credentialsContainer.logoManager.(*logoManager).scope
}

// frozenVectorInputs is the canonical input set for the frozen-vector
// regression test. It is also the input set the regen helper iterates over,
// so the two stay in sync by construction.
var frozenVectorInputs = []string{
	"",
	"https://example.org/a.png",
	"https://example.org/b.png",
	"https://yivi.app/crl.crl",
}

// TestScopedFS_FrozenVectors locks the on-disk filename construction to a
// specific AES-derived key and a specific HMAC-SHA256 keyed-hash. Any change
// to the HKDF info string, the HMAC layout, the hash function, or the hex
// encoding will fail this test and must be reflected in updated vectors.
//
// To regenerate after a deliberate construction change, run:
//
//	IRMAGO_REGEN_FS_TEST_VECTORS=1 go test ./eudi/storage/filesystem -run TestScopedFS_RegenerateFrozenVectors -v
//
// then copy the printed literals into the cases slice below.
func TestScopedFS_FrozenVectors(t *testing.T) {
	scope := frozenLogoScope(t)

	expected := map[string]string{
		"":                          "a93bf766ae99efa4686bd5dc424b4925ee95c378aff3e7ca9e98cab6198c3c00",
		"https://example.org/a.png": "b8528a16a1667b9533f8418755d9c201f82146a870bf37e5f177b0265d0f027b",
		"https://example.org/b.png": "8ffcbec7e4568cd8ceeaae74792d00f765a9e6fb5fd67038477c155fe156f836",
		"https://yivi.app/crl.crl":  "5af1206ef9a2183e70b18882114db8cb31de478990199acac7e6a661b66f14ff",
	}

	for _, input := range frozenVectorInputs {
		require.Equal(t, expected[input], scope.hashName(input),
			"frozen vector regression for input %q — if this change is intentional, regenerate vectors via IRMAGO_REGEN_FS_TEST_VECTORS=1 and update the literals", input)
	}
}

// TestScopedFS_RegenerateFrozenVectors prints fresh expected vectors for the
// frozen AES key and the canonical input set. It is gated behind the
// IRMAGO_REGEN_FS_TEST_VECTORS env var so it never runs in CI; the only
// reason to invoke it is when bumping the HKDF info string or otherwise
// intentionally changing the on-disk filename construction.
func TestScopedFS_RegenerateFrozenVectors(t *testing.T) {
	if os.Getenv("IRMAGO_REGEN_FS_TEST_VECTORS") == "" {
		t.Skip("set IRMAGO_REGEN_FS_TEST_VECTORS=1 to regenerate frozen vectors")
	}
	scope := frozenLogoScope(t)
	t.Log("Copy the lines below into the expected map in TestScopedFS_FrozenVectors:")
	for _, input := range frozenVectorInputs {
		t.Logf("  %q: %q,", input, scope.hashName(input))
	}
}

// TestScopedFS_HashIsDeterministic verifies the same logical name always
// produces the same hex output across calls.
func TestScopedFS_HashIsDeterministic(t *testing.T) {
	scope := frozenLogoScope(t)
	const input = "https://example.org/logo.png"

	require.Equal(t, scope.hashName(input), scope.hashName(input))
}

// TestScopedFS_HashOutputIsLowercaseHex64 verifies the on-disk filename has
// the expected length and character class regardless of input.
func TestScopedFS_HashOutputIsLowercaseHex64(t *testing.T) {
	scope := frozenLogoScope(t)

	for _, input := range []string{"", "x", "https://yivi.app/", "ünîc☃de"} {
		got := scope.hashName(input)
		require.Len(t, got, 64, "expected 64-char hex for input %q, got %q", input, got)
		decoded, err := hex.DecodeString(got)
		require.NoError(t, err, "expected valid hex for input %q, got %q", input, got)
		require.Equal(t, got, fmt.Sprintf("%x", decoded), "expected lowercase hex")
	}
}

// TestScopedFS_SaltIsApplied verifies the on-disk filename is **not** the
// plain SHA-256 of the logical name. This is the regression guard against
// accidental reverts to the unsalted construction.
func TestScopedFS_SaltIsApplied(t *testing.T) {
	scope := frozenLogoScope(t)

	const input = "https://example.org/a.png"
	plainSHA := sha256.Sum256([]byte(input))

	require.NotEqual(t, hex.EncodeToString(plainSHA[:]), scope.hashName(input),
		"on-disk filename equals plain sha256(input) — the AES-derived key is not in the loop")
}

// TestScopedFS_CrossScopeIdentity verifies that the same logical name in two
// different scopes (under the same FS) produces the same hex. Disambiguation
// between scopes lives in the directory structure on disk, not in the hash.
func TestScopedFS_CrossScopeIdentity(t *testing.T) {
	fs := frozenFSStorage(t).(*fileSystemStorage)
	credLogos := fs.credentialsContainer.logoManager.(*logoManager).scope
	issuerLogos := fs.issuersContainer.logoManager.(*logoManager).scope

	const input = "x"
	require.Equal(t, credLogos.hashName(input), issuerLogos.hashName(input),
		"hash should not depend on the scope's directory")
}

// TestScopedFS_WriteRead_RoundTrip verifies the public Write/Read pair
// round-trips data through the encrypted, hashed-filename layer.
func TestScopedFS_WriteRead_RoundTrip(t *testing.T) {
	scope := frozenLogoScope(t)

	data := []byte("logo bytes")
	require.NoError(t, scope.Write("https://example.org/a.png", "", data))

	got, err := scope.Read("https://example.org/a.png", "")
	require.NoError(t, err)
	require.Equal(t, data, got)
}

// TestScopedFS_OnDiskBytesAreEncrypted verifies that what lands on disk is not
// the plaintext data — i.e. the encryption middleware is in the loop.
func TestScopedFS_OnDiskBytesAreEncrypted(t *testing.T) {
	scope := frozenLogoScope(t)

	plaintext := []byte("the quick brown fox")
	require.NoError(t, scope.Write("k", "", plaintext))

	rawPath := filepath.Join(scope.fullPath, scope.hashName("k"))
	rawBytes, err := os.ReadFile(rawPath)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, rawBytes, "on-disk bytes should be encrypted, not plaintext")
}

// TestScopedFS_ReadGarbledFile_FailsWithDecryptError verifies that reading a
// file that wasn't written through the FS layer surfaces a decryption error
// rather than returning garbage.
func TestScopedFS_ReadGarbledFile_FailsWithDecryptError(t *testing.T) {
	scope := frozenLogoScope(t)

	rawPath := filepath.Join(scope.fullPath, scope.hashName("k"))
	require.NoError(t, os.WriteFile(rawPath, []byte("not actually ciphertext"), 0644))

	_, err := scope.Read("k", "")
	require.Error(t, err)
}

// TestScopedFS_ReadMissing_ReturnsNotExist verifies the read path surfaces
// os.ErrNotExist for missing entries rather than a different error.
func TestScopedFS_ReadMissing_ReturnsNotExist(t *testing.T) {
	scope := frozenLogoScope(t)

	_, err := scope.Read("never-written", "")
	require.True(t, errors.Is(err, os.ErrNotExist), "expected ErrNotExist, got %v", err)
}

// TestScopedFS_Walk_VisitsEveryWrittenEntry verifies Walk yields the plaintext
// bytes of every file written through the scope.
func TestScopedFS_Walk_VisitsEveryWrittenEntry(t *testing.T) {
	scope := frozenLogoScope(t)

	expected := map[string]bool{
		"alpha":   true,
		"beta":    true,
		"gamma":   true,
		"delta!!": true,
	}
	for k := range expected {
		require.NoError(t, scope.Write(k, "", []byte(k+"-payload")))
	}

	seen := map[string]bool{}
	err := scope.Walk(func(data []byte) error {
		s := string(data)
		require.True(t, len(s) > len("-payload"))
		seen[s[:len(s)-len("-payload")]] = true
		return nil
	}, nil)
	require.NoError(t, err)
	require.Equal(t, expected, seen)
}

// TestScopedFS_Walk_OnErrorContinues verifies that when onError is non-nil,
// per-file failures are surfaced via the callback and iteration continues.
func TestScopedFS_Walk_OnErrorContinues(t *testing.T) {
	scope := frozenLogoScope(t)

	require.NoError(t, scope.Write("good", "", []byte("good-payload")))

	garbledPath := filepath.Join(scope.fullPath, scope.hashName("bad"))
	require.NoError(t, os.WriteFile(garbledPath, []byte("not ciphertext"), 0644))

	var errSeen []error
	var goodSeen []string
	err := scope.Walk(func(data []byte) error {
		goodSeen = append(goodSeen, string(data))
		return nil
	}, func(e error) {
		errSeen = append(errSeen, e)
	})
	require.NoError(t, err)
	require.Equal(t, []string{"good-payload"}, goodSeen)
	require.Len(t, errSeen, 1)
}

// TestScopedFS_Walk_OnErrorNilStopsAtFirstFailure verifies that when onError
// is nil, the first per-file failure aborts the walk.
func TestScopedFS_Walk_OnErrorNilStopsAtFirstFailure(t *testing.T) {
	scope := frozenLogoScope(t)

	garbledPath := filepath.Join(scope.fullPath, scope.hashName("bad"))
	require.NoError(t, os.WriteFile(garbledPath, []byte("not ciphertext"), 0644))

	err := scope.Walk(func(data []byte) error {
		return nil
	}, nil)
	require.Error(t, err)
}

// TestScopedFS_DeleteThenExists verifies the existence/delete pair behaves on
// the logical-key axis.
func TestScopedFS_DeleteThenExists(t *testing.T) {
	scope := frozenLogoScope(t)

	require.NoError(t, scope.Write("k", "", []byte("v")))
	exists, err := scope.Exists("k", "")
	require.NoError(t, err)
	require.True(t, exists)

	require.NoError(t, scope.Delete("k", ""))
	exists, err = scope.Exists("k", "")
	require.NoError(t, err)
	require.False(t, exists)
}

// TestScopedFS_ExtensionAppendedAfterHash verifies that an extension passed to
// Write lands on disk after the hex hash, and that Read with the same
// extension finds it. Read with a different extension must not find it.
func TestScopedFS_ExtensionAppendedAfterHash(t *testing.T) {
	scope := frozenLogoScope(t)

	require.NoError(t, scope.Write("https://yivi.app/crl.crl", ".crl", []byte("crl bytes")))

	expectedFilename := scope.hashName("https://yivi.app/crl.crl") + ".crl"
	require.FileExists(t, filepath.Join(scope.fullPath, expectedFilename))

	got, err := scope.Read("https://yivi.app/crl.crl", ".crl")
	require.NoError(t, err)
	require.Equal(t, []byte("crl bytes"), got)

	_, err = scope.Read("https://yivi.app/crl.crl", "")
	require.Error(t, err, "extension is part of the on-disk identity; reading without it must miss")
}
