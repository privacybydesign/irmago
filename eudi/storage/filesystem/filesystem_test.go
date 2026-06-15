package filesystem

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// --- Helpers ---

// newTestStorage builds a FileSystemContainer wired through real AES-GCM with a
// zero key. Tests round-trip data through the encrypted layer; they don't
// inspect raw on-disk bytes.
func newTestStorage(t *testing.T) (*FileSystemContainer, string) {
	t.Helper()
	basePath := t.TempDir()
	fs := NewFileSystemStorage([32]byte{}, basePath)
	container := fs.Credentials()
	return &container, filepath.Join(basePath, "credentials")
}

func certsToPem(certs ...*x509.Certificate) []byte {
	var result []byte
	for _, cert := range certs {
		result = append(result, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	return result
}

// --- NewFileSystemStorage tests ---

func TestNewFileSystemStorage_CreatesSubDirectories(t *testing.T) {
	basePath := t.TempDir()
	fs := NewFileSystemStorage([32]byte{}, basePath)
	require.NotNil(t, fs)

	for _, container := range []string{"credentials", "issuers", "verifiers"} {
		require.DirExists(t, filepath.Join(basePath, container, certificatesDirName))
		require.DirExists(t, filepath.Join(basePath, container, logosDirName))
		require.DirExists(t, filepath.Join(basePath, container, crlsDirName))
	}
}

func TestNewFileSystemStorage_ExposesAllManagers(t *testing.T) {
	storage, _ := newTestStorage(t)
	require.NotNil(t, storage.CertificateManager())
	require.NotNil(t, storage.CertificateRevocationListManager())
	require.NotNil(t, storage.LogoManager())
}

// --- CertificateManager tests ---

func TestCertificateManager_InstallCertificate_SingleCert(t *testing.T) {
	storage, _ := newTestStorage(t)
	_, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("ROOT"), testdata.PkiOption_None)

	require.NoError(t, storage.CertificateManager().InstallCertificate(certsToPem(rootCert)))
}

func TestCertificateManager_InstallCertificate_CertChain(t *testing.T) {
	storage, _ := newTestStorage(t)
	_, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT"), 1, testdata.PkiOption_None, nil)

	require.NoError(t, storage.CertificateManager().InstallCertificate(certsToPem(caCerts[0], rootCert)))
}

func TestCertificateManager_InstallCertificate_InvalidPem(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.CertificateManager().InstallCertificate([]byte("not valid pem data"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "no certificates found")
}

func TestCertificateManager_InstallCertificate_EmptyData(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.CertificateManager().InstallCertificate([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no certificates found")
}

func TestCertificateManager_GetRawCertificates_Empty(t *testing.T) {
	storage, _ := newTestStorage(t)

	certs, err := storage.CertificateManager().GetRawCertificates()
	require.NoError(t, err)
	require.Empty(t, certs)
}

func TestCertificateManager_GetRawCertificates_ReturnsAllInstalled(t *testing.T) {
	storage, _ := newTestStorage(t)
	_, cert1 := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("ROOT 1"), testdata.PkiOption_None)
	_, cert2 := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("ROOT 2"), testdata.PkiOption_None)

	require.NoError(t, storage.CertificateManager().InstallCertificate(certsToPem(cert1)))
	require.NoError(t, storage.CertificateManager().InstallCertificate(certsToPem(cert2)))

	certs, err := storage.CertificateManager().GetRawCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 2)
}

func TestCertificateManager_InstallCertificate_SharedRootDoesNotOverwrite(t *testing.T) {
	// Two chains share the same root but have different CA leaves. The filename is
	// derived from the leaf cert's signature, so both chains must be stored as
	// separate files and neither overwrites the other.
	storage, _ := newTestStorage(t)
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("SHARED ROOT"), testdata.PkiOption_None)
	_, caCert1, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("CA 1"), rootCert, rootKey, testdata.PkiOption_None, nil)
	_, caCert2, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("CA 2"), rootCert, rootKey, testdata.PkiOption_None, nil)

	require.NoError(t, storage.CertificateManager().InstallCertificate(certsToPem(caCert1, rootCert)))
	require.NoError(t, storage.CertificateManager().InstallCertificate(certsToPem(caCert2, rootCert)))

	certs, err := storage.CertificateManager().GetRawCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 2)
}

func TestCertificateManager_InstallCertificate_Idempotent(t *testing.T) {
	// Installing the same certificate twice must not create duplicate files
	storage, _ := newTestStorage(t)
	_, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("ROOT"), testdata.PkiOption_None)
	pemData := certsToPem(rootCert)

	require.NoError(t, storage.CertificateManager().InstallCertificate(pemData))
	require.NoError(t, storage.CertificateManager().InstallCertificate(pemData))

	certs, err := storage.CertificateManager().GetRawCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

// --- LogoManager tests ---

func TestLogoManager_Save_ValidData(t *testing.T) {
	storage, _ := newTestStorage(t)

	require.NoError(t, storage.LogoManager().Save("https://example.org/a.png", []byte("logo data")))
}

func TestLogoManager_Save_EmptyData(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.LogoManager().Save("https://example.org/a.png", []byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "data cannot be nil or empty")
}

func TestLogoManager_Save_NilData(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.LogoManager().Save("https://example.org/a.png", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "data cannot be nil or empty")
}

func TestLogoManager_Save_EmptyKey(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.LogoManager().Save("", []byte("logo data"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "key cannot be empty")
}

func TestLogoManager_Get_RoundTrip(t *testing.T) {
	storage, _ := newTestStorage(t)
	originalData := []byte("logo content")

	require.NoError(t, storage.LogoManager().Save("mylogo", originalData))

	readData, err := storage.LogoManager().Get("mylogo")
	require.NoError(t, err)
	require.Equal(t, originalData, readData)
}

func TestLogoManager_Get_MissingKey(t *testing.T) {
	storage, _ := newTestStorage(t)

	_, err := storage.LogoManager().Get("nonexistent")
	require.Error(t, err)
}

func TestLogoManager_Save_Overwrites(t *testing.T) {
	storage, _ := newTestStorage(t)

	require.NoError(t, storage.LogoManager().Save("mylogo", []byte("original")))
	require.NoError(t, storage.LogoManager().Save("mylogo", []byte("updated")))

	readData, err := storage.LogoManager().Get("mylogo")
	require.NoError(t, err)
	require.Equal(t, []byte("updated"), readData)
}

func TestLogoManager_Exists(t *testing.T) {
	storage, _ := newTestStorage(t)

	exists, err := storage.LogoManager().Exists("k")
	require.NoError(t, err)
	require.False(t, exists)

	require.NoError(t, storage.LogoManager().Save("k", []byte("v")))
	exists, err = storage.LogoManager().Exists("k")
	require.NoError(t, err)
	require.True(t, exists)
}

// --- CertificateRevocationListManager tests ---

func newTestCrl(t *testing.T) *x509.RevocationList {
	t.Helper()
	_, _, _, _, crls := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT"), 1, testdata.PkiOption_None, nil)
	return crls[0]
}

func TestCrlManager_Exists_NonExistingDistPoint(t *testing.T) {
	storage, _ := newTestStorage(t)

	present, err := storage.CertificateRevocationListManager().Exists("https://example.org/missing.crl")
	require.NoError(t, err)
	require.False(t, present)
}

func TestCrlManager_Exists_AfterSave(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)
	const distPoint = "https://example.org/test.crl"

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, distPoint))

	present, err := storage.CertificateRevocationListManager().Exists(distPoint)
	require.NoError(t, err)
	require.True(t, present)
}

func TestCrlManager_Save_NilCrl(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.CertificateRevocationListManager().Save(nil, "https://example.org/x.crl")
	require.Error(t, err)
	require.Contains(t, err.Error(), "crl cannot be nil")
}

func TestCrlManager_Read_RoundTrip(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)
	const distPoint = "https://example.org/test.crl"

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, distPoint))

	readCrl, err := storage.CertificateRevocationListManager().Read(distPoint)
	require.NoError(t, err)
	require.NotNil(t, readCrl)
	require.Equal(t, crl.Number, readCrl.Number)
}

func TestCrlManager_Read_NonExistingDistPoint(t *testing.T) {
	storage, _ := newTestStorage(t)

	_, err := storage.CertificateRevocationListManager().Read("https://example.org/missing.crl")
	require.Error(t, err)
}

func TestCrlManager_Remove_AfterSave(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)
	const distPoint = "https://example.org/test.crl"

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, distPoint))
	require.NoError(t, storage.CertificateRevocationListManager().Remove(distPoint))

	present, err := storage.CertificateRevocationListManager().Exists(distPoint)
	require.NoError(t, err)
	require.False(t, present)
}

func TestCrlManager_Remove_NonExisting(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.CertificateRevocationListManager().Remove("https://example.org/missing.crl")
	require.Error(t, err)
}

func TestCrlManager_LoadAll_Empty(t *testing.T) {
	storage, _ := newTestStorage(t)

	crls, err := storage.CertificateRevocationListManager().LoadAll(nil)
	require.NoError(t, err)
	require.Empty(t, crls)
}

func TestCrlManager_LoadAll_ReturnsAllSavedCrls(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)
	mgr := storage.CertificateRevocationListManager()

	require.NoError(t, mgr.Save(crl, "https://example.org/first.crl"))
	require.NoError(t, mgr.Save(crl, "https://example.org/second.crl"))

	crls, err := mgr.LoadAll(nil)
	require.NoError(t, err)
	require.Len(t, crls, 2)
}

func TestCrlManager_LoadAll_OnErrorContinuesPastBadFile(t *testing.T) {
	storage, basePath := newTestStorage(t)
	crl := newTestCrl(t)
	mgr := storage.CertificateRevocationListManager()

	require.NoError(t, mgr.Save(crl, "https://example.org/good.crl"))

	// Drop a file in the CRL dir that won't decrypt — simulates corruption.
	require.NoError(t, os.WriteFile(filepath.Join(basePath, crlsDirName, "garbage.crl"), []byte("not ciphertext"), 0644))

	var errs []error
	crls, err := mgr.LoadAll(func(loadErr error) {
		errs = append(errs, loadErr)
	})
	require.NoError(t, err)
	require.Len(t, crls, 1)
	require.Len(t, errs, 1)
}

// TestCrlManager_LoadAll_OnErrorSurfacesParseFailures verifies that a file
// which decrypts cleanly but does not parse as a CRL reaches onError via the
// fn-returns-error path of Walk, and that iteration continues.
func TestCrlManager_LoadAll_OnErrorSurfacesParseFailures(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)
	mgr := storage.CertificateRevocationListManager()

	require.NoError(t, mgr.Save(crl, "https://example.org/good.crl"))

	// Write a payload through the same scope so it round-trips through AES-GCM
	// but fails x509.ParseRevocationList — exercises the fn-returns-error path
	// of Walk, distinct from the decrypt-failure path covered above.
	mgrImpl := mgr.(*certificateRevocationListManager)
	require.NoError(t, mgrImpl.scope.Write("https://example.org/notacrl", crlExtension, []byte("decrypts but not a crl")))

	var errs []error
	crls, err := mgr.LoadAll(func(loadErr error) {
		errs = append(errs, loadErr)
	})
	require.NoError(t, err)
	require.Len(t, crls, 1)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "parse crl")
}
