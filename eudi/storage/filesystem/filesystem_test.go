package filesystem

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/mocks"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// --- Helpers ---

func newTestStorage(t *testing.T) (*FileSystemContainer, string) {
	t.Helper()
	basePath := t.TempDir()
	storageMiddleware := NewStorageMiddleware(&mocks.MockEncryptionMiddleware{})
	return newFileSystemContainer(storageMiddleware, basePath), basePath
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

type failingEncryptionMiddleware struct{}

func (m *failingEncryptionMiddleware) Encrypt(_ []byte) ([]byte, error) {
	return nil, fmt.Errorf("encryption failed")
}

func (m *failingEncryptionMiddleware) Decrypt(_ []byte) ([]byte, error) {
	return nil, fmt.Errorf("decryption failed")
}

// --- fsStorage tests ---

func TestFsStorage_WriteAndReadFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStorageMiddleware(&mocks.MockEncryptionMiddleware{})

	data := []byte("hello filesystem")
	filePath := filepath.Join(dir, "test.bin")

	require.NoError(t, s.writeFile(filePath, data))

	got, err := s.readFile(filePath)
	require.NoError(t, err)
	require.Equal(t, data, got)
}

func TestFsStorage_WriteFile_EncryptionError(t *testing.T) {
	dir := t.TempDir()
	s := NewStorageMiddleware(&failingEncryptionMiddleware{})

	err := s.writeFile(filepath.Join(dir, "test.bin"), []byte("data"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "encryption failed")
}

func TestFsStorage_ReadFile_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	s := NewStorageMiddleware(&mocks.MockEncryptionMiddleware{})

	_, err := s.readFile(filepath.Join(dir, "nonexistent.bin"))
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist))
}

func TestFsStorage_ReadFile_DecryptionError(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("data"), 0644))

	s := NewStorageMiddleware(&failingEncryptionMiddleware{})
	_, err := s.readFile(filePath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decryption failed")
}

// --- NewFileSystemStorage tests ---

func TestNewFileSystemStorage_CreatesSubDirectories(t *testing.T) {
	basePath := t.TempDir()
	storage := newFileSystemContainer(NewStorageMiddleware(&mocks.MockEncryptionMiddleware{}), basePath)
	require.NotNil(t, storage)

	require.DirExists(t, filepath.Join(basePath, certificatesDirName))
	require.DirExists(t, filepath.Join(basePath, logosDirName))
	require.DirExists(t, filepath.Join(basePath, crlsDirName))
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

	require.NoError(t, storage.CertificateManager().InstallCertificate(certsToPem(rootCert, caCerts[0])))
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

func TestLogoManager_SaveLogo_ValidData(t *testing.T) {
	storage, _ := newTestStorage(t)

	savedPath, err := storage.LogoManager().SaveLogo("test-logo", []byte("logo data"))
	require.NoError(t, err)
	require.NotEmpty(t, savedPath)
	require.FileExists(t, savedPath)
}

func TestLogoManager_SaveLogo_EmptyData(t *testing.T) {
	storage, _ := newTestStorage(t)

	_, err := storage.LogoManager().SaveLogo("test-logo", []byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "data cannot be nil or empty")
}

func TestLogoManager_SaveLogo_NilData(t *testing.T) {
	storage, _ := newTestStorage(t)

	_, err := storage.LogoManager().SaveLogo("test-logo", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "data cannot be nil or empty")
}

func TestLogoManager_GetLogo_ExistingFile(t *testing.T) {
	storage, _ := newTestStorage(t)
	originalData := []byte("logo content")

	savedPath, err := storage.LogoManager().SaveLogo("mylogo", originalData)
	require.NoError(t, err)

	readData, err := storage.LogoManager().GetLogo(filepath.Base(savedPath))
	require.NoError(t, err)
	expected := base64.StdEncoding.EncodeToString(originalData)
	require.Equal(t, &expected, readData)
}

func TestLogoManager_GetLogo_NonExistingFile(t *testing.T) {
	storage, _ := newTestStorage(t)

	_, err := storage.LogoManager().GetLogo("nonexistent.png")
	require.Error(t, err)
}

func TestLogoManager_SaveLogo_OverwritesExisting(t *testing.T) {
	storage, _ := newTestStorage(t)

	savedPath, err := storage.LogoManager().SaveLogo("mylogo", []byte("original"))
	require.NoError(t, err)

	_, err = storage.LogoManager().SaveLogo("mylogo", []byte("updated"))
	require.NoError(t, err)

	readData, err := storage.LogoManager().GetLogo(filepath.Base(savedPath))
	require.NoError(t, err)
	expected := base64.StdEncoding.EncodeToString([]byte("updated"))
	require.Equal(t, &expected, readData)
}

// --- CertificateRevocationListManager tests ---

func newTestCrl(t *testing.T) *x509.RevocationList {
	t.Helper()
	_, _, _, _, crls := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT"), 1, testdata.PkiOption_None, nil)
	return crls[0]
}

func TestCrlManager_CrlExists_NonExistingFile(t *testing.T) {
	storage, _ := newTestStorage(t)

	present, err := storage.CertificateRevocationListManager().CrlExists("nonexistent.crl")
	require.NoError(t, err)
	require.False(t, present)
}

func TestCrlManager_CrlExists_ExistingFile(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, "test.crl"))

	present, err := storage.CertificateRevocationListManager().CrlExists("test.crl")
	require.NoError(t, err)
	require.True(t, present)
}

func TestCrlManager_Save_ValidCrl(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, "test.crl"))
}

func TestCrlManager_Save_NilCrl(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.CertificateRevocationListManager().Save(nil, "test.crl")
	require.Error(t, err)
	require.Contains(t, err.Error(), "crl cannot be nil")
}

func TestCrlManager_Save_MissingCrlExtension(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)

	err := storage.CertificateRevocationListManager().Save(crl, "test.txt")
	require.Error(t, err)
	require.Contains(t, err.Error(), ".crl extension")
}

func TestCrlManager_ReadFromFileName_ExistingCrl(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, "test.crl"))

	readCrl, err := storage.CertificateRevocationListManager().ReadFromFileName("test.crl")
	require.NoError(t, err)
	require.NotNil(t, readCrl)
	require.Equal(t, crl.Number, readCrl.Number)
}

func TestCrlManager_ReadFromFileName_NonExistingFile(t *testing.T) {
	storage, _ := newTestStorage(t)

	_, err := storage.CertificateRevocationListManager().ReadFromFileName("nonexistent.crl")
	require.Error(t, err)
}

func TestCrlManager_ReadFromFileName_InvalidContent(t *testing.T) {
	storage, basePath := newTestStorage(t)
	crlPath := filepath.Join(basePath, crlsDirName, "invalid.crl")
	require.NoError(t, os.WriteFile(crlPath, []byte("this is not a valid crl"), 0644))

	_, err := storage.CertificateRevocationListManager().ReadFromFileName("invalid.crl")
	require.Error(t, err)
}

func TestCrlManager_Remove_ExistingFile(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, "test.crl"))
	require.NoError(t, storage.CertificateRevocationListManager().RemoveByFileName("test.crl"))

	present, err := storage.CertificateRevocationListManager().CrlExists("test.crl")
	require.NoError(t, err)
	require.False(t, present)
}

func TestCrlManager_Remove_NonExistingFile(t *testing.T) {
	storage, _ := newTestStorage(t)

	err := storage.CertificateRevocationListManager().RemoveByFileName("nonexistent.crl")
	require.Error(t, err)
}

func TestCrlManager_GetAllFileNames_Empty(t *testing.T) {
	storage, _ := newTestStorage(t)

	names, err := storage.CertificateRevocationListManager().GetAllFileNames()
	require.NoError(t, err)
	require.Empty(t, names)
}

func TestCrlManager_GetAllFileNames_ReturnsBaseNamesOnly(t *testing.T) {
	storage, _ := newTestStorage(t)
	crl := newTestCrl(t)

	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, "first.crl"))
	require.NoError(t, storage.CertificateRevocationListManager().Save(crl, "second.crl"))

	names, err := storage.CertificateRevocationListManager().GetAllFileNames()
	require.NoError(t, err)
	require.Len(t, names, 2)
	require.Contains(t, names, "first.crl")
	require.Contains(t, names, "second.crl")
}

func TestGetCrlFileNameForCertDistributionPoint_IsDeterministic(t *testing.T) {
	dp := "https://yivi.app/crl.crl"

	name1 := GetCrlFileNameForCertDistributionPoint(dp)
	name2 := GetCrlFileNameForCertDistributionPoint(dp)

	require.Equal(t, name1, name2)
	require.Contains(t, name1, ".crl")
}

func TestGetCrlFileNameForCertDistributionPoint_DifferentInputsDifferentNames(t *testing.T) {
	name1 := GetCrlFileNameForCertDistributionPoint("https://yivi.app/crl1.crl")
	name2 := GetCrlFileNameForCertDistributionPoint("https://yivi.app/crl2.crl")

	require.NotEqual(t, name1, name2)
}
