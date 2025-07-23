package eudi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	mathRand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	// NewConfiguration tests
	t.Run("NewConfiguration creates required directories and initializes successfully", testNewConfigurationSuccessfulInitialization)

	// // ParseFolder tests
	// t.Run("ParseFolder reads issuer and verifier trustmodels", testParseFolderReadsIssuerAndVerifierTrustModels)

	// readTrustModel tests
	t.Run("readTrustModel reads single certificate chain (root-only, no crl) successfully", testReadTrustModelReadsSingleCertificateChainRootOnlyNoCrlSuccessfully)
	t.Run("readTrustModel reads single certificate chain (root-only + crl) successfully", testReadTrustModelReadsSingleCertificateChainRootOnlyWithCrlSuccessfully)
	t.Run("readTrustModel reads multiple certificate chains (root-only + crls) successfully", testReadTrustModelReadsMultipleCertificateChainsWithCrlsRootOnlySuccessfully)
	t.Run("readTrustModel reads certificate chain (root + single sub-CA + crl) successfully", testReadTrustModelReadsSingleCertificateChainRootWithSingleSubCaAndCrlsSuccessfully)
	t.Run("readTrustModel reads certificate chains (root with multiple sub-CAs + crls) successfully", testReadTrustModelReadsMultipleCertificateChainRootWithMultipleSubCAsAndCrlsSuccessfully)
	t.Run("readTrustModel reads certificate chain (root with multi level sub-CA + crls) successfully", testReadTrustModelReadsMultipleCertificateChainRootWithMultiLevelSubCaAndCrlsSuccessfully)

	// TODO:
	// t.Run("readTrustModel reads invalid certificate chain file, should .....", )
	// t.Run("readTrustModel reads invalid certificate chain (valid root + revoked sub-CA), should .....", )
	// t.Run("readTrustModel reads invalid certificate chain (expired root + valid single sub-CA), should .....", )
	// t.Run("readTrustModel reads invalid certificate chain (valid root + expired single sub-CA), should .....", )
	// t.Run("readTrustModel reads invalid certificate chain (root + single sub-CA in reversed order in file), should .....", )

	// // readRevocationLists tests
	// t.Run("readRevocationLists reads invalid revocation list, should .....", )

	// GetRevocationListsForIssuer tests
	t.Run("GetRevocationListsForIssuer returns correct CRLs", testTrustModelGetRevocationListsForIssuerReturnsCorrectCRLs)

	// VerifyRevocationListSignatures tests
	t.Run("verifyRevocationListSignatures returns no error on valid signatures", testTrustModelVerifyRevocationListSignaturesReturnsNoErrorOnValidSignatures)
	t.Run("verifyRevocationListSignatures returns nil on no revocation lists", testTrustModelVerifyRevocationListSignaturesReturnsNilOnNoRevocationLists)

	// // Logo cache tests
	// t.Run("CacheVerifierLogo caches logo successfully", testCacheVerifierLogoCachesLogoSuccessfully)
	// t.Run("CacheVerifierLogo caches logo multiple times successfully", testCacheVerifierLogoCachesLogoMultipleTimesSuccessfully)
	// t.Run("CacheVerifierLogo returns error on nil logo", testCacheVerifierLogoReturnsErrorOnNilLogo)
	// t.Run("CacheVerifierLogo returns error on empty logo data", testCacheVerifierLogoReturnsErrorOnEmptyLogoData)
	// t.Run("CacheVerifierLogo returns error on unknown mime type", testCacheVerifierLogoReturnsErrorOnUnknownMimeType)

}

func testNewConfigurationSuccessfulInitialization(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	err := common.EnsureDirectoryExists(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	require.NoDirExists(t, filepath.Join(storageFolder, "eudi_configuration", "issuers"))
	require.NoDirExists(t, filepath.Join(storageFolder, "eudi_configuration", "verifiers"))

	conf, err := NewConfiguration(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)
	require.NotNil(t, conf)
	require.DirExists(t, conf.Issuers.GetCertificatePath())
	require.DirExists(t, conf.Issuers.GetCrlPath())
	require.DirExists(t, conf.Issuers.GetLogosPath())
	require.DirExists(t, conf.Verifiers.GetCertificatePath())
	require.DirExists(t, conf.Verifiers.GetCrlPath())
	require.DirExists(t, conf.Verifiers.GetLogosPath())

	require.NotNil(t, conf.Issuers.rootPool)
	require.NotNil(t, conf.Issuers.intermediatePool)
	require.NotNil(t, conf.Issuers.revocationLists)
	require.Len(t, conf.Issuers.revocationLists, 0)
	require.NotNil(t, conf.Verifiers.rootPool)
	require.NotNil(t, conf.Verifiers.intermediatePool)
	require.NotNil(t, conf.Verifiers.revocationLists)
	require.Len(t, conf.Verifiers.revocationLists, 0)
}

func testReadTrustModelReadsSingleCertificateChainRootOnlyNoCrlSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	tm := &TrustModel{
		basePath: filepath.Join(storageFolder, "eudi_configuration", "issuers"),
	}
	tm.clear()

	err := common.EnsureDirectoryExists(tm.GetCertificatePath())
	require.NoError(t, err)

	// Create a root certificate and write it to storage
	rootDN := createDistinguishedName("ROOT CERT 1")
	_, rootCert, _ := createRootCertificate(t, rootDN)
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.rootPool.Subjects(), 1)
	require.Len(t, tm.intermediatePool.Subjects(), 0)
	require.Len(t, tm.revocationLists, 0)
}

func testReadTrustModelReadsSingleCertificateChainRootOnlyWithCrlSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	tm := &TrustModel{
		basePath: filepath.Join(storageFolder, "eudi_configuration", "issuers"),
	}
	tm.clear()

	err := common.EnsureDirectoryExists(tm.GetCertificatePath())
	require.NoError(t, err)
	err = common.EnsureDirectoryExists(tm.GetCrlPath())
	require.NoError(t, err)

	// Create a root certificate and write it to storage
	rootDN := createDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl := createRootCertificate(t, rootDN)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.rootPool.Subjects(), 1)
	require.Len(t, tm.intermediatePool.Subjects(), 0)
	require.Len(t, tm.revocationLists, 1)
}

func testReadTrustModelReadsMultipleCertificateChainsWithCrlsRootOnlySuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	tm := &TrustModel{
		basePath: filepath.Join(storageFolder, "eudi_configuration", "issuers"),
	}
	tm.clear()

	err := common.EnsureDirectoryExists(tm.GetCertificatePath())
	require.NoError(t, err)
	err = common.EnsureDirectoryExists(tm.GetCrlPath())
	require.NoError(t, err)

	// Create a root certificate and write it to storage
	rootDN := createDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl := createRootCertificate(t, rootDN)
	rootDN2 := createDistinguishedName("ROOT CERT 2")
	_, rootCert2, rootCrl2 := createRootCertificate(t, rootDN2)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert2.pem"), rootCert2)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert2.crl"), rootCrl2.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.rootPool.Subjects(), 2)
	require.Len(t, tm.intermediatePool.Subjects(), 0)
	require.Len(t, tm.revocationLists, 2)
}

func testReadTrustModelReadsSingleCertificateChainRootWithSingleSubCaAndCrlsSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	tm := &TrustModel{
		basePath: filepath.Join(storageFolder, "eudi_configuration", "issuers"),
	}
	tm.clear()

	err := common.EnsureDirectoryExists(tm.GetCertificatePath())
	require.NoError(t, err)
	err = common.EnsureDirectoryExists(tm.GetCrlPath())
	require.NoError(t, err)

	// Create a root certificate and write it to storage
	rootDN := createDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, _, caCerts, caCrls := createTestPkiHierarchy(t, rootDN, 1)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0])
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca.crl"), caCrls[0].Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.rootPool.Subjects(), 1)
	require.Len(t, tm.intermediatePool.Subjects(), 1)
	require.Len(t, tm.revocationLists, 2)
}

func testReadTrustModelReadsMultipleCertificateChainRootWithMultipleSubCAsAndCrlsSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	tm := &TrustModel{
		basePath: filepath.Join(storageFolder, "eudi_configuration", "issuers"),
	}
	tm.clear()

	err := common.EnsureDirectoryExists(tm.GetCertificatePath())
	require.NoError(t, err)
	err = common.EnsureDirectoryExists(tm.GetCrlPath())
	require.NoError(t, err)

	// Create a (root > CA1) and (root > CA2) chains and write to storage
	rootDN := createDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, _, caCerts, caCrls := createTestPkiHierarchy(t, rootDN, 2)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain1.pem"), rootCert, caCerts[0])
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain2.pem"), rootCert, caCerts[1])
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca1.crl"), caCrls[0].Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca2.crl"), caCrls[1].Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.rootPool.Subjects(), 1)
	require.Len(t, tm.intermediatePool.Subjects(), 2)
	require.Len(t, tm.revocationLists, 3)
}

func testReadTrustModelReadsMultipleCertificateChainRootWithMultiLevelSubCaAndCrlsSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	tm := &TrustModel{
		basePath: filepath.Join(storageFolder, "eudi_configuration", "issuers"),
	}
	tm.clear()

	err := common.EnsureDirectoryExists(tm.GetCertificatePath())
	require.NoError(t, err)
	err = common.EnsureDirectoryExists(tm.GetCrlPath())
	require.NoError(t, err)

	// Create a (root > CA > CA) chain and write it to storage
	rootDN := createDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, caKeys, caCerts, caCrls := createTestPkiHierarchy(t, rootDN, 1)
	_, subCaCert, subCaCrl := createCaCertificate(t, createDistinguishedName("SUB-CA CERT"), caCerts[0], caKeys[0])

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0], subCaCert)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca.crl"), caCrls[0].Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "sub-ca.crl"), subCaCrl.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.rootPool.Subjects(), 1)
	require.Len(t, tm.intermediatePool.Subjects(), 2)
	require.Len(t, tm.revocationLists, 3)
}

// PKI setup
// ROOT CERT 1
//   - CA CERT 1
//   - CA CERT 2
//
// ROOT CERT 2
//   - CA CERT 1
func testTrustModelGetRevocationListsForIssuerReturnsCorrectCRLs(t *testing.T) {
	// Setup multiple CRLs
	rootDN1 := createDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, _, caCerts, caCrls := createTestPkiHierarchy(t, rootDN1, 2)
	rootDN2 := createDistinguishedName("ROOT CERT 2")
	_, rootCert2, rootCrl2, _, _, caCrls2 := createTestPkiHierarchy(t, rootDN2, 1)

	tm := &TrustModel{
		// Add all CRLs except the one for ROOT CERT 1 > CA CERT 2
		revocationLists: []*x509.RevocationList{rootCrl, rootCrl2, caCrls[0], caCrls2[0]},
	}

	// Root certificate 1 has 1 CRL
	crls := tm.GetRevocationListsForIssuer(rootCert.SubjectKeyId, rootCert.Subject)
	require.Len(t, crls, 1)
	require.Contains(t, crls, rootCrl)

	// Root certificate 2 has 1 CRL
	crls = tm.GetRevocationListsForIssuer(rootCert2.SubjectKeyId, rootCert2.Subject)
	require.Len(t, crls, 1)
	require.Contains(t, crls, rootCrl2)

	// Root certificate 1, CA 1 has 1 CRL
	crls = tm.GetRevocationListsForIssuer(caCerts[0].SubjectKeyId, caCerts[0].Subject)
	require.Len(t, crls, 1)
	require.Contains(t, crls, caCrls[0])

	// Root certificate 1, CA 2 has no CRL
	crls = tm.GetRevocationListsForIssuer(caCerts[1].SubjectKeyId, caCerts[1].Subject)
	require.Len(t, crls, 0)
}

func testTrustModelVerifyRevocationListSignaturesReturnsNoErrorOnValidSignatures(t *testing.T) {
	rootDN1 := createDistinguishedName("ROOT CERT 1")
	_, _, rootCrl, _, caCerts, caCrls := createTestPkiHierarchy(t, rootDN1, 2)

	tm := &TrustModel{
		revocationLists: []*x509.RevocationList{rootCrl, caCrls[0], caCrls[1]},
	}

	err := tm.verifyRevocationListsSignatures(caCerts[0])
	require.NoError(t, err)
}

func testTrustModelVerifyRevocationListSignaturesReturnsNilOnNoRevocationLists(t *testing.T) {
	rootDN1 := createDistinguishedName("ROOT CERT 1")
	_, _, rootCrl, _, caCerts, _ := createTestPkiHierarchy(t, rootDN1, 2)

	tm := &TrustModel{
		revocationLists: []*x509.RevocationList{rootCrl},
	}

	err := tm.verifyRevocationListsSignatures(caCerts[0])
	require.NoError(t, err)
}

func createTestPkiHierarchy(t *testing.T, rootName pkix.Name, numberOfCAs int) (
	rootKey *ecdsa.PrivateKey,
	rootCert *x509.Certificate,
	rootCrl *x509.RevocationList,
	caKeys []*ecdsa.PrivateKey,
	caCerts []*x509.Certificate,
	caCrls []*x509.RevocationList,
) {
	rootKey, rootCert, rootCrl = createRootCertificate(t, rootName)

	caKeys = make([]*ecdsa.PrivateKey, numberOfCAs)
	caCerts = make([]*x509.Certificate, numberOfCAs)
	caCrls = make([]*x509.RevocationList, numberOfCAs)

	for i := range numberOfCAs {
		caKey, caCert, caCrl := createCaCertificate(t, createDistinguishedName("CA CERT "+strconv.Itoa(i)), rootCert, rootKey)
		caKeys[i] = caKey
		caCerts[i] = caCert
		caCrls[i] = caCrl
	}

	return
}

func createRootCertificate(t *testing.T, subject pkix.Name) (key *ecdsa.PrivateKey, cert *x509.Certificate, crl *x509.RevocationList) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a self-signed root certificate
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(mathRand.Int63()),
		Subject:               subject,
		SubjectKeyId:          generateRandomBytes(10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(time.Duration(-1 * time.Hour)),
		NotAfter:              time.Now().Add(time.Duration(1 * time.Hour)),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	// Create a CRL for the root certificate
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(time.Duration(-1 * time.Hour)),
		NextUpdate: time.Now().Add(time.Duration(1 * time.Hour)),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, cert, key)
	require.NoError(t, err)
	crl, err = x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)
	return
}

func createCaCertificate(t *testing.T, subject pkix.Name, rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey) (key *ecdsa.PrivateKey, cert *x509.Certificate, crl *x509.RevocationList) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create the CA certificate
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(mathRand.Int63()),
		Subject:               subject,
		SubjectKeyId:          generateRandomBytes(10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(time.Duration(-1 * time.Hour)),
		NotAfter:              time.Now().Add(time.Duration(1 * time.Hour)),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, rootCert, key.Public(), rootKey)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	// Create a CRL for the CA
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(time.Duration(-1 * time.Hour)),
		NextUpdate: time.Now().Add(time.Duration(1 * time.Hour)),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, cert, key)
	require.NoError(t, err)
	crl, err = x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)
	return
}

func createDistinguishedName(cn string) pkix.Name {
	return pkix.Name{
		Country:            []string{"NL"},
		Organization:       []string{"Test Organization"},
		OrganizationalUnit: []string{"Test Unit"},
		CommonName:         cn,
	}
}

func generateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("Failed to generate random bytes: " + err.Error())
	}
	return bytes
}

func writeCertAsPemFile(t *testing.T, path string, certs ...*x509.Certificate) {
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		err = pem.Encode(file, pemBlock)
	}
	require.NoError(t, err)
}
