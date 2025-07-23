package eudi

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"mime"
	"os"
	"path/filepath"

	"github.com/privacybydesign/irmago/internal/common"
)

// Configuration keeps track of issuer and requestor trusted chains and certificate revocation lists,
// retrieving them from the eudi_configuration folder, and downloads and saves new ones on demand.
// The trust chains are stored in the issuers and verifiers subfolders (.pem files), and the crls in the crls subfolder (.crl files).
// The trust chains are expected to be in PEM format, where the first certificate is the root, followed by intermediate certificates.
type Configuration struct {
	path string

	Issuers   TrustModel
	Verifiers TrustModel
}

const certFolder = "certs"
const crlFolder = "crls"
const logoCacheFolder = "logos"

type TrustModel struct {
	basePath         string
	rootPool         *x509.CertPool
	intermediatePool *x509.CertPool
	revocationLists  []*x509.RevocationList
}

func (tm *TrustModel) GetCertificatePath() string {
	return filepath.Join(tm.basePath, certFolder)
}
func (tm *TrustModel) GetCrlPath() string {
	return filepath.Join(tm.basePath, crlFolder)
}
func (tm *TrustModel) GetLogosPath() string {
	return filepath.Join(tm.basePath, logoCacheFolder)
}
func (tm *TrustModel) GetRootCerts() *x509.CertPool {
	return tm.rootPool
}
func (tm *TrustModel) GetIntermediateCerts() *x509.CertPool {
	return tm.intermediatePool
}
func (tm *TrustModel) ensureDirectoryExists() error {
	if err := common.EnsureDirectoryExists(tm.GetCertificatePath()); err != nil {
		return err
	}
	if err := common.EnsureDirectoryExists(tm.GetCrlPath()); err != nil {
		return err
	}
	if err := common.EnsureDirectoryExists(tm.GetLogosPath()); err != nil {
		return err
	}
	return nil
}
func (tm *TrustModel) clear() {
	tm.rootPool = x509.NewCertPool()
	tm.intermediatePool = x509.NewCertPool()
	tm.revocationLists = []*x509.RevocationList{}
}

// NewConfiguration returns a new configuration. After this ParseFolder() should be called to parse the specified path.
func NewConfiguration(path string) (conf *Configuration, err error) {
	conf = &Configuration{
		path: path,
		Issuers: TrustModel{
			basePath: filepath.Join(path, "issuers"),
		},
		Verifiers: TrustModel{
			basePath: filepath.Join(path, "verifiers"),
		},
	}

	conf.Issuers.ensureDirectoryExists()
	conf.Verifiers.ensureDirectoryExists()

	conf.clear()

	return
}

// ParseFolder assumes the latest files (certs + crls) are downloaded.
// ParseFolder populates the current Configuration by parsing the available trust chains and crls.
func (conf *Configuration) ParseFolder() error {
	conf.clear()

	err := conf.Issuers.readTrustModel()
	if err != nil {
		return err
	}

	err = conf.Verifiers.readTrustModel()
	if err != nil {
		return err
	}

	return err
}

func (conf *Configuration) clear() {
	conf.Issuers.clear()
	conf.Verifiers.clear()
}

func (tm *TrustModel) readTrustModel() error {
	// Parse and read the CRLs
	err := tm.readRevocationLists()
	if err != nil {
		return err
	}

	// Parse and load the trustchains
	err = tm.readTrustChains()
	if err != nil {
		return err
	}

	// TODO: verify all root and intermediate certs have a valid CRL present?

	return nil
}

func (tm *TrustModel) readTrustChains() error {
	chains, err := filepath.Glob(filepath.Join(tm.GetCertificatePath(), "*.pem"))
	if err != nil {
		return err
	}
	for _, trustChainFile := range chains {
		bts, err := os.ReadFile(trustChainFile)
		if err != nil {
			return err
		}

		chain, err := ParsePemCertificateChain(bts)
		if err != nil {
			return err
		}

		// Add the root cert to the root pool
		if len(chain) >= 1 {
			rootCert := chain[0]

			// Verify if the root is self-signed, otherwise this is not a valid root cert
			if rootCert.Subject.ToRDNSequence().String() != rootCert.Issuer.ToRDNSequence().String() {
				// TODO: add authorityKeyId == subjectKeyId check?
				return fmt.Errorf("certificate %s is not self-signed, and thus not a valid root certificate", rootCert.Subject.ToRDNSequence().String())
			}

			// Valid root cert, add to the root pool and continue with intermediate certs
			// Note: duplicates are filtered out by the call to .AddCert()
			tm.rootPool.AddCert(rootCert)

			// TODO: add expiration checks for the root cert?

			// Add the intermediate certs to the intermediate pool
			if len(chain) >= 2 {
				intermediateCerts := chain[1:]
				validationOptions := x509.VerifyOptions{
					Roots:         tm.rootPool,
					Intermediates: tm.intermediatePool,
					// TODO: add KeyUsages validation ?
				}

				parentCert := rootCert
				for _, caCert := range intermediateCerts {
					// Verify the certificate against the root pool and add it to the intermediate pool
					if _, err := caCert.Verify(validationOptions); err != nil {
						return err
					}

					// Check if the available CLR(s) for this cert are signed correctly
					if err := tm.verifyRevocationListsSignatures(parentCert); err != nil {
						return err
					}

					// Validate intermediate cert against parent CRL(s)
					isRevoked := false
					parentRevocationLists := tm.GetRevocationListsForIssuer(caCert.AuthorityKeyId, caCert.Issuer)
					for _, crl := range parentRevocationLists {
						for _, revoked := range crl.RevokedCertificateEntries {
							if revoked.SerialNumber == caCert.SerialNumber {
								isRevoked = true
								break
							}
						}

						if isRevoked {
							break
						}
					}

					// Only if the validations pass, add the cert to the intermediate pool
					// Otherwise, skip this (and all following) intermediate certs in the chain
					if isRevoked {
						break
					}

					tm.intermediatePool.AddCert(caCert)
					parentCert = caCert
				}
			}
		}
	}
	return nil
}

func (tm *TrustModel) readRevocationLists() error {
	crlFiles, err := filepath.Glob(filepath.Join(tm.GetCrlPath(), "*.crl"))
	if err != nil {
		return err
	}

	var crls []*x509.RevocationList
	if len(crlFiles) == 0 {
		return nil // No CRLs found
	}

	for _, crlFile := range crlFiles {
		crlBytes, err := os.ReadFile(crlFile)
		if err != nil {
			return err
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			return err
		}

		crls = append(crls, crl)
	}

	tm.revocationLists = crls
	return nil
}

func (tm *TrustModel) GetRevocationListsForIssuer(authorityKeyId []byte, issuer pkix.Name) []*x509.RevocationList {
	var clrs []*x509.RevocationList
	for _, rl := range tm.revocationLists {
		if bytes.Equal(rl.AuthorityKeyId, authorityKeyId) && rl.Issuer.ToRDNSequence().String() == issuer.ToRDNSequence().String() {
			clrs = append(clrs, rl)
		}
	}
	return clrs
}

// Verify the signatures of the revocation lists for a given parent certificate
// In case of a revocation list for the root certificate, this will verify for the root certificate itself.
func (tm *TrustModel) verifyRevocationListsSignatures(parentCert *x509.Certificate) error {
	revocationLists := tm.GetRevocationListsForIssuer(parentCert.SubjectKeyId, parentCert.Subject)
	if len(revocationLists) == 0 {
		return nil
	}
	for _, crl := range revocationLists {
		if err := crl.CheckSignatureFrom(parentCert); err != nil {
			return err
		}
	}
	return nil
}

func (conf *Configuration) CacheVerifierLogo(filename string, logo *RequestorSchemeLogo) (fullFilename string, path string, err error) {
	if logo == nil || logo.Data == nil {
		return "", "", fmt.Errorf("cannot cache nil logo")
	}

	// Find a file-extension for the logo based on its MIME type
	extensions, err := mime.ExtensionsByType(logo.MimeType)
	if err != nil {
		return "", "", err
	}

	fullFilename = filename + extensions[0]
	path = filepath.Join(conf.Verifiers.GetLogosPath(), fullFilename)

	// If file exists, overwrite it, as it might have updated between certificate issuances
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if file != nil {
		defer file.Close()
	}

	if err != nil {
		return "", "", err
	}

	_, err = file.Write(logo.Data)
	if err != nil {
		return "", "", err
	}

	return
}
