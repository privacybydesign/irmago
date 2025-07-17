package eudi

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
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

	issuer   TrustModel
	verifier TrustModel
}

const certFolder = "certs"
const crlFolder = "crls"

type TrustModel struct {
	basePath         string
	rootPool         *x509.CertPool
	intermediatePool *x509.CertPool
	revocationLists  []*x509.RevocationList
}

func (tm *TrustModel) GetCertificatePath() string {
	return filepath.Join(tm.basePath, certFolder)
}
func (tm *TrustModel) GetClrPath() string {
	return filepath.Join(tm.basePath, crlFolder)
}

// NewConfiguration returns a new configuration. After this ParseFolder() should be called to parse the specified path.
func NewConfiguration(path string) (conf *Configuration, err error) {
	conf = &Configuration{
		path: path,
		issuer: TrustModel{
			basePath: filepath.Join(path, "issuers"),
		},
		verifier: TrustModel{
			basePath: filepath.Join(path, "verifiers"),
		},
	}

	if err = common.EnsureDirectoryExists(conf.path); err != nil {
		return nil, err
	}
	if err = common.EnsureDirectoryExists(conf.issuer.GetCertificatePath()); err != nil {
		return nil, err
	}
	if err = common.EnsureDirectoryExists(conf.verifier.GetCertificatePath()); err != nil {
		return nil, err
	}
	if err = common.EnsureDirectoryExists(conf.issuer.GetClrPath()); err != nil {
		return nil, err
	}
	if err = common.EnsureDirectoryExists(conf.verifier.GetClrPath()); err != nil {
		return nil, err
	}

	conf.clear()

	return
}

// ParseFolder assumes the latest files (certs + crls) are downloaded.
// ParseFolder populates the current Configuration by parsing the available trust chains and crls.
func (conf *Configuration) ParseFolder() error {
	conf.clear()

	err := readTrustModel(conf.issuer)
	if err != nil {
		return err
	}

	err = readTrustModel(conf.verifier)
	if err != nil {
		return err
	}

	return err
}

func (conf *Configuration) clear() {
	conf.issuer.rootPool = x509.NewCertPool()
	conf.issuer.intermediatePool = x509.NewCertPool()
	conf.issuer.revocationLists = nil
	conf.verifier.rootPool = x509.NewCertPool()
	conf.verifier.intermediatePool = x509.NewCertPool()
	conf.verifier.revocationLists = nil
}

func readTrustModel(trustModel TrustModel) error {
	// Parse and read the CRLs
	err := trustModel.readRevocationLists()
	if err != nil {
		return err
	}

	// Parse and load the trustchains
	err = trustModel.readTrustChains()
	if err != nil {
		return err
	}

	// TODO: verify all root and intermediate certs have a valid CRL present

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
				return fmt.Errorf("certificate %s is not self-signed, and thus not a valid root certificate", rootCert.Subject.ToRDNSequence().String())
			}

			// Valid root cert, add to pool and continue with intermediate certs
			tm.rootPool.AddCert(rootCert)

			// Add the intermediate certs to the intermediate pool
			if len(chain) > 2 {
				intermediateCerts := chain[1:]
				validationOptions := x509.VerifyOptions{
					Roots:         tm.rootPool,
					Intermediates: tm.intermediatePool,
					// TODO: add KeyUsages validation ?
				}

				parentCert := rootCert
				for _, cert := range intermediateCerts {
					// Verify the certificate against the root pool and add it to the intermediate pool
					if _, err := cert.Verify(validationOptions); err != nil {
						return err
					}

					// Check if the available CLR(s) for this cert are signed correctly
					if err := tm.verifyRevocationListSignatures(parentCert); err != nil {
						return err
					}

					// Validate intermediate cert against parent CRL(s)
					isRevoked := false
					parentRevocationLists := tm.GetRevocationListsForCert(parentCert.Issuer)
					for _, crl := range parentRevocationLists {
						for _, revoked := range crl.RevokedCertificateEntries {
							if revoked.SerialNumber == cert.SerialNumber {
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

					tm.intermediatePool.AddCert(cert)
					parentCert = cert
				}
			}
		}
	}
	return nil
}

func (tm *TrustModel) readRevocationLists() error {
	crlFiles, err := filepath.Glob(filepath.Join(tm.GetClrPath(), "*.crl"))
	if err != nil {
		return err
	}

	var crls []*x509.RevocationList
	if len(crls) == 0 {
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

func (tm *TrustModel) GetRevocationListsForCert(issuer pkix.Name) []*x509.RevocationList {
	var clrs []*x509.RevocationList
	for _, rl := range tm.revocationLists {
		if rl.Issuer.ToRDNSequence().String() == issuer.ToRDNSequence().String() {
			clrs = append(clrs, rl)
		}
	}
	return clrs
}

// Verify the signatures of the revocation lists for a given parent certificate
// In care of a revocation list for the root certificate, this will verify for the root certificate itself.
func (tm *TrustModel) verifyRevocationListSignatures(parentCert *x509.Certificate) error {
	revocationLists := tm.GetRevocationListsForCert(parentCert.Issuer)
	if len(revocationLists) == 0 {
		return fmt.Errorf("no revocation lists found for parent certificate %s", parentCert.Subject.ToRDNSequence().String())
	}
	for _, crl := range revocationLists {
		if err := crl.CheckSignatureFrom(parentCert); err != nil {
			return err
		}
	}
	return nil
}
