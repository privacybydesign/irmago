package eudi

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
)

type TrustModel struct {
	basePath                        string
	trustedRootCertificates         *x509.CertPool
	trustedIntermediateCertificates *x509.CertPool
	revocationLists                 []*x509.RevocationList

	logger *logrus.Logger
}

func (tm *TrustModel) GetCertificatePath() string {
	return filepath.Join(tm.basePath, "certs")
}
func (tm *TrustModel) GetCrlPath() string {
	return filepath.Join(tm.basePath, "crls")
}
func (tm *TrustModel) GetLogosPath() string {
	return filepath.Join(tm.basePath, "logos")
}
func (tm *TrustModel) GetRootCerts() *x509.CertPool {
	return tm.trustedRootCertificates
}
func (tm *TrustModel) GetIntermediateCerts() *x509.CertPool {
	return tm.trustedIntermediateCertificates
}
func (tm *TrustModel) GetRevocationLists(authorityKeyId []byte, issuer pkix.Name) []*x509.RevocationList {
	return tm.revocationLists
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
	tm.trustedRootCertificates = x509.NewCertPool()
	tm.trustedIntermediateCertificates = x509.NewCertPool()
	tm.revocationLists = []*x509.RevocationList{}
}

// Verify the signatures of the revocation lists for a given parent certificate
// In case of a revocation list for the root certificate, this will verify for the root certificate itself.
func (tm *TrustModel) verifyRevocationListsSignatures(parentCert *x509.Certificate) error {
	revocationLists := tm.GetRevocationListsForIssuer(parentCert.SubjectKeyId, parentCert.Subject)
	for _, crl := range revocationLists {
		if err := crl.CheckSignatureFrom(parentCert); err != nil {
			return err
		}
	}
	return nil
}

func (tm *TrustModel) readRevocationLists() error {
	crlFiles, err := filepath.Glob(filepath.Join(tm.GetCrlPath(), "*.crl"))
	if err != nil {
		return err
	}

	crls := make([]*x509.RevocationList, len(crlFiles))
	for i, crlFile := range crlFiles {
		crlBytes, err := os.ReadFile(crlFile)
		if err != nil {
			return err
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			return err
		}

		crls[i] = crl
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
	trustAnchors := make([][]byte, len(chains))
	for i, trustChainFile := range chains {
		bts, err := os.ReadFile(trustChainFile)
		if err != nil {
			return err
		}
		trustAnchors[i] = bts
	}
	return tm.addTrustAnchors(trustAnchors...)
}

func (tm *TrustModel) addTrustAnchors(trustAnchors ...[]byte) error {
	rootValidationOptions := x509.VerifyOptions{
		CurrentTime: time.Now(),
		Roots:       tm.trustedRootCertificates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsage(x509.KeyUsageCertSign),
			x509.ExtKeyUsage(x509.KeyUsageCRLSign),
		},
	}

	for _, bts := range trustAnchors {
		chain, err := ParsePemCertificateChain(bts)
		if err != nil {
			return err
		}

		// Add the root cert to the root pool
		if len(chain) >= 1 {
			rootCert := chain[0]

			// For now, we only accept the root certs that are self-signed (no system CA certs)
			// Verify if the root is self-signed, otherwise this is not a valid root cert
			if !bytes.Equal(rootCert.RawSubject, rootCert.RawIssuer) {
				tm.logger.Infof("Root certificate %s is not valid: %v, skipping the rest of the chain", rootCert.Subject.ToRDNSequence().String(), err)
				continue
			}

			// Self-signed root cert, verify other options, add to the root pool and continue with intermediate certs
			// Note: duplicates are filtered out by the call to .AddCert()
			// Note: if the root cert is not valid, the cert will still be in the trustedRootCertificates pool, but the verification will fail later on
			tm.trustedRootCertificates.AddCert(rootCert)

			_, err = rootCert.Verify(rootValidationOptions)
			if err != nil {
				// If the root cert is not valid, skip the rest of the chain
				tm.logger.Infof("Root certificate %s is not valid: %v, skipping the rest of the chain", rootCert.Subject.ToRDNSequence().String(), err)
				continue
			}

			// Add the intermediate certs to the intermediate pool
			if len(chain) >= 2 {
				intermediateCerts := chain[1:]
				validationOptions := x509.VerifyOptions{
					CurrentTime:   time.Now(),
					Roots:         tm.trustedRootCertificates,
					Intermediates: tm.trustedIntermediateCertificates,
					KeyUsages: []x509.ExtKeyUsage{
						x509.ExtKeyUsage(x509.KeyUsageCertSign),
						x509.ExtKeyUsage(x509.KeyUsageCRLSign),
					},
				}

				parentCert := rootCert
				for _, caCert := range intermediateCerts {
					// Verify the certificate against the root pools
					if _, err := caCert.Verify(validationOptions); err != nil {
						// Skip this intermediate cert, as it is not valid
						tm.logger.Infof("Intermediate certificate %s is not valid: %v, skipping the rest of the chain", caCert.Subject.ToRDNSequence().String(), err)
						continue
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
							if revoked.SerialNumber.Cmp(caCert.SerialNumber) == 0 {
								isRevoked = true
								tm.logger.Infof("Intermediate certificate %s is revoked by CRL %s (number %s), skipping the rest of the chain", caCert.Subject.ToRDNSequence().String(), crl.Issuer.ToRDNSequence().String(), crl.Number.String())
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

					tm.trustedIntermediateCertificates.AddCert(caCert)
					parentCert = caCert
				}
			}
		}
	}
	return nil
}

func (tm *TrustModel) VerifyCertificateAgainstIssuerRevocationLists(cert *x509.Certificate) error {
	issuerRevocationLists := tm.GetRevocationListsForIssuer(cert.AuthorityKeyId, cert.Issuer)

	for _, revocationList := range issuerRevocationLists {
		for _, revokedCert := range revocationList.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("certificate is revoked by issuer %v in revocation list with number %v", cert.Issuer.ToRDNSequence().String(), revocationList.Number)
			}
		}
	}
	return nil
}
