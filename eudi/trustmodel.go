package eudi

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/sirupsen/logrus"
)

type TrustModel struct {
	storageContainer filesystem.FileSystemContainer

	trustedRootCertificates           *x509.CertPool
	trustedIntermediateCertificates   *x509.CertPool
	allCerts                          []*x509.Certificate
	revocationLists                   []*x509.RevocationList
	revocationListsDistributionPoints []string
	httpClient                        *http.Client
	logger                            *logrus.Logger
	certificateVerificationMode       CertificateVerificationMode
}

type CertificateVerificationMode int

const (
	StrictCertificateVerification CertificateVerificationMode = iota
	DeveloperModeCertificateVerification
)

func (tm *TrustModel) GetRevocationLists() []*x509.RevocationList {
	return tm.revocationLists
}

func (tm *TrustModel) SetCertificateVerificationMode(mode CertificateVerificationMode) {
	tm.certificateVerificationMode = mode
}

func (tm *TrustModel) clear() {
	tm.allCerts = []*x509.Certificate{}
	tm.trustedRootCertificates = x509.NewCertPool()
	tm.trustedIntermediateCertificates = x509.NewCertPool()
	tm.revocationLists = []*x509.RevocationList{}
	tm.revocationListsDistributionPoints = []string{}
}

func (tm *TrustModel) findCertificateForRevocationList(crl *x509.RevocationList) *x509.Certificate {
	// Find the certificate that matches the CRL's issuer
	for _, cert := range tm.allCerts {
		if bytes.Equal(crl.AuthorityKeyId, cert.SubjectKeyId) && cert.Subject.ToRDNSequence().String() == crl.Issuer.ToRDNSequence().String() {
			return cert
		}
	}
	return nil
}

func (tm *TrustModel) readAndVerifyRevocationListsForCert(cert *x509.Certificate, parentCert *x509.Certificate) ([]*x509.RevocationList, error) {
	var crls []*x509.RevocationList
	mgr := tm.storageContainer.CertificateRevocationListManager()

	// Loop over the distribution points to get the list of CRLs files to load
	for _, distPoint := range cert.CRLDistributionPoints {
		if present, err := mgr.Exists(distPoint); err != nil {
			tm.logger.Warnf("Failed to check presence of CRL for distribution point %q: %v. Skip loading the CRL.", distPoint, err)
			continue
		} else if !present {
			tm.logger.Infof("CRL for distribution point %q not present. Skip loading the CRL.", distPoint)
			continue
		}

		crl, err := mgr.Read(distPoint)
		if err != nil {
			tm.logger.Warnf("Failed to read CRL for distribution point %q: %v. Skip loading the CRL.", distPoint, err)
			continue
		}

		// Verify the CRL signature using the parent cert
		if err := crl.CheckSignatureFrom(parentCert); err != nil {
			tm.logger.Warnf("Failed to verify CRL for distribution point %q: %v. Skip loading the CRL.", distPoint, err)
			continue
		}
		crls = append(crls, crl)
	}
	return crls, nil
}

func (tm *TrustModel) isCrlValid(crl *x509.RevocationList) bool {
	if crl == nil {
		return false
	}

	// Find issuing certificate for the CRL
	cert := tm.findCertificateForRevocationList(crl)

	if cert == nil {
		tm.logger.Warnf("No valid certificate found for CRL from issuer %s", crl.Issuer.ToRDNSequence().String())
		return false
	}

	// Check CRL signature
	err := crl.CheckSignatureFrom(cert)
	if err != nil {
		tm.logger.Warnf("CRL signature check failed: %v", err)
		return false
	}

	return true
}

func (tm *TrustModel) isCrlUpToDate(crl *x509.RevocationList) bool {
	updateNeeded := crl != nil && crl.NextUpdate.After(time.Now())

	if !updateNeeded {
		tm.logger.Infof("CRL from %x is outdated, a new version needs to be downloaded.", crl.AuthorityKeyId)
	}

	return updateNeeded
}

func (tm *TrustModel) Reload() error {
	// Load all trust chains from the certs folder
	if err := tm.loadTrustChains(); err != nil {
		return fmt.Errorf("failed to load trust chains: %v", err)
	}

	// With all certs loaded into memory, load all CRLs from the CRL folder and verify them against the certs
	if err := tm.loadRevocationLists(); err != nil {
		return fmt.Errorf("failed to load revocation lists: %v", err)
	}

	return nil
}

func (tm *TrustModel) GetSavedTrustChains() ([][]byte, error) {
	return tm.storageContainer.CertificateManager().GetRawCertificates()
}

func (tm *TrustModel) loadTrustChains() error {
	trustedChainFiles, err := tm.storageContainer.CertificateManager().GetRawCertificates()
	if err != nil {
		return err
	}
	return tm.addTrustAnchors(trustedChainFiles...)
}

func (tm *TrustModel) addRevocationListDistributionPoints(distPointUrls ...string) {
	tm.revocationListsDistributionPoints = append(tm.revocationListsDistributionPoints, distPointUrls...)
}

func (tm *TrustModel) getRootVerificationOptions(rootCerts *x509.CertPool) x509.VerifyOptions {
	validationOptions := x509.VerifyOptions{
		CurrentTime: time.Now(),
		Roots:       rootCerts,
	}

	if tm.certificateVerificationMode == StrictCertificateVerification {
		validationOptions.KeyUsages = []x509.ExtKeyUsage{
			x509.ExtKeyUsage(x509.KeyUsageCertSign),
			x509.ExtKeyUsage(x509.KeyUsageCRLSign),
		}
	}

	return validationOptions
}

func (tm *TrustModel) getIntermediateCertificateVerificationOptions() x509.VerifyOptions {
	validationOptions := x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Roots:         tm.trustedRootCertificates,
		Intermediates: tm.trustedIntermediateCertificates,
	}

	if tm.certificateVerificationMode == StrictCertificateVerification {
		validationOptions.KeyUsages = []x509.ExtKeyUsage{
			x509.ExtKeyUsage(x509.KeyUsageCertSign),
			x509.ExtKeyUsage(x509.KeyUsageCRLSign),
		}
	}

	return validationOptions
}

func (tm *TrustModel) addTrustAnchors(trustAnchors ...[]byte) error {
	for _, bts := range trustAnchors {
		chain, err := utils.ParsePemCertificateChain(bts)
		if err != nil {
			return err
		}

		// Add the root cert to the root pool. Chains on disk are stored in
		// leaf-to-root order (matching the convention enforced by
		// certificateManager.InstallCertificate, where the filename is
		// derived from chain[0] — the leaf). The root is therefore the
		// last element, and the intermediates follow in root→leaf order.
		if len(chain) >= 1 {
			rootCert := chain[len(chain)-1]
			intermediateChain := chain[:len(chain)-1]

			// For now, we only accept the root certs that are self-signed (no system CA certs)
			// Verify if the root is self-signed, otherwise this is not a valid root cert
			if !bytes.Equal(rootCert.RawSubject, rootCert.RawIssuer) {
				tm.logger.Warnf("Root certificate %s is no root or self-signed certificate. Skipping the rest of the chain", rootCert.Subject.ToRDNSequence().String())
				continue
			}

			// Self-signed root cert, verify other options, add to the root pool and continue with intermediate certs
			// Note: duplicates are filtered out by the call to .AddCert()

			rootCertsForValidation := tm.trustedRootCertificates.Clone()
			rootCertsForValidation.AddCert(rootCert)
			rootValidationOptions := tm.getRootVerificationOptions(rootCertsForValidation)

			_, err = rootCert.Verify(rootValidationOptions)
			if err != nil {
				// If the root cert is not valid, skip the rest of the chain
				tm.logger.Warnf("Root certificate %s is not valid: %v, skipping the rest of the chain", rootCert.Subject.ToRDNSequence().String(), err)
				continue
			}

			// Only add the root again if it wasn't already part of another chain loaded into memory
			if !slices.ContainsFunc(tm.allCerts, func(cert *x509.Certificate) bool {
				return bytes.Equal(cert.Raw, rootCert.Raw)
			}) {
				tm.allCerts = append(tm.allCerts, rootCert)
			}

			// Valid root cert, add to the trusted root pool
			tm.trustedRootCertificates.AddCert(rootCert)

			// Add the intermediate certs to the intermediate pool. The chain
			// on disk is leaf-to-root, so to walk outward from the root we
			// iterate intermediateChain in reverse (last → first).
			if len(intermediateChain) > 0 {
				parentCert := rootCert
				intermediateCerts := make([]*x509.Certificate, len(intermediateChain))
				for i, c := range intermediateChain {
					intermediateCerts[len(intermediateChain)-1-i] = c
				}
				validationOptions := tm.getIntermediateCertificateVerificationOptions()

				for _, caCert := range intermediateCerts {
					// Verify the certificate against the root pools
					if _, err := caCert.Verify(validationOptions); err != nil {
						// Skip this intermediate cert, as it is not valid
						tm.logger.Warnf("Intermediate certificate %s is not valid: %v, skipping the rest of the chain", caCert.Subject.ToRDNSequence().String(), err)
						continue
					}

					// Add the CA parents CRLs
					crls, err := tm.readAndVerifyRevocationListsForCert(caCert, parentCert)
					if err != nil {
						tm.logger.Warnf("Failed to read or verify CRLs to verify intermediate certificate %s revocation: %v", caCert.Subject.ToRDNSequence().String(), err)
					}

					// Validate intermediate cert against parent CRLs (if any)
					isRevoked := false
					for _, crl := range crls {
						for _, revoked := range crl.RevokedCertificateEntries {
							if revoked.SerialNumber.Cmp(caCert.SerialNumber) == 0 {
								isRevoked = true
								tm.logger.Warnf("Intermediate certificate %s is revoked by CRL %s (number %s), skipping the rest of the chain", caCert.Subject.ToRDNSequence().String(), crl.Issuer.ToRDNSequence().String(), crl.Number.String())
								break
							}
						}

						if isRevoked {
							break
						}
					}

					// Only if the validations passes, add the cert to the intermediate pool
					// Otherwise, skip this (and all following) intermediate certs in the chain
					if isRevoked {
						break
					}

					tm.trustedIntermediateCertificates.AddCert(caCert)
					tm.allCerts = append(tm.allCerts, caCert)
					parentCert = caCert

					// If the revocation list distribution points of this intermediate cert are known, add them to the list of known distribution points
					for _, distPoint := range caCert.CRLDistributionPoints {
						if !slices.Contains(tm.revocationListsDistributionPoints, distPoint) {
							tm.revocationListsDistributionPoints = append(tm.revocationListsDistributionPoints, distPoint)
						}
					}
				}
			}
		}
	}
	return nil
}

func (tm *TrustModel) loadRevocationLists() error {
	mgr := tm.storageContainer.CertificateRevocationListManager()

	loaded, err := mgr.LoadAll(func(loadErr error) {
		tm.logger.Warnf("Failed to load CRL from disk: %v, skipping", loadErr)
	})
	if err != nil {
		return err
	}

	verified := make([]*x509.RevocationList, 0, len(loaded))
	for _, crl := range loaded {
		// Find the issuing certificate for this CRL
		issuingCert := tm.findCertificateForRevocationList(crl)
		if issuingCert == nil {
			tm.logger.Warnf("No issuing certificate found for CRL from issuer %s, skipping loading the CRL", crl.Issuer.ToRDNSequence().String())
			continue
		}

		tm.logger.Tracef("Found issuing certificate %s for CRL from issuer %s. Verifying...", issuingCert.Subject.ToRDNSequence().String(), crl.Issuer.ToRDNSequence().String())
		// Verify the CRL signature using the issuing cert
		if err := crl.CheckSignatureFrom(issuingCert); err != nil {
			tm.logger.Warnf("Failed to verify CRL from issuer %s: %v, skipping loading the CRL", crl.Issuer.ToRDNSequence().String(), err)
			continue
		}

		tm.logger.Tracef("Successfully loaded and verified CRL %x issued by %s", crl.Signature, crl.Issuer.ToRDNSequence().String())
		verified = append(verified, crl)
	}
	tm.revocationLists = verified
	return nil
}

func (tm *TrustModel) GetVerificationOptionsTemplate() x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:         tm.trustedRootCertificates,
		Intermediates: tm.trustedIntermediateCertificates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)}, // VerifyOptions does not check against the KeyUsage extension, but we set it to ExtKeyUsageAny to allow any usage and validate the digital signature key usage ourselfs.
	}
}

func (tm *TrustModel) syncCertificateRevocationLists() {
	tm.logger.Debugf("Starting CRL sync...")

	mgr := tm.storageContainer.CertificateRevocationListManager()

	// Loop over the known distribution points to download and verify CRLs
	for _, distPoint := range tm.revocationListsDistributionPoints {
		tm.logger.Debugf("Checking CRL distribution point %q...", distPoint)

		// If the CRL is not cached, download and verify it
		if present, _ := mgr.Exists(distPoint); !present {
			tm.logger.Info("CRL not cached, downloading file...")
		} else {
			// CRL is cached, read it, verify it and check if an update might be available
			// If the cached CRL is invalid, remove it and download it anew
			crl, err := mgr.Read(distPoint)
			if err != nil || !tm.isCrlValid(crl) {
				tm.logger.Warnf("Failed to verify cached CRL: %v. Downloading new version...", err)
			} else if tm.isCrlUpToDate(crl) {
				tm.logger.Info("CRL is valid and up-to-date, no action needed.")
				continue
			}

			tm.logger.Info("CRL is outdated and needs to be updated. Downloading new version...")
		}

		// At this point, we need to download a CRL update
		if err := tm.downloadVerifyAndCacheCrl(distPoint); err != nil {
			tm.logger.Warnf("Failed to download and cache CRL from %q: %v. Removing cached CRL.", distPoint, err)
			if rmErr := mgr.Remove(distPoint); rmErr != nil {
				tm.logger.Warnf("Failed to remove cached CRL for %q: %v", distPoint, rmErr)
			}
			tm.logger.Info("Removed cached CRL.")
			continue
		}
		tm.logger.Info("Successfully downloaded and cached CRL.")
	}

	tm.logger.Debugf("CRL sync completed.")
}

func (tm *TrustModel) downloadAndVerifyCrl(distPoint string) (*x509.RevocationList, error) {
	// Get the data
	resp, err := tm.httpClient.Get(distPoint)
	if err != nil {
		return nil, fmt.Errorf("error downloading CRL file: %v", err)
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error downloading CRL file, HTTP status: %s", resp.Status)
	}

	// Read the CRL so we can verify its signature
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading CRL file from HTTP response: %v", err)
	}

	crl, err := x509.ParseRevocationList(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading CRL file: %v", err)
	}

	// Validate download against issuing cert
	isCrlValid := tm.isCrlValid(crl)
	if !isCrlValid {
		return nil, fmt.Errorf("CRL signature is invalid")
	}

	return crl, nil
}

func (tm *TrustModel) downloadVerifyAndCacheCrl(crlDistPoint string) error {
	tm.logger.Infof("Downloading and verifying CRL from %q...", crlDistPoint)
	newCrl, err := tm.downloadAndVerifyCrl(crlDistPoint)
	if err != nil {
		return err
	}

	tm.logger.Infof("Successfully downloaded and verified CRL from %q, caching...", crlDistPoint)
	if err := tm.storageContainer.CertificateRevocationListManager().Save(newCrl, crlDistPoint); err != nil {
		return err
	}

	tm.logger.Infof("Successfully cached CRL for %q.", crlDistPoint)
	return nil
}

func (tm *TrustModel) InstallCertificate(pemData []byte) error {
	return tm.storageContainer.CertificateManager().InstallCertificate(pemData)
}
