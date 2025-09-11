package eudi

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
)

type TrustModel struct {
	basePath                        string
	trustedRootCertificates         *x509.CertPool
	trustedIntermediateCertificates *x509.CertPool
	allCerts                        []*x509.Certificate
	revocationLists                 []*x509.RevocationList
	httpClient                      *http.Client
	logger                          *logrus.Logger
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

func (tm *TrustModel) GetRevocationLists() []*x509.RevocationList {
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
	tm.allCerts = []*x509.Certificate{}
	tm.trustedRootCertificates = x509.NewCertPool()
	tm.trustedIntermediateCertificates = x509.NewCertPool()
	tm.revocationLists = []*x509.RevocationList{}
}

func getCrlFileNameForCertDistributionPoint(distPoint string) string {
	return fmt.Sprintf("%x.crl", sha256.Sum256([]byte(distPoint)))
}

func (tm *TrustModel) isCrlFileCached(crlFileName string) bool {
	crlFilePath := filepath.Join(tm.GetCrlPath(), crlFileName)
	_, err := os.Stat(crlFilePath)
	return err == nil
}

func (tm *TrustModel) findCertificateForRevocationList(crl *x509.RevocationList) *x509.Certificate {
	// Find the certificate that matches the CRL's issuer
	for _, cert := range tm.allCerts {
		if bytes.Equal(crl.AuthorityKeyId, cert.AuthorityKeyId) && cert.Issuer.ToRDNSequence().String() == crl.Issuer.ToRDNSequence().String() {
			return cert
		}
	}
	return nil
}

// The CRL index stores a mapping from the certificate Distribution Point to a local stored file
func (tm *TrustModel) readCRLIndex(indexFileName string) (map[string]string, error) {
	var crlIndex = make(map[string]string)

	clrPath := filepath.Join(tm.GetCrlPath(), indexFileName)

	// If the file does not (yet) exist, return an empty map
	if _, err := os.Stat(clrPath); os.IsNotExist(err) {
		return nil, nil
	}

	// Open the file
	file, err := os.Open(clrPath)
	if err != nil {
		return nil, fmt.Errorf("error opening CRL index file: %v", err)
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Print each line
		line := scanner.Text()
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			crlIndex[parts[0]] = parts[1]
		} else {
			tm.logger.Warnf("invalid line in CRL index file: %q. Skipping line...", line)
		}
	}

	// Check for errors during scanning
	if err := scanner.Err(); err != nil {
		// Since we don't know the state of the index at this point, return an empty map and the error so the caller can decide how to handle it
		return make(map[string]string), fmt.Errorf("error reading CRL index file: %v", err)
	}
	return crlIndex, nil
}

func (tm *TrustModel) writeCRLIndex(indexFileName string, crlIndex map[string]string) error {
	filePath := filepath.Join(tm.GetCrlPath(), indexFileName)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	// Use a buffered writer for efficient writing
	writer := bufio.NewWriter(file)

	for distPoint, filename := range crlIndex {
		_, err := fmt.Fprintf(writer, "%s\t%s\n", distPoint, filename)
		if err != nil {
			return fmt.Errorf("error writing to file: %v", err)
		}
	}

	return writer.Flush()
}

func (tm *TrustModel) readAndVerifyRevocationListsForCert(cert *x509.Certificate, parentCert *x509.Certificate) ([]*x509.RevocationList, error) {
	var crls []*x509.RevocationList

	// Loop over the distribution points to get the list of CRLs files to load
	for _, distPoint := range cert.CRLDistributionPoints {
		crlFile := getCrlFileNameForCertDistributionPoint(distPoint)

		crl, err := tm.readRevocationListFromFile(crlFile)
		if err != nil {
			tm.logger.Warnf("Failed to read CRL file %q for distribution point %q: %v. Skip loading the CRL.", crlFile, distPoint, err)

			// Skip loading this CRL, for instance on first startup
			continue
		}

		// Verify the CRL signature using the parent cert
		err = crl.CheckSignatureFrom(parentCert)
		if err != nil {
			tm.logger.Warnf("Failed to verify CRL file %q for distribution point %q: %v. Skip loading the CRL.", crlFile, distPoint, err)

			// Skip loading this CRL, for instance on first startup
			continue
		}
		crls = append(crls, crl)
	}
	return crls, nil
}

func (tm *TrustModel) readRevocationListFromFile(fileName string) (*x509.RevocationList, error) {
	crlBytes, err := os.ReadFile(filepath.Join(tm.GetCrlPath(), fileName))
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, err
	}

	return crl, nil
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
	return crl != nil && crl.NextUpdate.After(time.Now())
}

func (tm *TrustModel) loadTrustChains() error {
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
		chain, err := utils.ParsePemCertificateChain(bts)
		if err != nil {
			return err
		}

		// Add the root cert to the root pool
		if len(chain) >= 1 {
			rootCert := chain[0]

			// For now, we only accept the root certs that are self-signed (no system CA certs)
			// Verify if the root is self-signed, otherwise this is not a valid root cert
			if !bytes.Equal(rootCert.RawSubject, rootCert.RawIssuer) {
				tm.logger.Warnf("Root certificate %s is not valid: %v, skipping the rest of the chain", rootCert.Subject.ToRDNSequence().String(), err)
				continue
			}

			// Only add the root again if it wasn't already part of another chain and loaded into memory
			if !slices.ContainsFunc(tm.allCerts, func(cert *x509.Certificate) bool {
				return bytes.Equal(cert.Raw, rootCert.Raw)
			}) {
				// Self-signed root cert, verify other options, add to the root pool and continue with intermediate certs
				// Note: duplicates are filtered out by the call to .AddCert()
				// Note: if the root cert is not valid, the cert will still be in the trustedRootCertificates pool, but the verification will fail later on
				tm.trustedRootCertificates.AddCert(rootCert)
				tm.allCerts = append(tm.allCerts, rootCert)

				_, err = rootCert.Verify(rootValidationOptions)
				if err != nil {
					// If the root cert is not valid, skip the rest of the chain
					tm.logger.Warnf("Root certificate %s is not valid: %v, skipping the rest of the chain", rootCert.Subject.ToRDNSequence().String(), err)
					continue
				}
			}

			// Add the intermediate certs to the intermediate pool
			if len(chain) >= 2 {
				parentCert := rootCert
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

				for _, caCert := range intermediateCerts {
					// Verify the certificate against the root pools
					if _, err := caCert.Verify(validationOptions); err != nil {
						// Skip this intermediate cert, as it is not valid
						tm.logger.Warnf("Intermediate certificate %s is not valid: %v, skipping the rest of the chain", caCert.Subject.ToRDNSequence().String(), err)
						continue
					}

					// Add the CA CRLs (if any and not already added to the list of revocation lists)
					crls, err := tm.readAndVerifyRevocationListsForCert(caCert, parentCert)
					if err != nil {
						tm.logger.Warnf("Failed to read or verify CRLs for intermediate certificate %s: %v", caCert.Subject.ToRDNSequence().String(), err)
					}

					for _, crl := range crls {
						if !slices.ContainsFunc(tm.revocationLists, func(item *x509.RevocationList) bool {
							return bytes.Equal(item.Signature, crl.Signature)
						}) {
							tm.revocationLists = append(tm.revocationLists, crl)
						}
					}

					// Validate intermediate cert against parent CRLs (if any)
					isRevoked := false
					parentRevocationLists := utils.GetRevocationListsForIssuer(caCert.AuthorityKeyId, caCert.Issuer, tm.revocationLists)
					for _, crl := range parentRevocationLists {
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
				}
			}
		}
	}
	return nil
}

func (tm *TrustModel) CreateVerifyOptionsTemplate() x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:         tm.trustedRootCertificates,
		Intermediates: tm.trustedIntermediateCertificates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// syncCertificateRevocationLists works by:
// - Listing all (unique) CRL distribution points from all root and intermediate certificates
// - Match that list against the locally stored once, and checking if they are (still) valid and up-to-date
// -- If valid:
// --- If not up-to-date: download and verify the latest CRL from the distribution point
// -- If not valid:
// --- Remove the local copy
// - For any distribution point which is not cached yet, also download and verify the latest CRL
// For any cached CRL that hasn't been checked, updated or downloaded anew, remove the cached file (this is the case when an issuing certificate removed one of its CRL distribution points)
func (tm *TrustModel) syncCertificateRevocationLists() {
	// Create a set, which will contain an up-to-date list of CRL files which should be on disk;
	// Any file that is not in this list, will be removed at the end
	crlFilesToKeep := utils.NewSet[string]()

	// Get a set of all (unique) CRL distribution points from all certificates in the trustmodel
	crlDistributionPoints := utils.NewSet[string]()
	for _, cert := range tm.allCerts {
		for _, dp := range cert.CRLDistributionPoints {
			crlDistributionPoints.Add(dp)
		}
	}

	// Match the list against the locally stored CRLs and check their validity (and up-to-dateness)
	for crlDistPoint := range crlDistributionPoints.Values() {
		crlFileName := getCrlFileNameForCertDistributionPoint(crlDistPoint)

		// If the file does not exist, continue with the next distribution point
		if !tm.isCrlFileCached(crlFileName) {
			tm.logger.Infof("CRL file %q does not exist and will be downloaded later...", crlFileName)
			continue
		}

		// Read the CRL file and validate
		crl, err := tm.readRevocationListFromFile(crlFileName)
		if err != nil {
			tm.logger.Warnf("Failed to read CRL file %q: %v", crlFileName, err)

			// Try to remove local copy to initiate downloading again
			err = os.Remove(crlFileName)
			if err != nil {
				tm.logger.Warnf("Failed to remove CRL file %q: %v", crlFileName, err)
			}
			continue
		}

		if !tm.isCrlValid(crl) {
			// Remove the local copy immediately, so the download section will pick it up
			tm.logger.Infof("CRL distribution point %q is not valid, removing local copy...", crlDistPoint)
			err := os.Remove(filepath.Join(tm.GetCrlPath(), crlFileName))
			if err != nil {
				tm.logger.Warnf("Failed to remove CRL file %q: %v", crlFileName, err)
			}
		} else if !tm.isCrlUpToDate(crl) {
			// Even if the update fails, keep the current file which (potentially) contains revoked certificates from before the latest update
			crlFilesToKeep.Add(crlFileName)

			tm.logger.Infof("CRL distribution point %q is not up-to-date, downloading latest CRL...", crlDistPoint)
			err = tm.downloadVerifyAndCacheCrl(crlDistPoint, crlFileName)
			if err != nil {
				tm.logger.Warnf("Failed to download/verify/save CRL from %q: %v. Keep using current cached revocation list.", crlDistPoint, err)
				continue
			}
			tm.logger.Infof("CRL distribution point %q updated successfully.", crlDistPoint)
		} else {
			crlFilesToKeep.Add(crlFileName)
		}
	}

	// For any distribution point which is not cached yet, download and verify the latest CRL
	for crlDistPoint := range crlDistributionPoints.Values() {
		crlFileName := getCrlFileNameForCertDistributionPoint(crlDistPoint)
		if !tm.isCrlFileCached(crlFileName) {
			tm.logger.Infof("CRL distribution point %q is not cached (yet), downloading latest CRL...", crlDistPoint)
			err := tm.downloadVerifyAndCacheCrl(crlDistPoint, crlFileName)
			if err != nil {
				// TODO: how should we work with this; we know there should be a CRL available (with potential revoked certs on it), but we cannot get to it....
				tm.logger.Warnf("Failed to download/verify/save CRL from %q: %v. Skip caching the CRL.", crlDistPoint, err)
				continue
			}
			tm.logger.Infof("CRL distribution point %q successfully cached.", crlDistPoint)
			crlFilesToKeep.Add(crlFileName)
		}
	}

	// For any cached CRL that hasn't been checked, updated or downloaded anew, remove the cached file (this is the case when an issuing certificate removed one of its CRL distribution points)
	tm.logger.Infof("Removing outdated CRL files...")
	existingFiles, _ := filepath.Glob(filepath.Join(tm.GetCrlPath(), "*.crl"))
	for _, existingCrlFilePath := range existingFiles {
		existingCrlFileName := filepath.Base(existingCrlFilePath)

		// If the file is not available in the 'list to keep', remove the cached file
		if !crlFilesToKeep.Contains(existingCrlFileName) {
			tm.logger.Infof("Removing CRL file %q...", existingCrlFileName)
			err := os.Remove(existingCrlFilePath)
			if err != nil {
				continue
			}
			tm.logger.Infof("CRL file %q removed successfully.", existingCrlFileName)
		}
	}

	tm.logger.Infof("CRL sync completed, %d CRL files are now cached.", crlFilesToKeep.Len())
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

func (tm *TrustModel) cacheCrl(crl *x509.RevocationList, crlFileName string) error {
	if crl == nil {
		return fmt.Errorf("invalid CRL: crl cannot be nil")
	}

	if !strings.Contains(crlFileName, ".crl") {
		return fmt.Errorf("invalid CRL: crlFileName must have .crl extension")
	}

	// Determine filename (hash cert subject + hash dist point) + filepath
	filePath := filepath.Join(tm.GetCrlPath(), crlFileName)

	out, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file on disk: %v", err)
	}
	defer out.Close()

	// Write the body to file
	_, err = out.Write(crl.Raw)
	if err != nil {
		return fmt.Errorf("error saving file content: %v", err)
	}

	return nil
}

func (tm *TrustModel) downloadVerifyAndCacheCrl(crlDistPoint string, crlFileName string) error {
	tm.logger.Infof("Downloading and verifying CRL from %q...", crlDistPoint)
	newCrl, err := tm.downloadAndVerifyCrl(crlDistPoint)
	if err != nil {
		return err
	}

	tm.logger.Infof("Successfully downloaded and verified CRL from %q, saving to file %q...", crlDistPoint, crlFileName)
	err = tm.cacheCrl(newCrl, crlFileName)
	if err != nil {
		return err
	}

	tm.logger.Infof("Successfully cached CRL to %q.", crlFileName)
	return nil
}
