package eudi

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
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

// The CRL index stores a mapping from the certificate Distribution Point to a local stored file
func (tm *TrustModel) readCRLIndex(indexFileName string) (map[string]string, error) {
	var crlIndex = make(map[string]string)

	filePath := filepath.Join(tm.GetCrlPath(), indexFileName)

	// If the file does not (yet) exist, return an empty map
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return crlIndex, nil
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return crlIndex, fmt.Errorf("error opening CRL index file: %v", err)
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
			log.Printf("invalid line in CRL index file: %q. Skipping line...", line)
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

func (tm *TrustModel) readRevocationLists() error {
	crlFiles, err := filepath.Glob(filepath.Join(tm.GetCrlPath(), "*.crl"))
	if err != nil {
		return err
	}

	crls := make([]*x509.RevocationList, len(crlFiles))
	for i, crlFile := range crlFiles {
		crl, err := readRevocationListFromFile(crlFile)
		if err != nil {
			return err
		}
		crls[i] = crl
	}

	tm.revocationLists = crls
	return nil
}

func readRevocationListFromFile(filePath string) (*x509.RevocationList, error) {
	crlBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, err
	}

	return crl, nil
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
				tm.logger.Infof("Root certificate %s is not valid: %v, skipping the rest of the chain", rootCert.Subject.ToRDNSequence().String(), err)
				continue
			}

			// Self-signed root cert, verify other options, add to the root pool and continue with intermediate certs
			// Note: duplicates are filtered out by the call to .AddCert()
			// Note: if the root cert is not valid, the cert will still be in the trustedRootCertificates pool, but the verification will fail later on
			tm.trustedRootCertificates.AddCert(rootCert)
			tm.allCerts = append(tm.allCerts, rootCert)

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
					if err := utils.VerifyRevocationListsSignatures(parentCert, tm.revocationLists); err != nil {
						return err
					}

					// Validate intermediate cert against parent CRLs (if any)
					isRevoked := false
					parentRevocationLists := utils.GetRevocationListsForIssuer(caCert.AuthorityKeyId, caCert.Issuer, tm.revocationLists)
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

// syncCertificateRevocationLists downloads revocation lists unknown by the system yet,
// plus it updates existing CRLs which are due for refresh.
// For now, we only support Full CRLs (issued by the certificate issuing CA, so no indirect CRLs) and we do not (yet) handle CRL-delta files.
// TODO: also read certs from file (not from tm.allCerts) ?
// TODO: determine what to do if one or more downloads fail;  do we accept the risk of using potentially revoked certificates?
// TODO: remove index files for certificates which are no longer available (i.e. on built-in chain update or after building 'Add/remove chain' functionality)
func (tm *TrustModel) syncCertificateRevocationLists() {
	// For each certificate in the model, check if it has a CRL distribution point and see if we need to download or update it
	for _, cert := range tm.allCerts {
		tm.logger.Debugf("Syncing CRLs for certificate %s with serial %s", cert.Subject.ToRDNSequence().String(), cert.SerialNumber.String())
		updatedCrlIndex := make(map[string]string)

		// Create a hash of the certificate's raw subject to be used as the filename
		hash := sha256.Sum256(cert.RawSubject)
		certIndexFile := fmt.Sprintf("%x.index", hash)

		// Read the current CRL index from file for processing
		tm.logger.Debugf("reading certificate CRL index file %s", certIndexFile)
		crlIndex, err := tm.readCRLIndex(certIndexFile)
		if err != nil {
			tm.logger.Warnf("error reading CRL index %q: %v", certIndexFile, err)

			// Since we cannot work with this file, delete it and re-sync all CRLs
			err = os.Remove(certIndexFile)
			if err != nil {
				tm.logger.Warnf("error removing CRL index file %q: %v", certIndexFile, err)
			}
		}

		// Read all CRLs from disk to check if any need to be updated
		tm.logger.Debug("syncing distribution points found in index file...")
		for crlDistPoint, crlFileName := range crlIndex {
			tm.logger.Debugf("syncing distribution point %q with filename %q...", crlDistPoint, crlFileName)

			crlFilePath := path.Join(tm.GetCrlPath(), crlFileName)
			markCrlForDeletion := false
			markCrlForResync := false

			if slices.Contains(cert.CRLDistributionPoints, crlDistPoint) {
				// Read the CRLs from file, verify the signature and check if it needs to be updated
				crl, err := readRevocationListFromFile(crlFilePath)
				if err != nil {
					tm.logger.Warnf("error reading CRL file %s: %v", crlFilePath, err)

					// Mark the file for deletion and also make sure the current index is updated, so the sync will think the distribution point is new
					markCrlForDeletion = true
					markCrlForResync = true
				}

				// Verify we are working with a valid CRL file
				err = crl.CheckSignatureFrom(cert)
				if err != nil {
					tm.logger.Warn("could not verify signature of cached CRL; marking CRL for deletion...")

					// Do not add the CRL to the index, instead remove the file from disk and check the next file
					markCrlForDeletion = true
					markCrlForResync = true
				} else if time.Now().After(crl.NextUpdate) {
					tm.logger.Debugf("CRL file NextUpdate expired (%s) and requires update. Downloading file from distribution point...", crl.NextUpdate.Format(time.UnixDate))

					if _, err := tm.downloadVerifyAndSaveCRL(crlDistPoint, cert); err != nil {
						// If the download fails, do not mark the current file for deletion, as we can still use it
						tm.logger.Warnf("error downloading new CRL file: %v", err)
						tm.logger.Debug("keeping old CRL file for certificate verification...")
					}
				}
			} else {
				tm.logger.Debug("indexed distribution point not found in certificate list of distribution points; marking CRL for deletion...")

				// The cert might have been updated and a previous known distribution point will probably have been removed from the list.
				markCrlForDeletion = true
			}

			if markCrlForDeletion {
				tm.logger.Debugf("removing file %q...", crlFilePath)

				// Remove the file from disk and remove the reference from the index
				if err := os.Remove(crlFilePath); err != nil {
					tm.logger.Debugf("error removing CRL file %s: %v", crlFilePath, err)
				}
			} else {
				// Make sure the distribution point is in the updated index
				tm.logger.Debugf("adding distribution point %q with CRL file %q to the index...", crlDistPoint, crlFilePath)
				updatedCrlIndex[crlDistPoint] = crlFileName
			}

			if markCrlForResync {
				// If a file has been marked for resync (i.e. the file was corrupt, unusable or has invalid sig), remove it from the 'current index'
				// So the next part of the sync will not find the distribution point in the index, and treat it as a new distribution point.
				delete(crlIndex, crlDistPoint)
			}
		}

		// Now we've updated all known distribution points, we need to download the ones we don't know about yet
		for _, distPoint := range cert.CRLDistributionPoints {
			if _, ok := crlIndex[distPoint]; !ok {
				// This is a new distribution point, download the CRL and update the index
				if filename, err := tm.downloadVerifyAndSaveCRL(distPoint, cert); err != nil {
					tm.logger.Warnf("error downloading CRL from distribution point %q: %v", distPoint, err)
				} else {
					updatedCrlIndex[distPoint] = filename
				}
			}
		}

		// Write the index to file again, as it might have been updated with new CRLs
		if err := tm.writeCRLIndex(certIndexFile, updatedCrlIndex); err != nil {
			tm.logger.Warnf("error writing CRL index %q: %v", certIndexFile, err)
		}
	}
}

// downloadAndVerifyCRL downloads the CRL from the distribution point, verifies its signature against the issuer cert
// and returns the filename (not the full path) where the file is stored.
// The filename is composed as "<sha256(cert.subject)>-<sha256(distPoint)>.crl" to support multiple distribution points per cert.
func (tm *TrustModel) downloadVerifyAndSaveCRL(distPoint string, cert *x509.Certificate) (string, error) {
	// Get the data
	resp, err := tm.httpClient.Get(distPoint)
	if err != nil {
		return "", fmt.Errorf("error downloading CRL file: %v", err)
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error downloading CRL file, HTTP status: %s", resp.Status)
	}

	// Read the CRL so we can verify its signature
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading CRL file from HTTP response: %v", err)
	}

	crlList, err := x509.ParseRevocationList(buf)
	if err != nil {
		return "", fmt.Errorf("error reading CRL file: %v", err)
	}

	err = crlList.CheckSignatureFrom(cert)
	if err != nil {
		return "", fmt.Errorf("error verifying CRL signature: %v", err)
	}

	// Determine filename (hash cert subject + hash dist point) + filepath
	filename := fmt.Sprintf("%x-%x.crl", sha256.Sum256(cert.RawSubject), sha256.Sum256([]byte(distPoint)))
	filePath := filepath.Join(tm.GetCrlPath(), filename)

	out, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("error creating file on disk: %v", err)
	}
	defer out.Close()

	// Write the body to file
	_, err = out.Write(buf)
	if err != nil {
		return "", fmt.Errorf("error saving file content: %v", err)
	}

	return filename, nil
}
