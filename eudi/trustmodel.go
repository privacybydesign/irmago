package eudi

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/sirupsen/logrus"
)

// trustState is everything a TrustModel knows about who it trusts, as one
// immutable value. A reload assembles a fresh one off to the side and publishes
// it whole, so a reader — a session's chain validation, the CRL sync — always
// sees a complete state: never the roots of a new reload beside the revocation
// lists of the old one, and never the emptied-out middle of a reload in
// progress. Nothing mutates a trustState after commit publishes it.
type trustState struct {
	trustedRootCertificates           *x509.CertPool
	trustedIntermediateCertificates   *x509.CertPool
	allCerts                          []*x509.Certificate
	revocationLists                   []*x509.RevocationList
	revocationListsDistributionPoints []string

	// installedAnchors are the roots that came from chains installed in storage
	// rather than from the wallet config: the developer, staging and test seam.
	// The trust ladder ranks what chains to them as under Yivi's own CA.
	installedAnchors []*x509.Certificate
}

func newTrustState() *trustState {
	return &trustState{
		trustedRootCertificates:           x509.NewCertPool(),
		trustedIntermediateCertificates:   x509.NewCertPool(),
		allCerts:                          []*x509.Certificate{},
		revocationLists:                   []*x509.RevocationList{},
		revocationListsDistributionPoints: []string{},
	}
}

// emptyTrustState is what a TrustModel answers with before its first reload.
// Its pools are empty rather than nil: a nil Roots pool makes x509.Verify fall
// back to the operating system's root store, which is the one thing a wallet
// that has not loaded its anchors yet must not do.
var emptyTrustState = newTrustState()

// issuerOf finds the certificate a CRL is issued by among the ones held.
func (s *trustState) issuerOf(crl *x509.RevocationList) *x509.Certificate {
	for _, cert := range s.allCerts {
		if bytes.Equal(crl.AuthorityKeyId, cert.SubjectKeyId) && cert.Subject.ToRDNSequence().String() == crl.Issuer.ToRDNSequence().String() {
			return cert
		}
	}
	return nil
}

// TrustModel holds one role's trust anchors: the CAs whose certificates the
// wallet accepts for that role, their intermediates, and the revocation lists
// that go with them. It is also the role's chain validator for the trust ladder.
type TrustModel struct {
	storageContainer filesystem.FileSystemContainer

	httpClient                  *http.Client
	logger                      *logrus.Logger
	certificateVerificationMode CertificateVerificationMode

	// current is the state every reader sees. It is replaced whole by commit and
	// never written in place, which is what lets chain validation run on the
	// session path while a reload runs on another goroutine.
	current atomic.Pointer[trustState]

	// pending is the state a reload is assembling: clear starts it, the add and
	// load methods fill it, commit publishes it. Only the reload sequence touches
	// it, which Configuration serializes; readers never see it.
	pending *trustState
}

type CertificateVerificationMode int

const (
	StrictCertificateVerification CertificateVerificationMode = iota
	DeveloperModeCertificateVerification
)

// state is what readers consult: the last committed state, or the empty one
// before any reload has committed.
func (tm *TrustModel) state() *trustState {
	if s := tm.current.Load(); s != nil {
		return s
	}
	return emptyTrustState
}

// building is the state the reload sequence is assembling.
func (tm *TrustModel) building() *trustState {
	if tm.pending == nil {
		tm.pending = newTrustState()
	}
	return tm.pending
}

// commit publishes the pending state to every reader at once. A model with
// nothing pending keeps what it has.
func (tm *TrustModel) commit() {
	if tm.pending == nil {
		return
	}
	tm.current.Store(tm.pending)
	tm.pending = nil
}

// discard drops a pending state a reload could not finish, so what readers see
// stays the last state that was assembled in full.
func (tm *TrustModel) discard() {
	tm.pending = nil
}

func (tm *TrustModel) GetRevocationLists() []*x509.RevocationList {
	return tm.state().revocationLists
}

func (tm *TrustModel) SetCertificateVerificationMode(mode CertificateVerificationMode) {
	tm.certificateVerificationMode = mode
}

func (tm *TrustModel) GetCertificateVerificationMode() CertificateVerificationMode {
	return tm.certificateVerificationMode
}

// clear starts a reload: an empty pending state, which the add and load methods
// fill and commit publishes. What readers see is untouched until then.
func (tm *TrustModel) clear() {
	tm.pending = newTrustState()
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

	// Find issuing certificate for the CRL among the anchors in force
	cert := tm.state().issuerOf(crl)

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

// Reload loads the stored trust chains and revocation lists on top of whatever
// the pending state holds, and publishes the result. On error nothing is
// published: readers keep the last complete state.
func (tm *TrustModel) Reload() error {
	if err := tm.load(); err != nil {
		tm.discard()
		return err
	}
	tm.commit()
	return nil
}

// load fills the pending state from storage without publishing it, so a caller
// reloading several models can commit them together.
func (tm *TrustModel) load() error {
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
	s := tm.building()
	for _, distPoint := range distPointUrls {
		if !slices.Contains(s.revocationListsDistributionPoints, distPoint) {
			s.revocationListsDistributionPoints = append(s.revocationListsDistributionPoints, distPoint)
		}
	}
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

func (tm *TrustModel) getIntermediateCertificateVerificationOptions(s *trustState) x509.VerifyOptions {
	validationOptions := x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Roots:         s.trustedRootCertificates,
		Intermediates: s.trustedIntermediateCertificates,
	}

	if tm.certificateVerificationMode == StrictCertificateVerification {
		validationOptions.KeyUsages = []x509.ExtKeyUsage{
			x509.ExtKeyUsage(x509.KeyUsageCertSign),
			x509.ExtKeyUsage(x509.KeyUsageCRLSign),
		}
	}

	return validationOptions
}

// addTrustAnchors installs PEM anchor chains from storage into the pending
// state. Each PEM is one chain in leaf-to-root order (matching the convention
// enforced by certificateManager.InstallCertificate, where the filename is
// derived from chain[0]): the root is the last certificate, the intermediates
// precede it. Chains installed this way are the developer, staging and test
// seam; their roots are recorded as installed anchors.
func (tm *TrustModel) addTrustAnchors(trustAnchors ...[]byte) error {
	for _, bts := range trustAnchors {
		chain, err := utils.ParsePemCertificateChain(bts)
		if err != nil {
			return err
		}
		if len(chain) == 0 {
			continue
		}

		root := chain[len(chain)-1]
		// Walk the intermediates outward from the root: the chain on disk is
		// leaf-to-root, so reverse the part before the root.
		intermediates := make([]*x509.Certificate, 0, len(chain)-1)
		for _, cert := range slices.Backward(chain[:len(chain)-1]) {
			intermediates = append(intermediates, cert)
		}
		if tm.addAnchor(root, intermediates) {
			s := tm.building()
			if !containsCertificate(s.installedAnchors, root) {
				s.installedAnchors = append(s.installedAnchors, root)
			}
		}
	}
	return nil
}

// addAnchor installs one anchor into the pending state: a root the chain
// building for this role may end at, with its intermediates ordered from the
// root downwards. An anchor is trusted for what chains to it whether or not it
// is self-signed, so a subordinate CA can be anchored on its own. Each
// intermediate is verified against the root and the intermediates before it, and
// checked against its parent's CRL; one that does not hold up ends the chain
// there, and the rest of the wallet's anchors still install. Reports whether the
// root itself was installed.
func (tm *TrustModel) addAnchor(root *x509.Certificate, intermediates []*x509.Certificate) bool {
	s := tm.building()
	subject := root.Subject.ToRDNSequence().String()

	// Verify the root's own validity window and key usage. The pool it is
	// checked against holds the root itself, so x509.Verify treats it as trusted
	// and only judges the certificate on its own terms.
	rootCertsForValidation := s.trustedRootCertificates.Clone()
	rootCertsForValidation.AddCert(root)
	if _, err := root.Verify(tm.getRootVerificationOptions(rootCertsForValidation)); err != nil {
		tm.logger.Warnf("Root certificate %s is not valid: %v, skipping the rest of the chain", subject, err)
		return false
	}

	// Only add the root again if it wasn't already part of another chain loaded into memory
	if !containsCertificate(s.allCerts, root) {
		s.allCerts = append(s.allCerts, root)
	}
	// Duplicates are filtered out by the pool itself.
	s.trustedRootCertificates.AddCert(root)

	parentCert := root
	validationOptions := tm.getIntermediateCertificateVerificationOptions(s)
	for _, caCert := range intermediates {
		// Verify the certificate against the root pools
		if _, err := caCert.Verify(validationOptions); err != nil {
			// Skip this intermediate cert, as it is not valid
			tm.logger.Warnf("Intermediate certificate %s is not valid: %v, skipping the rest of the chain", caCert.Subject.ToRDNSequence().String(), err)
			return true
		}

		// Add the CA parents CRLs
		crls, err := tm.readAndVerifyRevocationListsForCert(caCert, parentCert)
		if err != nil {
			tm.logger.Warnf("Failed to read or verify CRLs to verify intermediate certificate %s revocation: %v", caCert.Subject.ToRDNSequence().String(), err)
		}

		// Validate intermediate cert against parent CRLs (if any)
		if crl := revokedBy(caCert, crls); crl != nil {
			tm.logger.Warnf("Intermediate certificate %s is revoked by CRL %s (number %s), skipping the rest of the chain", caCert.Subject.ToRDNSequence().String(), crl.Issuer.ToRDNSequence().String(), crl.Number.String())
			return true
		}

		// Only if the validations pass, add the cert to the intermediate pool.
		// Otherwise, skip this (and all following) intermediate certs in the chain.
		s.trustedIntermediateCertificates.AddCert(caCert)
		if !containsCertificate(s.allCerts, caCert) {
			s.allCerts = append(s.allCerts, caCert)
		}
		parentCert = caCert

		// If the revocation list distribution points of this intermediate cert are known, add them to the list of known distribution points
		tm.addRevocationListDistributionPoints(caCert.CRLDistributionPoints...)
	}
	return true
}

// revokedBy returns the CRL among crls that names cert, or nil.
func revokedBy(cert *x509.Certificate, crls []*x509.RevocationList) *x509.RevocationList {
	for _, crl := range crls {
		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return crl
			}
		}
	}
	return nil
}

func containsCertificate(certs []*x509.Certificate, cert *x509.Certificate) bool {
	return slices.ContainsFunc(certs, func(c *x509.Certificate) bool {
		return bytes.Equal(c.Raw, cert.Raw)
	})
}

func (tm *TrustModel) loadRevocationLists() error {
	s := tm.building()
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
		issuingCert := s.issuerOf(crl)
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
	s.revocationLists = verified
	return nil
}

func (tm *TrustModel) GetVerificationOptionsTemplate() x509.VerifyOptions {
	s := tm.state()
	return x509.VerifyOptions{
		Roots:         s.trustedRootCertificates,
		Intermediates: s.trustedIntermediateCertificates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // VerifyOptions does not check against the KeyUsage extension, but we set it to ExtKeyUsageAny to allow any usage and validate the digital signature key usage ourselfs.
	}
}

// ValidateChain implements trust.ChainValidator: the chains from leaf to one of
// this model's anchors, with the digitalSignature key usage on the leaf and no
// revocation against it. An error means nothing anchors the leaf, or it does
// not hold up; the trust ladder reads either as absent evidence.
func (tm *TrustModel) ValidateChain(leaf *x509.Certificate) ([][]*x509.Certificate, error) {
	return eudi_jwt.VerifyCertificateChains(tm, leaf, nil)
}

// InstalledAnchor implements trust.ChainValidator: whether root came from a
// chain installed in storage rather than from the wallet config.
func (tm *TrustModel) InstalledAnchor(root *x509.Certificate) bool {
	return containsCertificate(tm.state().installedAnchors, root)
}

func (tm *TrustModel) syncCertificateRevocationLists() {
	tm.logger.Debugf("Starting CRL sync...")

	mgr := tm.storageContainer.CertificateRevocationListManager()

	// Loop over the known distribution points to download and verify CRLs
	for _, distPoint := range tm.state().revocationListsDistributionPoints {
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

// RemoveCertificate removes the installed certificate chain whose leaf
// certificate signature (hex-encoded) matches the given thumbprint. Call
// Reload afterwards to drop the chain from the in-memory trust pools.
func (tm *TrustModel) RemoveCertificate(thumbprint string) error {
	return tm.storageContainer.CertificateManager().RemoveCertificate(thumbprint)
}
