package eudi

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/sirupsen/logrus"
)

// trustState is everything a TrustModel knows about who it trusts, as one
// immutable value. A reload assembles a fresh one off to the side and publishes it
// whole, so a reader — a session gate, Classify, the CRL sync — always sees a
// complete state: never the roots of a new reload beside the revocation lists of
// the old one, and never the emptied-out middle of a reload in progress. That
// middle used to be fail-open: with the revocation lists cleared and unanchored
// certificates admitted as low, a revoked certificate passed the gate until the
// reload finished.
//
// Nothing mutates a trustState after commit publishes it.
type trustState struct {
	// roots holds the anchors: the certificates chain building ends at. An anchor
	// is trusted for what it signs directly — a CA, self-signed or not — and never
	// for what its own issuer signed besides it.
	roots *x509.CertPool
	// intermediates is not filled by anchor installation any more, since the anchor
	// is the CA that issues end-entity certificates and no path building beyond it
	// is wanted. It stays for callers that assemble a model by hand.
	intermediates *x509.CertPool
	// anchors lists what roots holds, in installation order, since a CertPool
	// cannot be enumerated.
	anchors []*x509.Certificate
	// allCerts holds every anchor and every anchor's issuers, for finding the
	// certificate a CRL is issued by: an anchor's CRL revokes its leaves, an
	// issuer's revokes the anchor.
	allCerts           []*x509.Certificate
	revocationLists    []*x509.RevocationList
	distributionPoints []string

	// anchorLevels records, per anchored root (keyed by the SHA-256 of its DER),
	// the trust level its certificates confer. Every path that adds an anchor
	// states the level explicitly; nothing defaults to high.
	anchorLevels map[[sha256.Size]byte]clientmodels.TrustLevel
}

func newTrustState() *trustState {
	return &trustState{
		roots:              x509.NewCertPool(),
		intermediates:      x509.NewCertPool(),
		anchors:            []*x509.Certificate{},
		allCerts:           []*x509.Certificate{},
		revocationLists:    []*x509.RevocationList{},
		distributionPoints: []string{},
		anchorLevels:       map[[sha256.Size]byte]clientmodels.TrustLevel{},
	}
}

// emptyTrustState is what a TrustModel answers with before its first reload.
// Its pools are empty rather than nil: a nil Roots pool makes x509.Verify fall
// back to the operating system's root store, which is the one thing a wallet
// that has not loaded its anchors yet must not do.
var emptyTrustState = newTrustState()

func (s *trustState) clone() *trustState {
	return &trustState{
		roots:              s.roots.Clone(),
		intermediates:      s.intermediates.Clone(),
		anchors:            slices.Clone(s.anchors),
		allCerts:           slices.Clone(s.allCerts),
		revocationLists:    slices.Clone(s.revocationLists),
		distributionPoints: slices.Clone(s.distributionPoints),
		anchorLevels:       maps.Clone(s.anchorLevels),
	}
}

// issuerOf finds the anchored certificate a CRL is issued by.
func (s *trustState) issuerOf(crl *x509.RevocationList) *x509.Certificate {
	for _, cert := range s.allCerts {
		if bytes.Equal(crl.AuthorityKeyId, cert.SubjectKeyId) && cert.Subject.ToRDNSequence().String() == crl.Issuer.ToRDNSequence().String() {
			return cert
		}
	}
	return nil
}

// anchorLevel reports the level this root's certificates confer, and whether the
// root is anchored at all.
func (s *trustState) anchorLevel(root *x509.Certificate) (clientmodels.TrustLevel, bool) {
	level, ok := s.anchorLevels[sha256.Sum256(root.Raw)]
	return level, ok
}

// recordAnchorLevel remembers the level this root's certificates confer. A root
// that arrives twice — the same CA pinned by two callers — keeps the strongest
// statement made about it.
func (s *trustState) recordAnchorLevel(root *x509.Certificate, confers clientmodels.TrustLevel) {
	key := sha256.Sum256(root.Raw)
	if existing, ok := s.anchorLevels[key]; ok && !trust.Stronger(confers, existing) {
		return
	}
	s.anchorLevels[key] = confers
}

// A trustState is itself an X509VerificationContext, so a caller that needs
// several answers about one moment — chains, then revocation — can bind them to
// the same snapshot rather than asking the model twice.
func (s *trustState) GetVerificationOptionsTemplate() x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:         s.roots,
		Intermediates: s.intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // VerifyOptions does not check against the KeyUsage extension, but we set it to ExtKeyUsageAny to allow any usage and validate the digital signature key usage ourselfs.
	}
}

func (s *trustState) GetRevocationLists() []*x509.RevocationList {
	return s.revocationLists
}

type TrustModel struct {
	storageContainer filesystem.FileSystemContainer

	httpClient                  *http.Client
	logger                      *logrus.Logger
	certificateVerificationMode CertificateVerificationMode

	// current is the state every reader sees. It is replaced whole by commit and
	// never written in place, which is what lets Classify run on the session path
	// while the CRL refresh job reloads from another goroutine.
	current atomic.Pointer[trustState]

	// pending is the state a reload is assembling: clear starts it, the add and
	// load methods fill it, commit publishes it. Only the reload sequence touches
	// it, which Configuration serialises; readers never see it.
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

// building is the state the reload sequence is assembling. Without a preceding
// clear it starts from a copy of the current state, so an anchor added outside a
// full reload extends what is there rather than replacing it.
func (tm *TrustModel) building() *trustState {
	if tm.pending == nil {
		tm.pending = tm.state().clone()
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
	return tm.state().GetRevocationLists()
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
	// Locally installed chains confer high: this storage is the dev, staging and
	// test seam standing in for the Yivi CA, and nothing writes here in a released
	// wallet. A third-party CA arrives through the anchor list with its own level.
	return tm.addTrustAnchors(clientmodels.TrustLevel_High, trustedChainFiles...)
}

func (tm *TrustModel) addRevocationListDistributionPoints(distPointUrls ...string) {
	s := tm.building()
	s.distributionPoints = append(s.distributionPoints, distPointUrls...)
}

// addTrustAnchors installs anchors into the pending state, recording confers as
// the trust level each passes on to the certificates that validate to it.
//
// Each PEM is one anchor chain. Its first certificate is the anchor: the
// certificate chain building ends at, trusted for what it signs directly and for
// nothing else, whether or not it is self-signed. Any certificates after it are
// its issuers, root last. They are never anchors themselves — anchoring a root
// would trust every sibling CA under it — and are kept for one purpose: only an
// issuer's CRL can say whether the anchor has been revoked, so the issuers are
// what that CRL is verified against, and where it is published is registered
// for the sync.
//
// An anchor that does not hold up — not a CA, outside its validity window, an
// issuer chain that does not actually issue it, or revoked by its issuer — is
// skipped with a warning; the rest of the PEMs still install.
func (tm *TrustModel) addTrustAnchors(confers clientmodels.TrustLevel, trustAnchors ...[]byte) error {
	s := tm.building()

	// An anchor that yields no revocation endpoint is one whose certificates can
	// never be revoked: an absent CRL reads as "not revoked", and the CRLs a CA
	// issues are advertised in the certificates it issues, not in the CA
	// certificate itself. That is silent everywhere else, so it is said here.
	before := len(s.distributionPoints)
	defer func() {
		if len(s.distributionPoints) == before {
			tm.logger.Warnf("Trust anchor added with no CRL distribution point: certificates under it cannot be revoked")
		}
	}()

	for _, bts := range trustAnchors {
		chain, err := utils.ParsePemCertificateChain(bts)
		if err != nil {
			return err
		}
		if len(chain) == 0 {
			continue
		}

		anchor, issuers := chain[0], chain[1:]
		subject := anchor.Subject.ToRDNSequence().String()

		if err := tm.checkAnchor(anchor); err != nil {
			tm.logger.Warnf("Trust anchor %s is not installed: %v", subject, err)
			continue
		}
		if err := checkIssuerChain(anchor, issuers); err != nil {
			tm.logger.Warnf("Trust anchor %s is not installed: %v", subject, err)
			continue
		}
		if tm.chainRevoked(chain) {
			tm.logger.Warnf("Trust anchor %s is not installed: it or one of its issuers is revoked", subject)
			continue
		}

		// Where the anchor and its intermediate issuers are revoked is on those
		// certificates; a self-signed root has nowhere to be revoked.
		for _, cert := range chain[:len(chain)-1] {
			for _, distPoint := range cert.CRLDistributionPoints {
				if !slices.Contains(s.distributionPoints, distPoint) {
					s.distributionPoints = append(s.distributionPoints, distPoint)
				}
			}
		}

		s.roots.AddCert(anchor)
		s.recordAnchorLevel(anchor, confers)
		if !containsCertificate(s.anchors, anchor) {
			s.anchors = append(s.anchors, anchor)
		}
		// Every certificate in the chain may issue a CRL the sync downloads: the
		// anchor's revoke its leaves, its issuers' revoke the anchor.
		for _, cert := range chain {
			if !containsCertificate(s.allCerts, cert) {
				s.allCerts = append(s.allCerts, cert)
			}
		}
	}
	return nil
}

// checkAnchor says whether a certificate can serve as an anchor at all: inside
// its validity window and, in strict mode, a CA. Developer mode keeps the window
// but lets a test anchor at anything, as it always has.
func (tm *TrustModel) checkAnchor(anchor *x509.Certificate) error {
	now := time.Now()
	if now.Before(anchor.NotBefore) || now.After(anchor.NotAfter) {
		return fmt.Errorf("not valid at %s (notBefore %s, notAfter %s)",
			now.Format(time.RFC3339), anchor.NotBefore.Format(time.RFC3339), anchor.NotAfter.Format(time.RFC3339))
	}
	if tm.certificateVerificationMode != StrictCertificateVerification {
		return nil
	}
	if !anchor.BasicConstraintsValid || !anchor.IsCA {
		return fmt.Errorf("not a CA certificate")
	}
	if anchor.KeyUsage != 0 && anchor.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("key usage does not include keyCertSign")
	}
	return nil
}

// checkIssuerChain checks that the issuers given with an anchor are its issuers:
// each signed the one before it, and the last is self-signed. Their validity
// windows are deliberately not checked — an issuer that has since expired can
// still have signed the anchor, and its CRL is still what revokes it.
func checkIssuerChain(anchor *x509.Certificate, issuers []*x509.Certificate) error {
	if len(issuers) == 0 {
		return nil
	}
	root := issuers[len(issuers)-1]
	if !bytes.Equal(root.RawSubject, root.RawIssuer) {
		return fmt.Errorf("last certificate in the chain, %s, is not self-signed", root.Subject.ToRDNSequence().String())
	}
	child := anchor
	for _, issuer := range issuers {
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("%s did not issue %s: %v",
				issuer.Subject.ToRDNSequence().String(), child.Subject.ToRDNSequence().String(), err)
		}
		child = issuer
	}
	return nil
}

// chainRevoked reports whether the anchor or any intermediate issuer in a chain
// is named on its issuer's stored CRL. An absent CRL reads as not revoked, as it
// does for leaves.
func (tm *TrustModel) chainRevoked(chain []*x509.Certificate) bool {
	for i := 0; i+1 < len(chain); i++ {
		cert, parent := chain[i], chain[i+1]
		crls, err := tm.readAndVerifyRevocationListsForCert(cert, parent)
		if err != nil {
			tm.logger.Warnf("Failed to read or verify CRLs for %s: %v", cert.Subject.ToRDNSequence().String(), err)
		}
		for _, crl := range crls {
			for _, revoked := range crl.RevokedCertificateEntries {
				if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					tm.logger.Warnf("Certificate %s is revoked by CRL %s (number %s)",
						cert.Subject.ToRDNSequence().String(), crl.Issuer.ToRDNSequence().String(), crl.Number.String())
					return true
				}
			}
		}
	}
	return false
}

func containsCertificate(certs []*x509.Certificate, cert *x509.Certificate) bool {
	return slices.ContainsFunc(certs, func(c *x509.Certificate) bool {
		return bytes.Equal(c.Raw, cert.Raw)
	})
}

// Anchor is one installed trust anchor and the level it confers.
type Anchor struct {
	Certificate *x509.Certificate
	Level       clientmodels.TrustLevel
}

// Anchors lists the anchors in force, in installation order.
func (tm *TrustModel) Anchors() []Anchor {
	s := tm.state()
	anchors := make([]Anchor, 0, len(s.anchors))
	for _, cert := range s.anchors {
		level, _ := s.anchorLevel(cert)
		anchors = append(anchors, Anchor{Certificate: cert, Level: level})
	}
	return anchors
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
		// Find the issuing certificate for this CRL among the anchors being loaded
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
	return tm.state().GetVerificationOptionsTemplate()
}

func (tm *TrustModel) syncCertificateRevocationLists() {
	tm.logger.Debugf("Starting CRL sync...")

	mgr := tm.storageContainer.CertificateRevocationListManager()

	// Loop over the known distribution points to download and verify CRLs
	for _, distPoint := range tm.state().distributionPoints {
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

// anchorLevel reports the level this root's certificates confer in the state
// currently in force, and whether the root is anchored at all.
func (tm *TrustModel) anchorLevel(root *x509.Certificate) (clientmodels.TrustLevel, bool) {
	return tm.state().anchorLevel(root)
}

// Classify implements [trust.CertificateClassifier]: the trust level conferred by
// the anchor the leaf's chain validates to, or unevaluated when no anchored chain
// holds up. It never errors, and it serves stored evidence too — a stored
// credential's issuer leaf is re-classified on every read.
//
// Classification is expiry-tolerant, verifying the chain at a time inside the
// leaf's validity window: the vouching question about stored evidence concerns
// the signing act, and issuer leaves routinely expire before the credentials they
// signed. Demotion is reserved for acts of distrust. Live parties are not exempt
// from expiry — the session gate checks the validity window against the wall
// clock before evaluation sees the certificate.
func (tm *TrustModel) Classify(leaf *x509.Certificate) clientmodels.TrustLevel {
	if leaf == nil {
		return clientmodels.TrustLevel_Unevaluated
	}

	// One snapshot for the whole classification, so the chains and the revocation
	// lists come from the same reload even if one lands halfway through.
	s := tm.state()

	// The acceptance rules are shared with the session gate, so a rule added there
	// also governs ranking. Only the moment differs.
	chains, err := eudi_jwt.VerifyCertificateChains(s, leaf, nil, classificationTime(time.Now(), leaf))
	if err != nil {
		// A revocation is an act of distrust rather than the ordinary absence of an
		// anchor, so it is worth saying out loud.
		if errors.Is(err, eudi_jwt.ErrCertificateRevoked) {
			tm.logger.Warnf("trust: certificate %s fails the revocation check, not classifying it: %v", leaf.Subject.ToRDNSequence().String(), err)
		} else {
			tm.logger.Tracef("trust: certificate %s classifies to no anchor: %v", leaf.Subject.ToRDNSequence().String(), err)
		}
		return clientmodels.TrustLevel_Unevaluated
	}

	// A cross-signed leaf may validate to several anchors; the party lands on
	// the strongest word any of them gives.
	best := clientmodels.TrustLevel_Unevaluated
	for _, chain := range chains {
		root := chain[len(chain)-1]
		if level, ok := s.anchorLevel(root); ok && trust.Stronger(level, best) {
			best = level
		}
	}
	return best
}

// classificationTime is the moment a chain is verified at when classifying:
// now, clamped into the leaf's own validity window.
func classificationTime(now time.Time, leaf *x509.Certificate) time.Time {
	if now.Before(leaf.NotBefore) {
		return leaf.NotBefore
	}
	if now.After(leaf.NotAfter) {
		return leaf.NotAfter
	}
	return now
}
