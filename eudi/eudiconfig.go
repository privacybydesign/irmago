package eudi

import (
	"fmt"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
)

type SdJwtVerificationMode int

const (
	StrictSdJwtVerificationMode SdJwtVerificationMode = iota
	LaxSdJwtVerificationMode
)

// Logger is used for logging. For now, it will be set via the Client component
var Logger *logrus.Logger

func init() {
	Logger = common.Logger
}

// ExtraTrustAnchor is one trust anchor a wallet is built with beyond the
// pinned Yivi roots: the PEM chain (leaf-to-root order, root last) and the
// trust level certificates under it confer. This is how a third-party CA is
// anchored at medium — and how a test pins one — and how a CA promoted under
// contract would be raised to high: as data on the anchor, not as code.
type ExtraTrustAnchor struct {
	PEM     []byte
	Confers clientmodels.TrustLevel
}

// Configuration keeps track of issuer and requestor trusted chains and certificate revocation lists,
// retrieving them from the eudi folder, and downloads and saves new ones on demand.
// The trust chains are stored in the issuers and verifiers subfolders (.pem files), and the crls in the crls subfolder (.crl files).
// The trust chains are expected to be in PEM format, where the first certificate is the root, followed by intermediate certificates.
type Configuration struct {
	useStagingTrustAnchors bool

	Storage   storage.Storage
	Issuers   TrustModel
	Verifiers TrustModel

	// ExtraIssuerTrustAnchors and ExtraVerifierTrustAnchors are anchors added
	// on top of the pinned Yivi roots, each with the level it confers. Set
	// them before the first Reload; they survive every Reload after that.
	ExtraIssuerTrustAnchors   []ExtraTrustAnchor
	ExtraVerifierTrustAnchors []ExtraTrustAnchor
}

// NewConfiguration returns a new configuration. After this ParseFolder() should be called to parse the specified path.
func NewConfiguration(s storage.Storage) (conf *Configuration, err error) {
	httpClient := common.HTTPClient

	conf = &Configuration{
		Storage: s,
		Issuers: TrustModel{
			storageContainer:                  s.FileSystem().Issuers(),
			logger:                            Logger,
			httpClient:                        httpClient,
			revocationListsDistributionPoints: []string{},
		},
		Verifiers: TrustModel{
			storageContainer:                  s.FileSystem().Verifiers(),
			logger:                            Logger,
			httpClient:                        httpClient,
			revocationListsDistributionPoints: []string{},
		},
	}

	return
}

func (c *Configuration) EnableStagingTrustAnchors() {
	c.useStagingTrustAnchors = true
}

func (c *Configuration) SetCertificateVerificationMode(mode CertificateVerificationMode) {
	c.Issuers.SetCertificateVerificationMode(mode)
	c.Verifiers.SetCertificateVerificationMode(mode)
}

// Reload assumes the latest files (trust anchors and certificate revocation lists) are downloaded.
// Reload (re)populates the Configuration by loading the pinned trust anchors, followed by the downloaded ones.
// Intermediate certificates are checked against the revocation list of the root certificates befor being added to the trust model.
func (c *Configuration) Reload() error {
	c.Issuers.clear()
	c.Verifiers.clear()

	if err := c.addProductionTrustAnchors(); err != nil {
		return err
	}

	if c.useStagingTrustAnchors {
		if err := c.addStagingTrustAnchors(); err != nil {
			return err
		}
	}

	for _, anchor := range c.ExtraIssuerTrustAnchors {
		if err := c.Issuers.addTrustAnchors(anchor.Confers, anchor.PEM); err != nil {
			return fmt.Errorf("failed to add extra issuer trust anchor: %v", err)
		}
	}
	for _, anchor := range c.ExtraVerifierTrustAnchors {
		if err := c.Verifiers.addTrustAnchors(anchor.Confers, anchor.PEM); err != nil {
			return fmt.Errorf("failed to add extra verifier trust anchor: %v", err)
		}
	}

	// Read the trust anchors from storage
	if err := c.Issuers.Reload(); err != nil {
		return fmt.Errorf("failed to load issuer trust model: %v", err)
	}

	if err := c.Verifiers.Reload(); err != nil {
		return fmt.Errorf("failed to load verifier trust model: %v", err)
	}

	return nil
}

func (c *Configuration) addProductionTrustAnchors() error {
	c.Issuers.addRevocationListDistributionPoints(
		Production_Yivi_RootCertificateRevocationListDistributionPoint,
		Production_Yivi_IssuerCaCertificateRevocationListDistributionPoint,
	)

	c.Verifiers.addRevocationListDistributionPoints(
		Production_Yivi_RootCertificateRevocationListDistributionPoint,
		Production_Yivi_VerifierCaCertificateRevocationListDistributionPoint,
	)

	// Read the hardcoded trust anchors. The Yivi roots confer high: a
	// certificate under them is Yivi vouching for its holder.
	if err := c.Issuers.addTrustAnchors(clientmodels.TrustLevel_High, []byte(Production_Yivi_IssuerTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add yivi production issuer trust anchors: %v", err)
	}
	if err := c.Verifiers.addTrustAnchors(clientmodels.TrustLevel_High, []byte(Production_Yivi_VerifierTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add yivi production verifier trust anchors: %v", err)
	}
	return nil
}

func (c *Configuration) addStagingTrustAnchors() error {
	c.Issuers.addRevocationListDistributionPoints(
		Staging_Yivi_RootCertificateRevocationListDistributionPoint,
		Staging_Yivi_IssuerCaCertificateRevocationListDistributionPoint,
	)

	c.Verifiers.addRevocationListDistributionPoints(
		Staging_Yivi_RootCertificateRevocationListDistributionPoint,
		Staging_Yivi_VerifierCaCertificateRevocationListDistributionPoint,
	)

	// Read the hardcoded trust anchors. The staging roots are Yivi's own too,
	// so they confer high like the production ones.
	if err := c.Issuers.addTrustAnchors(clientmodels.TrustLevel_High, []byte(Staging_Yivi_IssuerTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add Yivi staging issuer trust anchors: %v", err)
	}
	if err := c.Verifiers.addTrustAnchors(clientmodels.TrustLevel_High, []byte(Staging_Yivi_VerifierTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add Yivi staging verifier trust anchors: %v", err)
	}

	return nil
}

// ResolveVerifierLogo returns the cached logo for the given verifier key
// (typically the verifier's certificate serial number) as a base64-encoded
// clientmodels.Image, or nil if no logo is cached.
func (c *Configuration) ResolveVerifierLogo(key string) *clientmodels.Image {
	return LoadLogoImage(c.Verifiers.storageContainer.LogoManager(), key)
}

func (c *Configuration) UpdateCertificateRevocationLists() error {
	var wg sync.WaitGroup
	wg.Add(2)

	go updateWorker(c.Issuers.syncCertificateRevocationLists, &wg)
	go updateWorker(c.Verifiers.syncCertificateRevocationLists, &wg)

	wg.Wait()

	// TODO: implement locking on the config to pause/start the job.
	// We should not update if we are in the middle of handling a session, because it might disrupt the session.
	return c.Reload()
}

func updateWorker(worker func(), wg *sync.WaitGroup) {
	defer wg.Done()
	worker()
}
