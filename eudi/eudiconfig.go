package eudi

import (
	"fmt"
	"net/http"
	"sync"

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

// Configuration keeps track of issuer and requestor trusted chains and certificate revocation lists,
// retrieving them from the eudi folder, and downloads and saves new ones on demand.
// The trust chains are stored in the issuers and verifiers subfolders (.pem files), and the crls in the crls subfolder (.crl files).
// The trust chains are expected to be in PEM format, where the first certificate is the root, followed by intermediate certificates.
type Configuration struct {
	useStagingTrustAnchors bool

	Storage   storage.Storage
	Issuers   TrustModel
	Verifiers TrustModel
}

// NewConfiguration returns a new configuration. After this ParseFolder() should be called to parse the specified path.
func NewConfiguration(s storage.Storage) (conf *Configuration, err error) {
	httpClient := &http.Client{}

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

	// Read the hardcoded trust anchors
	if err := c.Issuers.addTrustAnchors([]byte(Production_Yivi_IssuerTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add yivi production issuer trust anchors: %v", err)
	}
	if err := c.Verifiers.addTrustAnchors([]byte(Production_Yivi_VerifierTrustAnchor)); err != nil {
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

	// Read the hardcoded trust anchors
	if err := c.Issuers.addTrustAnchors([]byte(Staging_Yivi_IssuerTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add Yivi staging issuer trust anchors: %v", err)
	}
	if err := c.Verifiers.addTrustAnchors([]byte(Staging_Yivi_VerifierTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add Yivi staging verifier trust anchors: %v", err)
	}

	return nil
}

func (c *Configuration) ResolveVerifierLogo(filename string) (*string, error) {
	return c.Verifiers.storageContainer.LogoManager().GetLogo(filename)
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
