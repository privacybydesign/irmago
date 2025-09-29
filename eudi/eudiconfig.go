package eudi

import (
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
)

// Logger is used for logging. For now, it will be set via the Client component
var Logger *logrus.Logger

func init() {
	Logger = common.Logger
}

// Configuration keeps track of issuer and requestor trusted chains and certificate revocation lists,
// retrieving them from the eudi_configuration folder, and downloads and saves new ones on demand.
// The trust chains are stored in the issuers and verifiers subfolders (.pem files), and the crls in the crls subfolder (.crl files).
// The trust chains are expected to be in PEM format, where the first certificate is the root, followed by intermediate certificates.
type Configuration struct {
	path                   string
	useStagingTrustAnchors bool

	Issuers   TrustModel
	Verifiers TrustModel
}

// NewConfiguration returns a new configuration. After this ParseFolder() should be called to parse the specified path.
func NewConfiguration(path string) (conf *Configuration, err error) {
	httpClient := &http.Client{}

	conf = &Configuration{
		path: path,
		Issuers: TrustModel{
			basePath:                          filepath.Join(path, "issuers"),
			logger:                            Logger,
			httpClient:                        httpClient,
			revocationListsDistributionPoints: []string{},
		},
		Verifiers: TrustModel{
			basePath:                          filepath.Join(path, "verifiers"),
			logger:                            Logger,
			httpClient:                        httpClient,
			revocationListsDistributionPoints: []string{},
		},
	}

	err = conf.Issuers.ensureDirectoryExists()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure issuer directories exist: %w", err)
	}

	err = conf.Verifiers.ensureDirectoryExists()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure verifier directories exist: %w", err)
	}
	return
}

func (conf *Configuration) EnableStagingTrustAnchors() {
	conf.useStagingTrustAnchors = true
}

// Reload assumes the latest files (trust anchors and certificate revocation lists) are downloaded.
// Reload (re)populates the Configuration by loading the pinned trust anchors, followed by the downloaded ones.
// Intermediate certificates are checked against the revocation list of the root certificates befor being added to the trust model.
func (conf *Configuration) Reload() error {
	conf.Issuers.clear()
	conf.Verifiers.clear()

	if err := conf.addProductionTrustAnchors(); err != nil {
		return err
	}

	if conf.useStagingTrustAnchors {
		if err := conf.addStagingTrustAnchors(); err != nil {
			return err
		}
	}

	// Read the trust anchors from storage
	if err := conf.Issuers.Reload(); err != nil {
		return fmt.Errorf("failed to load issuer trust model: %v", err)
	}

	if err := conf.Verifiers.Reload(); err != nil {
		return fmt.Errorf("failed to load verifier trust model: %v", err)
	}

	return nil
}

func (conf *Configuration) addProductionTrustAnchors() error {
	conf.Issuers.addRevocationListDistributionPoints(
		Production_Yivi_RootCertificateRevocationListDistributionPoint,
		Production_Yivi_IssuerCaCertificateRevocationListDistributionPoint,
	)

	conf.Verifiers.addRevocationListDistributionPoints(
		Production_Yivi_RootCertificateRevocationListDistributionPoint,
		Production_Yivi_VerifierCaCertificateRevocationListDistributionPoint,
	)

	// Read the hardcoded trust anchors
	if err := conf.Issuers.addTrustAnchors([]byte(Production_Yivi_IssuerTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add yivi production issuer trust anchors: %v", err)
	}
	if err := conf.Verifiers.addTrustAnchors([]byte(Production_Yivi_VerifierTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add yivi production verifier trust anchors: %v", err)
	}
	return nil
}

func (conf *Configuration) addStagingTrustAnchors() error {
	conf.Issuers.addRevocationListDistributionPoints(
		Staging_Yivi_RootCertificateRevocationListDistributionPoint,
		Staging_Yivi_IssuerCaCertificateRevocationListDistributionPoint,
	)

	conf.Verifiers.addRevocationListDistributionPoints(
		Staging_Yivi_RootCertificateRevocationListDistributionPoint,
		Staging_Yivi_VerifierCaCertificateRevocationListDistributionPoint,
	)

	// Read the hardcoded trust anchors
	if err := conf.Issuers.addTrustAnchors([]byte(Staging_Yivi_IssuerTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add yivi staging issuer trust anchors: %v", err)
	}
	if err := conf.Verifiers.addTrustAnchors([]byte(Staging_Yivi_VerifierTrustAnchor)); err != nil {
		return fmt.Errorf("failed to add yivi staging verifier trust anchors: %v", err)
	}
	return nil
}

func (conf *Configuration) ResolveVerifierLogoPath(filename string) (string, error) {
	path := filepath.Join(conf.Verifiers.GetLogosPath(), filename)
	exists, err := common.PathExists(path)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("verifier logo %v not found", filename)
	}
	return path, nil
}

func (conf *Configuration) CacheVerifierLogo(filename string, logo *scheme.Logo) (fullFilename string, path string, err error) {
	if logo == nil || logo.Data == nil || len(logo.Data) == 0 {
		return "", "", fmt.Errorf("invalid logo")
	}

	// Find a file-extension for the logo based on its MIME type
	extensions, err := mime.ExtensionsByType(logo.MimeType)
	if err != nil {
		return "", "", err
	}

	if len(extensions) == 0 {
		return "", "", fmt.Errorf("unknown mime type %q", logo.MimeType)
	}

	fullFilename = filename + extensions[0]
	path = filepath.Join(conf.Verifiers.GetLogosPath(), fullFilename)

	// If file exists, overwrite it, as it might have updated between certificate issuances
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", "", fmt.Errorf("failed to open file %s: %w", path, err)
	}

	defer func() {
		if file != nil {
			if cerr := file.Close(); err == nil && cerr != nil {
				err = cerr
			}
		}
	}()

	_, err = file.Write(logo.Data)
	if err != nil {
		return "", "", err
	}

	return
}

func (conf *Configuration) UpdateCertificateRevocationLists() error {
	var wg sync.WaitGroup
	wg.Add(2)

	go updateWorker(conf.Issuers.syncCertificateRevocationLists, &wg)
	go updateWorker(conf.Verifiers.syncCertificateRevocationLists, &wg)

	wg.Wait()

	// TODO: implement locking on the config to pause/start the job.
	// We should not update if we are in the middle of handling a session, because it might disrupt the session.
	return conf.Reload()
}

func updateWorker(worker func(), wg *sync.WaitGroup) {
	defer wg.Done()
	worker()
}
