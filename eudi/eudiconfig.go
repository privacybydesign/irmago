package eudi

import (
	"fmt"
	"mime"
	"net/http"
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

	Issuers   TrustModel
	Verifiers TrustModel
}

// NewConfiguration returns a new configuration. After this ParseFolder() should be called to parse the specified path.
func NewConfiguration(path string) (conf *Configuration, err error) {
	httpClient := &http.Client{}

	conf = &Configuration{
		path: path,
		Issuers: TrustModel{
			basePath:   filepath.Join(path, "issuers"),
			logger:     common.Logger,
			httpClient: httpClient,
		},
		Verifiers: TrustModel{
			basePath:   filepath.Join(path, "verifiers"),
			logger:     common.Logger,
			httpClient: httpClient,
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

	err = conf.Reload()

	return
}

// Reload assumes the latest files (trust anchors and certificate revocation lists) are downloaded.
// Reload (re)populates the Configuration by loading the pinned trust anchors, followed by the downloaded ones.
// Intermediate certificates are checked against the revocation list of the root certificates befor being added to the trust model.
func (conf *Configuration) Reload() error {
	conf.Issuers.clear()
	conf.Verifiers.clear()

	// Read the hardcoded trust anchors
	conf.Issuers.addTrustAnchors([]byte(DefaultIssuerTrustAnchor_YiviStaging))
	conf.Verifiers.addTrustAnchors([]byte(DefaultVerifierTrustAnchor_YiviStaging))

	// Read the trust anchors from storage
	err := conf.Issuers.loadTrustChains()
	if err != nil {
		return err
	}

	return conf.Verifiers.loadTrustChains()
}

func (conf *Configuration) CacheVerifierLogo(filename string, logo *Logo) (fullFilename string, path string, err error) {
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
