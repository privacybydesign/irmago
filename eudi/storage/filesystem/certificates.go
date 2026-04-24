package filesystem

import (
	"fmt"
	"path/filepath"

	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
)

const certificatesDirName = "certificates"

type CertificateManager interface {
	InstallCertificate(pemData []byte) error
	GetRawCertificates() ([][]byte, error)
	RemoveAll() error
}

type certificateManager struct {
	fileManager
}

func newCertificateManager(basePath string, internalStorage *fsStorage) CertificateManager {
	path := filepath.Join(basePath, certificatesDirName)

	err := common.EnsureDirectoryExists(path)
	if err != nil {
		panic(err)
	}

	return &certificateManager{
		fileManager: fileManager{
			basePath:        path,
			internalStorage: internalStorage,
		},
	}
}

func (s *certificateManager) InstallCertificate(pemData []byte) error {
	certChain, err := utils.ParsePemCertificateChain(pemData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate chain: %v", err)
	}

	if len(certChain) == 0 {
		return fmt.Errorf("no certificates found in provided data")
	}

	// Create a filename based on the signature of the 'leaf' certificate in this chain
	filename := fmt.Sprintf("%x.pem", certChain[len(certChain)-1].Signature)
	fullPath := filepath.Join(s.basePath, filename)

	err = s.internalStorage.writeFile(fullPath, pemData)
	if err != nil {
		return fmt.Errorf("failed to write certificate file: %v", err)
	}

	return nil
}

func (s *certificateManager) GetRawCertificates() ([][]byte, error) {
	chains, err := filepath.Glob(filepath.Join(s.basePath, "*.pem"))
	if err != nil {
		return nil, err
	}
	trustAnchors := make([][]byte, len(chains))
	for i, trustChainFile := range chains {
		bts, err := s.internalStorage.readFile(trustChainFile)
		if err != nil {
			return nil, err
		}
		trustAnchors[i] = bts
	}
	return trustAnchors, nil
}
