package filesystem

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
)

const certificatesDirName = "certificates"

type CertificateManager interface {
	InstallCertificate(pemData []byte) error
	RemoveCertificate(thumbprint string) error
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

	// Create a filename based on the signature of the 'leaf' certificate in this chain.
	// Chains are expected in leaf-to-root order, so the leaf is the first element.
	filename := fmt.Sprintf("%x.pem", certChain[0].Signature)
	fullPath := filepath.Join(s.basePath, filename)

	err = s.internalStorage.writeFile(fullPath, pemData)
	if err != nil {
		return fmt.Errorf("failed to write certificate file: %v", err)
	}

	return nil
}

// RemoveCertificate removes the installed certificate chain whose leaf
// certificate signature (hex-encoded) matches the given thumbprint, i.e. the
// inverse of InstallCertificate, which names the chain's file after the leaf
// signature.
func (s *certificateManager) RemoveCertificate(thumbprint string) error {
	if thumbprint == "" {
		return fmt.Errorf("no thumbprint provided")
	}

	// The thumbprint doubles as the filename, so only accept plain hex to
	// make path traversal outside the certificates directory impossible.
	if _, err := hex.DecodeString(thumbprint); err != nil {
		return fmt.Errorf("invalid thumbprint: %v", err)
	}

	fullPath := filepath.Join(s.basePath, strings.ToLower(thumbprint)+".pem")
	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no certificate found with thumbprint %s", thumbprint)
		}
		return fmt.Errorf("failed to remove certificate file: %v", err)
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
