package filesystem

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/privacybydesign/irmago/internal/common"
)

const crlsDirName = "crls"

type CertificateRevocationListManager interface {
	CrlExists(filename string) (bool, error)
	Save(crl *x509.RevocationList, fileName string) error
	ReadFromFileName(filename string) (*x509.RevocationList, error)
	RemoveByFileName(filename string) error
	GetAllFileNames() ([]string, error)
	RemoveAll() error
}

type certificateRevocationListManager struct {
	fileManager
}

func newCertificateRevocationListManager(basePath string, internalStorage *fsStorage) CertificateRevocationListManager {
	path := filepath.Join(basePath, crlsDirName)

	err := common.EnsureDirectoryExists(path)
	if err != nil {
		panic(err)
	}

	return &certificateRevocationListManager{
		fileManager: fileManager{
			basePath:        path,
			internalStorage: internalStorage,
		},
	}
}

func (s *certificateRevocationListManager) CrlExists(filename string) (bool, error) {
	crlFilePath := filepath.Join(s.basePath, filename)
	return s.internalStorage.fileExists(crlFilePath)
}

func (s *certificateRevocationListManager) Save(crl *x509.RevocationList, fileName string) error {
	if crl == nil {
		return fmt.Errorf("invalid CRL: crl cannot be nil")
	}

	if !strings.Contains(fileName, ".crl") {
		return fmt.Errorf("invalid CRL: fileName must have .crl extension")
	}

	// Determine filename (hash cert subject + hash dist point) + filepath
	filePath := filepath.Join(s.basePath, fileName)

	return s.internalStorage.writeFile(filePath, crl.Raw)
}

func (s *certificateRevocationListManager) ReadFromFileName(filename string) (*x509.RevocationList, error) {
	fullPath := filepath.Join(s.basePath, filename)
	return s.read(fullPath)
}

func (s *certificateRevocationListManager) read(filePath string) (*x509.RevocationList, error) {
	crlBytes, err := s.internalStorage.readFile(filePath)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, err
	}

	return crl, nil
}

func (s *certificateRevocationListManager) GetAllFileNames() ([]string, error) {
	filePaths, err := filepath.Glob(filepath.Join(s.basePath, "*.crl"))
	if err != nil {
		return nil, err
	}

	fileNames := make([]string, len(filePaths))
	for i, filePath := range filePaths {
		fileNames[i] = filepath.Base(filePath)
	}
	return fileNames, nil
}

func GetCrlFileNameForCertDistributionPoint(distPoint string) string {
	return fmt.Sprintf("%x.crl", sha256.Sum256([]byte(distPoint)))
}

func (s *certificateRevocationListManager) RemoveByFileName(filename string) error {
	filePath := filepath.Join(s.basePath, filename)
	return os.Remove(filePath)
}
