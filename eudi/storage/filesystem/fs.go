package filesystem

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
)

type fileManager struct {
	basePath        string
	internalStorage *fsStorage
}

type FileSystemStorage interface {
	Credentials() FileSystemContainer
	Issuers() FileSystemContainer
	Verifiers() FileSystemContainer
}

type fileSystemStorage struct {
	credentialsContainer FileSystemContainer
	issuersContainer     FileSystemContainer
	verifiersContainer   FileSystemContainer
}

type FileSystemContainer struct {
	logoManager                      LogoManager
	certificateManager               CertificateManager
	certificateRevocationListManager CertificateRevocationListManager
}

func NewFileSystemStorage(encryptionMiddleware encryption.EncryptionMiddleware, basePath string) FileSystemStorage {
	err := common.EnsureDirectoryExists(basePath)
	if err != nil {
		panic(err)
	}

	storageMiddleware := NewStorageMiddleware(encryptionMiddleware)

	return &fileSystemStorage{
		credentialsContainer: *newFileSystemContainer(storageMiddleware, filepath.Join(basePath, "credentials")),
		issuersContainer:     *newFileSystemContainer(storageMiddleware, filepath.Join(basePath, "issuers")),
		verifiersContainer:   *newFileSystemContainer(storageMiddleware, filepath.Join(basePath, "verifiers")),
	}
}

// newFileSystemContainer creates a new instance of FileSystemContainer.
func newFileSystemContainer(storageMiddleware *fsStorage, basePath string) *FileSystemContainer {
	err := common.EnsureDirectoryExists(basePath)
	if err != nil {
		panic(err)
	}

	return &FileSystemContainer{
		logoManager:                      newLogoManager(basePath, storageMiddleware),
		certificateManager:               newCertificateManager(basePath, storageMiddleware),
		certificateRevocationListManager: newCertificateRevocationListManager(basePath, storageMiddleware),
	}
}

func (s *fileSystemStorage) Credentials() FileSystemContainer {
	return s.credentialsContainer
}

func (s *fileSystemStorage) Issuers() FileSystemContainer {
	return s.issuersContainer
}

func (s *fileSystemStorage) Verifiers() FileSystemContainer {
	return s.verifiersContainer
}

func (s FileSystemContainer) CertificateManager() CertificateManager {
	return s.certificateManager
}

func (s FileSystemContainer) CertificateRevocationListManager() CertificateRevocationListManager {
	return s.certificateRevocationListManager
}

func (s FileSystemContainer) LogoManager() LogoManager {
	return s.logoManager
}

type fsStorage struct {
	encryptionMiddleware encryption.EncryptionMiddleware
}

func NewStorageMiddleware(encryptionMiddleware encryption.EncryptionMiddleware) *fsStorage {
	return &fsStorage{
		encryptionMiddleware: encryptionMiddleware,
	}
}

func (s *fsStorage) writeFile(filePath string, data []byte) error {
	encryptedData, err := s.encryptionMiddleware.Encrypt(data)
	if err != nil {
		return err
	}

	out, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file on disk: %v", err)
	}
	defer out.Close()

	// Write the body to file
	_, err = out.Write(encryptedData)
	if err != nil {
		return fmt.Errorf("error saving file content: %v", err)
	}

	return nil
}

func (s *fsStorage) readFile(filename string) ([]byte, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return s.encryptionMiddleware.Decrypt(encryptedData)
}

func (s *fsStorage) fileExists(filename string) (bool, error) {
	_, err := os.Stat(filename)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
