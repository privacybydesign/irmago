package filesystem

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"

	"github.com/privacybydesign/irmago/internal/common"
)

const logosDirName = "logos"

type LogoManager interface {
	GetLogoFilenameWithoutExtensionFromUrl(url string) string
	SaveLogo(filename string, data []byte) (string, error)
	LogoExists(filename string) (bool, error)
	GetLogo(filename string) (*string, error)
	RemoveAll() error
}

type logoManager struct {
	fileManager
}

func newLogoManager(basePath string, internalStorage *fsStorage) LogoManager {
	path := filepath.Join(basePath, logosDirName)

	err := common.EnsureDirectoryExists(path)
	if err != nil {
		panic(err)
	}

	return &logoManager{
		fileManager: fileManager{
			basePath:        path,
			internalStorage: internalStorage,
		},
	}
}

// SaveLogo saves the provided logo data to the filesystem, using a filename derived from the provided base filename and the MIME type of the logo.
// The baseFilename should be the filename without extension, as the extension will be determined based on the MIME type of the logo data.
// It returns the full filepath of the saved logo file, or an error if the operation fails.
func (s *logoManager) SaveLogo(filename string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("invalid logo: data cannot be nil or empty")
	}

	filePath := filepath.Join(s.basePath, filename)

	// If file exists, overwrite it, as it might have updated between certificate issuances
	err := s.internalStorage.writeFile(filePath, data)
	if err != nil {
		return "", fmt.Errorf("failed to save logo file: %v", err)
	}

	return filePath, nil
}

// GetLogo reads the logo file with the given filename from the filesystem and returns its base64 encoded data.
func (s *logoManager) GetLogo(filename string) (*string, error) {
	filePath := filepath.Join(s.basePath, filename)

	data, err := s.internalStorage.readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read logo file: %v", err)
	}

	encodedData := base64.StdEncoding.EncodeToString(data)
	return &encodedData, nil
}

func (s *logoManager) LogoExists(filename string) (bool, error) {
	filePath := filepath.Join(s.basePath, filename)
	return s.internalStorage.fileExists(filePath)
}

func (s *logoManager) GetLogoFilenameWithoutExtensionFromUrl(url string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(url)))
}
