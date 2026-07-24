package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
)

const logosDirName = "logos"

// LogoManager stores per-container (credentials/issuers/verifiers) logo images
// keyed by an opaque logical key — the logo URL when retrieved from credential
// metadata, or the issuer/credential/requestor ID when persisted from log
// entries. On-disk filenames are HMAC-SHA256 hex of the key under an
// AES-derived sub-key, so plaintext keys are never written to disk.
//
// The MIME type (needed by the wallet to distinguish SVG from bitmap logos)
// is stored in a sidecar file next to the image data. An empty mimeType is
// valid: Save then removes any stale sidecar and Get returns "".
type LogoManager interface {
	Save(key string, data []byte, mimeType string) error
	Get(key string) (data []byte, mimeType string, err error)
	Exists(key string) (bool, error)
	RemoveAll() error
}

// mimeTypeExt is the filename suffix of the MIME type sidecar file.
const mimeTypeExt = ".mime"

type logoManager struct {
	scope *scopedFS
}

func newLogoManager(basePath string, internalStorage *fsStorage) LogoManager {
	return &logoManager{
		scope: internalStorage.Scope(filepath.Join(basePath, logosDirName)),
	}
}

func (s *logoManager) Save(key string, data []byte, mimeType string) error {
	if key == "" {
		return fmt.Errorf("invalid logo: key cannot be empty")
	}
	if len(data) == 0 {
		return fmt.Errorf("invalid logo: data cannot be nil or empty")
	}
	if err := s.scope.Write(key, "", data); err != nil {
		return err
	}
	if mimeType == "" {
		// Remove any sidecar left by a previous Save so the MIME type
		// can't go stale relative to the image data.
		if err := s.scope.Delete(key, mimeTypeExt); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return s.scope.Write(key, mimeTypeExt, []byte(mimeType))
}

func (s *logoManager) Get(key string) ([]byte, string, error) {
	data, err := s.scope.Read(key, "")
	if err != nil {
		return nil, "", err
	}
	// Logos saved before MIME types were recorded have no sidecar;
	// treat that as an unknown MIME type rather than an error.
	exists, err := s.scope.Exists(key, mimeTypeExt)
	if err != nil || !exists {
		return data, "", nil
	}
	mimeType, err := s.scope.Read(key, mimeTypeExt)
	if err != nil {
		return data, "", nil
	}
	return data, string(mimeType), nil
}

func (s *logoManager) Exists(key string) (bool, error) {
	return s.scope.Exists(key, "")
}

func (s *logoManager) RemoveAll() error {
	return s.scope.RemoveAll()
}
