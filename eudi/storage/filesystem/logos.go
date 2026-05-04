package filesystem

import (
	"fmt"
	"path/filepath"
)

const logosDirName = "logos"

// LogoManager stores per-container (credentials/issuers/verifiers) logo images
// keyed by an opaque logical key — the logo URL when retrieved from credential
// metadata, or the issuer/credential/requestor ID when persisted from log
// entries. On-disk filenames are HMAC-SHA256 hex of the key under an
// AES-derived sub-key, so plaintext keys are never written to disk.
type LogoManager interface {
	Save(key string, data []byte) error
	Get(key string) ([]byte, error)
	Exists(key string) (bool, error)
	RemoveAll() error
}

type logoManager struct {
	scope *scopedFS
}

func newLogoManager(basePath string, internalStorage *fsStorage) LogoManager {
	return &logoManager{
		scope: internalStorage.Scope(filepath.Join(basePath, logosDirName)),
	}
}

func (s *logoManager) Save(key string, data []byte) error {
	if key == "" {
		return fmt.Errorf("invalid logo: key cannot be empty")
	}
	if len(data) == 0 {
		return fmt.Errorf("invalid logo: data cannot be nil or empty")
	}
	return s.scope.Write(key, "", data)
}

func (s *logoManager) Get(key string) ([]byte, error) {
	return s.scope.Read(key, "")
}

func (s *logoManager) Exists(key string) (bool, error) {
	return s.scope.Exists(key, "")
}

func (s *logoManager) RemoveAll() error {
	return s.scope.RemoveAll()
}
