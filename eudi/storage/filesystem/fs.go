package filesystem

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"golang.org/x/crypto/hkdf"
)

// fsFilenameKeyHkdfInfo is the HKDF info string used to derive the filename-MAC
// key from the AES storage key. Bumping the version suffix produces an entirely
// new keyspace without touching the AES key.
const fsFilenameKeyHkdfInfo = "irmago-fs-filename-v1"

type fileManager struct {
	basePath        string
	internalStorage *fsStorage
}

// RemoveAll removes all files and subdirectories inside this manager's directory.
func (m *fileManager) RemoveAll() error {
	return removeDirectoryContents(m.basePath)
}

type FileSystemStorage interface {
	Credentials() FileSystemContainer
	Issuers() FileSystemContainer
	Verifiers() FileSystemContainer

	// RemoveAllFiles removes all files from all containers (logos, certificates, CRLs).
	RemoveAllFiles() error
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

// NewFileSystemStorage constructs the EUDI filesystem layer. It derives both
// the AES-GCM encryption middleware and the filename-MAC key from the provided
// AES key, so all on-disk filenames are HMAC-based and unrecoverable without
// the key.
func NewFileSystemStorage(aesKey [32]byte, basePath string) FileSystemStorage {
	if err := common.EnsureDirectoryExists(basePath); err != nil {
		panic(err)
	}

	middleware := encryption.NewAESEncryptionMiddleware(aesKey)
	fsFilenameKey := deriveFSFilenameKey(aesKey)

	storage := newFsStorage(middleware, fsFilenameKey)

	return &fileSystemStorage{
		credentialsContainer: *newFileSystemContainer(storage, filepath.Join(basePath, "credentials")),
		issuersContainer:     *newFileSystemContainer(storage, filepath.Join(basePath, "issuers")),
		verifiersContainer:   *newFileSystemContainer(storage, filepath.Join(basePath, "verifiers")),
	}
}

func deriveFSFilenameKey(aesKey [32]byte) [32]byte {
	r := hkdf.New(sha256.New, aesKey[:], nil, []byte(fsFilenameKeyHkdfInfo))
	var key [32]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic(fmt.Sprintf("hkdf expand failed: %v", err))
	}
	return key
}

// newFileSystemContainer creates a new instance of FileSystemContainer.
func newFileSystemContainer(storage *fsStorage, basePath string) *FileSystemContainer {
	if err := common.EnsureDirectoryExists(basePath); err != nil {
		panic(err)
	}

	return &FileSystemContainer{
		logoManager:                      newLogoManager(basePath, storage),
		certificateManager:               newCertificateManager(basePath, storage),
		certificateRevocationListManager: newCertificateRevocationListManager(basePath, storage),
	}
}

func (s *fileSystemStorage) RemoveAllFiles() error {
	for _, c := range []FileSystemContainer{s.credentialsContainer, s.issuersContainer, s.verifiersContainer} {
		if err := c.logoManager.RemoveAll(); err != nil {
			return err
		}
		if err := c.certificateManager.RemoveAll(); err != nil {
			return err
		}
		if err := c.certificateRevocationListManager.RemoveAll(); err != nil {
			return err
		}
	}
	return nil
}

// removeDirectoryContents removes all files and subdirectories inside a directory
// without removing the directory itself.
func removeDirectoryContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("failed to remove %s: %w", entry.Name(), err)
		}
	}
	return nil
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
	fsFilenameKey        [32]byte
}

func newFsStorage(middleware encryption.EncryptionMiddleware, fsFilenameKey [32]byte) *fsStorage {
	return &fsStorage{
		encryptionMiddleware: middleware,
		fsFilenameKey:        fsFilenameKey,
	}
}

// Scope returns a scoped filesystem handle rooted at the given absolute
// directory. The directory is created if it does not exist. The handle
// exposes write/read/exists/delete/walk operations that take a logical name;
// the on-disk filename is HMAC-SHA256(fsFilenameKey, name) hex-encoded, so no
// plaintext key ever lands on disk.
func (s *fsStorage) Scope(fullPath string) *scopedFS {
	if err := common.EnsureDirectoryExists(fullPath); err != nil {
		panic(err)
	}
	return &scopedFS{parent: s, fullPath: fullPath}
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

	if _, err := out.Write(encryptedData); err != nil {
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

// scopedFS is a filesystem handle bound to a fixed directory. All names passed
// to its methods are logical keys (URLs, distribution points, IDs); the on-disk
// filename is derived via HMAC and never exposed to callers.
type scopedFS struct {
	parent   *fsStorage
	fullPath string
}

func (s *scopedFS) hashName(name string) string {
	mac := hmac.New(sha256.New, s.parent.fsFilenameKey[:])
	mac.Write([]byte(name))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *scopedFS) absPath(name, ext string) string {
	return filepath.Join(s.fullPath, s.hashName(name)+ext)
}

func (s *scopedFS) Write(name, ext string, data []byte) error {
	return s.parent.writeFile(s.absPath(name, ext), data)
}

func (s *scopedFS) Read(name, ext string) ([]byte, error) {
	return s.parent.readFile(s.absPath(name, ext))
}

func (s *scopedFS) Exists(name, ext string) (bool, error) {
	return s.parent.fileExists(s.absPath(name, ext))
}

func (s *scopedFS) Delete(name, ext string) error {
	return os.Remove(s.absPath(name, ext))
}

func (s *scopedFS) RemoveAll() error {
	return removeDirectoryContents(s.fullPath)
}

// Walk reads every regular file in the scope, decrypts it, and calls fn with
// the plaintext bytes. Per-file failures (read, decrypt, or fn returning
// non-nil) are passed to onError when it is non-nil and iteration continues;
// when onError is nil, the first such failure aborts the walk.
func (s *scopedFS) Walk(fn func(data []byte) error, onError func(err error)) error {
	entries, err := os.ReadDir(s.fullPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(s.fullPath, entry.Name())
		data, err := s.parent.readFile(path)
		if err != nil {
			if onError == nil {
				return err
			}
			onError(err)
			continue
		}
		if err := fn(data); err != nil {
			if onError == nil {
				return err
			}
			onError(err)
			continue
		}
	}
	return nil
}
