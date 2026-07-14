package filesystem

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
)

const crlsDirName = "crls"

// crlExtension is appended to the on-disk hex filename. It's not part of the
// HMAC input — it lives on disk only so the directory can be globbed by
// extension if ever needed externally.
const crlExtension = ".crl"

// CertificateRevocationListManager stores CRLs keyed by their distribution
// point URL. On-disk filenames are HMAC-SHA256 hex of the distribution point
// (under an AES-derived sub-key) suffixed with .crl.
type CertificateRevocationListManager interface {
	Save(crl *x509.RevocationList, distPoint string) error
	Read(distPoint string) (*x509.RevocationList, error)
	Exists(distPoint string) (bool, error)
	Remove(distPoint string) error

	// LoadAll iterates every CRL on disk, parses each, and returns the parsed
	// list. When onError is non-nil, per-file failures (read, decrypt, parse)
	// are surfaced to the callback and iteration continues; when onError is
	// nil, the first such failure aborts and is returned as the function's
	// error.
	LoadAll(onError func(err error)) ([]*x509.RevocationList, error)

	RemoveAll() error
}

type certificateRevocationListManager struct {
	scope *scopedFS
}

func newCertificateRevocationListManager(basePath string, internalStorage *fsStorage) CertificateRevocationListManager {
	return &certificateRevocationListManager{
		scope: internalStorage.Scope(filepath.Join(basePath, crlsDirName)),
	}
}

func (s *certificateRevocationListManager) Save(crl *x509.RevocationList, distPoint string) error {
	if crl == nil {
		return fmt.Errorf("invalid CRL: crl cannot be nil")
	}
	return s.scope.Write(distPoint, crlExtension, crl.Raw)
}

func (s *certificateRevocationListManager) Read(distPoint string) (*x509.RevocationList, error) {
	bytes, err := s.scope.Read(distPoint, crlExtension)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(bytes)
}

func (s *certificateRevocationListManager) Exists(distPoint string) (bool, error) {
	return s.scope.Exists(distPoint, crlExtension)
}

func (s *certificateRevocationListManager) Remove(distPoint string) error {
	return s.scope.Delete(distPoint, crlExtension)
}

func (s *certificateRevocationListManager) LoadAll(onError func(err error)) ([]*x509.RevocationList, error) {
	var crls []*x509.RevocationList
	err := s.scope.Walk(func(data []byte) error {
		crl, err := x509.ParseRevocationList(data)
		if err != nil {
			return fmt.Errorf("parse crl: %w", err)
		}
		crls = append(crls, crl)
		return nil
	}, onError)
	return crls, err
}

func (s *certificateRevocationListManager) RemoveAll() error {
	return s.scope.RemoveAll()
}
