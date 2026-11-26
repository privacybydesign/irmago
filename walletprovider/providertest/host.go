// Package providertest holds test doubles for the walletprovider contract —
// an in-memory Host and a software PossessionKey — and the conformance suite
// every provider must pass.
package providertest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"maps"
	"sync"

	"github.com/privacybydesign/irmago/walletprovider"
)

// Host is an in-memory walletprovider.Host.
type Host struct {
	storage *MemoryStorage
}

// NewHost returns a host with empty storage.
func NewHost() *Host {
	return &Host{storage: NewMemoryStorage()}
}

func (h *Host) Storage() walletprovider.Storage { return h.storage }

// MemoryStorage is an in-memory walletprovider.Storage.
type MemoryStorage struct {
	mu     sync.Mutex
	values map[string][]byte
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{values: map[string][]byte{}}
}

func (s *MemoryStorage) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	if !ok {
		return nil, walletprovider.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (s *MemoryStorage) Update(fn func(tx walletprovider.StorageTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx := &memoryTx{values: maps.Clone(s.values)}
	if err := fn(tx); err != nil {
		return err
	}
	s.values = tx.values
	return nil
}

type memoryTx struct {
	values map[string][]byte
}

func (tx *memoryTx) Get(key string) ([]byte, error) {
	v, ok := tx.values[key]
	if !ok {
		return nil, walletprovider.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (tx *memoryTx) Put(key string, value []byte) error {
	tx.values[key] = append([]byte(nil), value...)
	return nil
}

func (tx *memoryTx) Delete(key string) error {
	delete(tx.values, key)
	return nil
}

// SoftwarePossessionKey is a walletprovider.PossessionKey whose private key
// lives in memory. It produces no key attestation and "open" app attestation
// consisting of the challenge itself.
type SoftwarePossessionKey struct {
	mu  sync.Mutex
	key *ecdsa.PrivateKey
}

func (k *SoftwarePossessionKey) Create(_ context.Context, _ []byte) (*ecdsa.PublicKey, [][]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.key = key
	return &key.PublicKey, nil, nil
}

func (k *SoftwarePossessionKey) PublicKey() (*ecdsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil, walletprovider.ErrNotFound
	}
	return &k.key.PublicKey, nil
}

func (k *SoftwarePossessionKey) SignDigest(digest []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.key == nil {
		return nil, walletprovider.ErrNotFound
	}
	return ecdsa.SignASN1(rand.Reader, k.key, digest)
}

func (k *SoftwarePossessionKey) AppAttestation(_ context.Context, challenge []byte) (string, []byte, error) {
	return "open", append([]byte(nil), challenge...), nil
}

func (k *SoftwarePossessionKey) Delete() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.key = nil
	return nil
}
