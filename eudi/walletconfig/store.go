package walletconfig

import (
	"slices"
	"sync"
)

// Store persists signed configs across restarts, filed under the config's id,
// so a wallet that starts offline still knows who is trusted. What is stored is
// the signed document, re-verified against the environment's root when it is
// read, so a document that no longer verifies is dropped rather than trusted.
//
// A store never reports read errors: an unreadable document is a miss, which is
// the same outcome as never having held one — the bundled config or a fetch
// fills the gap.
type Store interface {
	Get(configID string) (raw []byte, ok bool)
	Put(configID string, raw []byte) error
}

// MemoryStore is a Store that forgets on restart. The default when a Manager is
// given none, and what tests use.
type MemoryStore struct {
	mu        sync.Mutex
	documents map[string][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{documents: map[string][]byte{}}
}

func (s *MemoryStore) Get(configID string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.documents[configID]
	return slices.Clone(raw), ok
}

func (s *MemoryStore) Put(configID string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[configID] = slices.Clone(raw)
	return nil
}
