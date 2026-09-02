package walletconfig

import (
	"slices"
	"sync"
)

// Store persists signed configs across restarts, one per environment, so a
// wallet that starts offline still knows who is trusted. What is stored is the
// signed document, re-verified against the environment's root when it is read,
// so a document that no longer verifies is dropped rather than trusted.
//
// A store never reports read errors: an unreadable document is a miss, which is
// the same outcome as never having held one — the bundled config or a fetch
// fills the gap.
type Store interface {
	Get(environment string) (raw []byte, ok bool)
	Put(environment string, raw []byte) error
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

func (s *MemoryStore) Get(environment string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.documents[environment]
	return slices.Clone(raw), ok
}

func (s *MemoryStore) Put(environment string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[environment] = slices.Clone(raw)
	return nil
}
