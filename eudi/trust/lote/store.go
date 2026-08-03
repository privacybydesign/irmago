package lote

import "sync"

// Store persists the signed list documents across restarts, so a wallet that
// starts up offline still knows who is on a recognized list.
//
// What is stored is the signed document, not the parsed content: it is
// re-verified against the anchors in force at the time it is read, so a signing
// certificate that has since been revoked invalidates the lists already on
// disk rather than only the next download.
//
// A store never reports read errors. An unreadable document is a miss, which
// costs a fetch and, offline, one degradation to low — the same outcome as
// never having held the list, and not something a caller could act on.
type Store interface {
	// Get returns the stored document for listId, or ok=false when there is
	// none.
	Get(listId string) (rawJws []byte, ok bool)

	// Put writes (or replaces) the document stored for listId.
	Put(listId string, rawJws []byte) error
}

// MemoryStore is a Store that keeps documents in memory only. It is the default
// when no store is configured, and it is what a caller that does not want the
// lists on disk passes deliberately. Safe for concurrent use.
type MemoryStore struct {
	mu        sync.RWMutex
	documents map[string][]byte
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{documents: map[string][]byte{}}
}

// Get implements [Store].
func (s *MemoryStore) Get(listId string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	raw, ok := s.documents[listId]
	return raw, ok
}

// Put implements [Store].
func (s *MemoryStore) Put(listId string, rawJws []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[listId] = rawJws
	return nil
}
