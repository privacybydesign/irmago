package lote

import (
	"sync"
	"time"
)

// StoredList is a persisted copy of one recognized list.
type StoredList struct {
	// Raw is the signed list exactly as it was fetched. The signature is
	// re-checked against the current anchors on every read, rather than the
	// decoded content being trusted because an earlier run believed it.
	Raw []byte
	// SequenceNumber is the revision this copy carries, kept alongside the raw
	// bytes so the rollback check does not have to verify the stored copy first.
	SequenceNumber int64
	// NextUpdate is when this copy stops counting.
	NextUpdate time.Time
}

// Store persists fetched lists across restarts, keyed by list identifier. The
// wallet backs it with its database; a relying party or a test can use
// NewInMemoryStore.
type Store interface {
	// Get returns the stored copy of the list, or (nil, nil) when there is
	// none.
	Get(listId string) (*StoredList, error)
	// Put replaces the stored copy of the list.
	Put(listId string, list *StoredList) error
}

// inMemoryStore keeps lists for the lifetime of the process.
type inMemoryStore struct {
	mu    sync.RWMutex
	lists map[string]StoredList
}

// NewInMemoryStore returns a Store that does not survive a restart. Safe for
// concurrent use.
func NewInMemoryStore() Store {
	return &inMemoryStore{lists: map[string]StoredList{}}
}

func (s *inMemoryStore) Get(listId string) (*StoredList, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list, ok := s.lists[listId]
	if !ok {
		return nil, nil
	}
	return &list, nil
}

func (s *inMemoryStore) Put(listId string, list *StoredList) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists[listId] = *list
	return nil
}
