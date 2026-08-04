package db

import (
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"gorm.io/gorm"
)

type trustListStore struct {
	db *gorm.DB
}

// NewTrustListStore returns a lote.Store backed by the trust_list_documents
// table. Returning the interface (not the concrete type) lets the wallet treat
// the persistent store and lote's in-memory one interchangeably.
func NewTrustListStore(db *gorm.DB) lote.Store {
	return &trustListStore{db: db}
}

// Get implements [lote.Store]. Any read failure reads as a miss: the caller
// re-fetches, and the interface has nowhere to report an error to.
func (s *trustListStore) Get(listId string) ([]byte, bool) {
	if listId == "" {
		return nil, false
	}
	var row models.TrustListDocument
	if err := s.db.First(&row, "list_id = ?", listId).Error; err != nil {
		return nil, false
	}
	return row.RawJws, true
}

// Put implements [lote.Store].
func (s *trustListStore) Put(listId string, rawJws []byte) error {
	if listId == "" {
		return fmt.Errorf("trust_list_documents: empty list id")
	}
	if len(rawJws) == 0 {
		return fmt.Errorf("trust_list_documents: empty document")
	}
	return s.db.Save(&models.TrustListDocument{
		ListId:    listId,
		RawJws:    rawJws,
		FetchedAt: time.Now(),
	}).Error
}
