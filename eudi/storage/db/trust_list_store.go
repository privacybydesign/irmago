package db

import (
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/gorm"
)

// TrustListStore persists signed trust list documents in the
// trust_list_documents table. It satisfies lote.Store structurally, which is how
// the wallet hands it to the LoTE checker; naming that interface here would make
// this package depend on the trust packages and, through them, on all of eudi.
type TrustListStore struct {
	db *gorm.DB
}

func NewTrustListStore(db *gorm.DB) *TrustListStore {
	return &TrustListStore{db: db}
}

// Get implements lote.Store. Any read failure reads as a miss: the caller
// re-fetches, and the interface has nowhere to report an error to.
func (s *TrustListStore) Get(listId string) ([]byte, bool) {
	if listId == "" {
		return nil, false
	}
	var row models.TrustListDocument
	if err := s.db.First(&row, "list_id = ?", listId).Error; err != nil {
		return nil, false
	}
	return row.RawJws, true
}

func (s *TrustListStore) Put(listId string, rawJws []byte) error {
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
