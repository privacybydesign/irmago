package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/lote"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/gorm"
)

type recognizedListStore struct {
	db *gorm.DB
}

// NewRecognizedListStore returns a lote.Store backed by the
// recognized_trust_list_entries table. Returning the interface lets the wallet
// treat the persistent store and the in-memory one interchangeably.
func NewRecognizedListStore(db *gorm.DB) lote.Store {
	return &recognizedListStore{db: db}
}

func (s *recognizedListStore) Get(listId string) (*lote.StoredList, error) {
	if listId == "" {
		return nil, nil
	}
	var row models.RecognizedTrustListEntry
	if err := s.db.First(&row, "list_id = ?", listId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &lote.StoredList{
		Raw:            row.RawJws,
		SequenceNumber: row.SequenceNumber,
		NextUpdate:     row.NextUpdate,
	}, nil
}

func (s *recognizedListStore) Put(listId string, list *lote.StoredList) error {
	if listId == "" {
		return fmt.Errorf("recognized_trust_list: empty list id")
	}
	if list == nil || len(list.Raw) == 0 {
		return fmt.Errorf("recognized_trust_list: empty list")
	}
	// Upsert: a list has one row, which every refresh overwrites.
	return s.db.Save(&models.RecognizedTrustListEntry{
		ListId:         listId,
		RawJws:         list.Raw,
		SequenceNumber: list.SequenceNumber,
		NextUpdate:     list.NextUpdate,
		FetchedAt:      time.Now(),
	}).Error
}
