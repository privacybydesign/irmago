package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/gorm"
)

type statusListCacheStore struct {
	db *gorm.DB
}

// NewStatusListCacheStore returns a statuslist.Cache backed by the
// status_list_cache table. Returning the interface (not the concrete
// type) lets the wallet client treat the persistent store and the
// in-memory test cache interchangeably.
func NewStatusListCacheStore(db *gorm.DB) statuslist.Cache {
	return &statusListCacheStore{db: db}
}

func (s *statusListCacheStore) Get(uri string) ([]byte, time.Time, bool) {
	if uri == "" {
		return nil, time.Time{}, false
	}
	var row models.StatusListCacheEntry
	err := s.db.First(&row, "uri = ?", uri).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, time.Time{}, false
		}
		// Anything else (locked DB, schema mismatch) — treat as a
		// miss so the caller re-fetches. We can't surface an error
		// through the interface contract here.
		return nil, time.Time{}, false
	}
	return row.RawJwt, row.ExpiresAt, true
}

func (s *statusListCacheStore) Put(uri string, rawJwt []byte, expiresAt time.Time) error {
	if uri == "" {
		return fmt.Errorf("status_list_cache: empty uri")
	}
	if len(rawJwt) == 0 {
		return fmt.Errorf("status_list_cache: empty rawJwt")
	}
	row := models.StatusListCacheEntry{
		URI:       uri,
		RawJwt:    rawJwt,
		ExpiresAt: expiresAt,
		FetchedAt: time.Now(),
	}
	// Upsert: if the URI exists, overwrite RawJwt/ExpiresAt/FetchedAt.
	return s.db.Save(&row).Error
}

func (s *statusListCacheStore) Delete(uri string) error {
	if uri == "" {
		return nil
	}
	return s.db.Delete(&models.StatusListCacheEntry{}, "uri = ?", uri).Error
}
