package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/gorm"
)

// KbJwtReplayStore persists KB-JWT replay state across process restarts.
type KbJwtReplayStore interface {
	StoreDigest(digest string, expiresAt time.Time) error
	ExistsDigest(digest string) (bool, error)
	DeleteExpired(referenceTime time.Time) error
	DeleteAll() error
}

type kbJwtReplayStore struct {
	db *gorm.DB
}

func NewKbJwtReplayStore(db *gorm.DB) KbJwtReplayStore {
	return &kbJwtReplayStore{db: db}
}

func (s *kbJwtReplayStore) StoreDigest(digest string, expiresAt time.Time) error {
	if digest == "" {
		return fmt.Errorf("digest is required")
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("expires_at is required")
	}

	entry := &models.KbJwtReplayEntry{Digest: digest, ExpiresAt: expiresAt.UTC()}
	if err := s.db.Create(entry).Error; err != nil {
		return err
	}
	return nil
}

func (s *kbJwtReplayStore) ExistsDigest(digest string) (bool, error) {
	if digest == "" {
		return false, fmt.Errorf("digest is required")
	}

	var count int64
	err := s.db.Model(&models.KbJwtReplayEntry{}).Where("digest = ?", digest).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *kbJwtReplayStore) DeleteExpired(referenceTime time.Time) error {
	if referenceTime.IsZero() {
		return fmt.Errorf("reference_time is required")
	}

	return s.db.Where("expires_at < ?", referenceTime.UTC()).Delete(&models.KbJwtReplayEntry{}).Error
}

func (s *kbJwtReplayStore) DeleteAll() error {
	return s.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.KbJwtReplayEntry{}).Error
}

func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := err.Error()
	return msg != "" && (contains(msg, "UNIQUE constraint failed") || contains(msg, "duplicate key"))
}

func contains(s string, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (indexOf(s, substr) >= 0)
}

func indexOf(s string, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
