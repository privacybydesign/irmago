package models

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// KbJwtReplayEntry stores used KB-JWT digests to prevent proof replay.
type KbJwtReplayEntry struct {
	Digest    string    `gorm:"primaryKey;type:text"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

func (e *KbJwtReplayEntry) BeforeCreate(tx *gorm.DB) error {
	if e.Digest == "" {
		return fmt.Errorf("digest is required")
	}
	if e.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at is required")
	}
	e.CreatedAt = time.Now().UTC()
	e.ExpiresAt = e.ExpiresAt.UTC()
	return nil
}
