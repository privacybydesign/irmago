package db

import (
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/gorm"
)

// EudiLogStore persists and retrieves EUDI activity log entries.
type EudiLogStore interface {
	AddLog(entry *models.EudiLogEntry) error
	GetNewestLogs(max int) ([]*models.EudiLogEntry, error)
	GetLogsBefore(before *models.EudiLogEntry, max int) ([]*models.EudiLogEntry, error)
	DeleteAll() error
}

type eudiLogStore struct {
	db *gorm.DB
}

func NewEudiLogStore(db *gorm.DB) EudiLogStore {
	return &eudiLogStore{db: db}
}

func (s *eudiLogStore) AddLog(entry *models.EudiLogEntry) error {
	return s.db.Create(entry).Error
}

func (s *eudiLogStore) GetNewestLogs(max int) ([]*models.EudiLogEntry, error) {
	var entries []*models.EudiLogEntry
	err := s.db.
		Preload("Credentials").
		Order("created_at DESC").
		Limit(max).
		Find(&entries).Error
	return entries, err
}

func (s *eudiLogStore) GetLogsBefore(before *models.EudiLogEntry, max int) ([]*models.EudiLogEntry, error) {
	var entries []*models.EudiLogEntry
	err := s.db.
		Preload("Credentials").
		Where("created_at < ?", before.CreatedAt).
		Order("created_at DESC").
		Limit(max).
		Find(&entries).Error
	return entries, err
}

func (s *eudiLogStore) DeleteAll() error {
	return s.db.Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&models.EudiLogEntry{}).Error
}
