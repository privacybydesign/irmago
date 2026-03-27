package storage

import (
	"errors"

	"gorm.io/gorm"
)

// Common errors for storage operations.
var (
	ErrNotFound = errors.New("not found")
)

type Storage interface {
	Close() error
	Db() *gorm.DB
}
