package storage

import (
	"gorm.io/gorm"
)

type UnitOfWork interface {
	Do(fn func(tx *gorm.DB) error) error
	Storage() Storage
	HolderBindingKeyStorage() HolderBindingKeyStore
}

type gormUnitOfWork struct {
	storage Storage

	holderBindingKeyStore *HolderBindingKeyStore
}

func NewUnitOfWork(storage Storage) UnitOfWork {
	return &gormUnitOfWork{storage: storage}
}

func (u *gormUnitOfWork) Do(fn func(tx *gorm.DB) error) error {
	return u.storage.Db().Transaction(fn)
}

func (u *gormUnitOfWork) HolderBindingKeyStorage() HolderBindingKeyStore {
	if u.holderBindingKeyStore == nil {
		ks := NewHolderBindingKeyStore(u.storage.Db())
		u.holderBindingKeyStore = &ks
	}
	return *u.holderBindingKeyStore
}

func (u *gormUnitOfWork) Storage() Storage {
	return u.storage
}
