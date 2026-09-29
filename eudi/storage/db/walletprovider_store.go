package db

import (
	"errors"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/walletprovider"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// walletProviderStorage is the walletprovider.Storage the wallet offers its
// wallet provider, backed by the wallet_provider_values table.
type walletProviderStorage struct {
	db *gorm.DB
}

// NewWalletProviderStorage returns the wallet provider's key-value store in d.
func NewWalletProviderStorage(d *gorm.DB) walletprovider.Storage {
	return &walletProviderStorage{db: d}
}

func (s *walletProviderStorage) Get(key string) ([]byte, error) {
	return getWalletProviderValue(s.db, key)
}

func (s *walletProviderStorage) Update(fn func(tx walletprovider.StorageTx) error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return fn(walletProviderTx{tx})
	})
}

type walletProviderTx struct {
	db *gorm.DB
}

func (tx walletProviderTx) Get(key string) ([]byte, error) {
	return getWalletProviderValue(tx.db, key)
}

func (tx walletProviderTx) Put(key string, value []byte) error {
	return tx.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&models.WalletProviderValue{Key: key, Value: value}).Error
}

func (tx walletProviderTx) Delete(key string) error {
	return tx.db.Delete(&models.WalletProviderValue{}, "key = ?", key).Error
}

func getWalletProviderValue(d *gorm.DB, key string) ([]byte, error) {
	var v models.WalletProviderValue
	err := d.First(&v, "key = ?", key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, walletprovider.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return v.Value, nil
}
